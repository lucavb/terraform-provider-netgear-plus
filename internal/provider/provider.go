package provider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	pschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

var hostMutexes sync.Map
var hostOperationPacers sync.Map

const defaultRequestSpacing = 5 * time.Second

type netgearPlusProvider struct{}

type providerModel struct {
	Host           types.String `tfsdk:"host"`
	Password       types.String `tfsdk:"password"`
	Model          types.String `tfsdk:"model"`
	RequestTimeout types.Int64  `tfsdk:"request_timeout"`
	RequestSpacing types.Int64  `tfsdk:"request_spacing"`
	InsecureHTTP   types.Bool   `tfsdk:"insecure_http"`
}

type providerData struct {
	config        client.Config
	driverFactory func(client.Config) (client.Driver, error)
	cachedSession *cachedDriverSession
}

type cachedDriverSession struct {
	fingerprint string
	driver      client.Driver
}

type providerOperationError struct {
	summary string
	detail  string
	cause   error
}

func (e *providerOperationError) Error() string {
	return e.detail
}

func (e *providerOperationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

type hostOperationPacer struct {
	mu      sync.Mutex
	lastRun time.Time
}

type vlanAttributeModel struct {
	ID    types.Int64 `tfsdk:"id"`
	Ports types.Map   `tfsdk:"ports"`
}

// New returns the provider implementation.
func New() provider.Provider {
	return &netgearPlusProvider{}
}

func (p *netgearPlusProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "netgear_plus"
}

func (p *netgearPlusProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = pschema.Schema{
		Attributes: map[string]pschema.Attribute{
			"host": pschema.StringAttribute{
				Required:    true,
				Description: "Switch hostname or URL.",
			},
			"password": pschema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "Switch admin password.",
			},
			"model": pschema.StringAttribute{
				Optional:    true,
				Description: "Switch model to bind to.",
				Validators: []validator.String{
					stringvalidator.OneOf(client.ModelGS108Ev3),
				},
			},
			"request_timeout": pschema.Int64Attribute{
				Optional:    true,
				Description: "HTTP timeout in seconds.",
			},
			"request_spacing": pschema.Int64Attribute{
				Optional:    true,
				Description: "Minimum delay in seconds between requests and operations against the same switch.",
			},
			"insecure_http": pschema.BoolAttribute{
				Optional:    true,
				Description: "Allow plaintext HTTP transport for switch access.",
			},
		},
	}
}

func (p *netgearPlusProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.Host.IsUnknown() || data.Password.IsUnknown() || data.Model.IsUnknown() {
		resp.Diagnostics.AddError("Unknown provider configuration", "Provider configuration contains unknown values.")
		return
	}

	host := strings.TrimSpace(data.Host.ValueString())
	if host == "" {
		resp.Diagnostics.AddError("Invalid host", "`host` must not be empty.")
		return
	}

	modelName := data.Model.ValueString()
	if modelName == "" {
		modelName = client.ModelGS108Ev3
	}

	requestTimeout := data.RequestTimeout.ValueInt64()
	if requestTimeout == 0 {
		requestTimeout = 15
	}

	requestSpacing := data.RequestSpacing.ValueInt64()
	if requestSpacing == 0 {
		requestSpacing = int64(defaultRequestSpacing / time.Second)
	}
	if requestSpacing < 0 {
		resp.Diagnostics.AddError("Invalid request spacing", "`request_spacing` must be zero or a positive number of seconds.")
		return
	}

	insecureHTTP := true
	if !data.InsecureHTTP.IsNull() && !data.InsecureHTTP.IsUnknown() {
		insecureHTTP = data.InsecureHTTP.ValueBool()
	}

	if !insecureHTTP {
		if !strings.HasPrefix(host, "https://") {
			resp.Diagnostics.AddError("Unsupported transport", "v0.1.0 only supports plaintext HTTP for GS108Ev3. Set `insecure_http = true` or provide an `https://` host if your device supports it.")
			return
		}
	}

	config := client.Config{
		Host:           host,
		Password:       data.Password.ValueString(),
		Model:          modelName,
		RequestTimeout: requestTimeout,
		InsecureHTTP:   insecureHTTP,
		RequestSpacing: time.Duration(requestSpacing) * time.Second,
	}

	providerData := &providerData{
		config:        config,
		driverFactory: client.NewDriver,
	}
	resp.DataSourceData = providerData
	resp.ResourceData = providerData
}

func (p *netgearPlusProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewVLANStateResource,
	}
}

func (p *netgearPlusProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSwitchDataSource,
		NewVLANStateDataSource,
	}
}

func withDriverForHost(ctx context.Context, data *providerData, fn func(client.Driver) error) error {
	if data == nil {
		return fmt.Errorf("provider is not configured")
	}

	mutex := mutexForHost(data.config.Host)
	mutex.Lock()
	defer mutex.Unlock()

	if err := waitForHostOperation(ctx, data.config.Host, data.config.RequestSpacing); err != nil {
		return err
	}

	driverFactory := data.driverFactory
	if driverFactory == nil {
		driverFactory = client.NewDriver
	}

	driver, err := data.driverForConfig(ctx, driverFactory)
	if err != nil {
		return err
	}

	if err := fn(driver); err != nil {
		if driver.ShouldInvalidateSession(err) {
			data.invalidateCachedDriver(ctx)
		}
		return err
	}

	return nil
}

func (d *providerData) driverForConfig(ctx context.Context, driverFactory func(client.Config) (client.Driver, error)) (client.Driver, error) {
	if d == nil {
		return nil, fmt.Errorf("provider is not configured")
	}

	fingerprint := d.configFingerprint()
	if d.cachedSession != nil && d.cachedSession.fingerprint == fingerprint && d.cachedSession.driver != nil {
		return d.cachedSession.driver, nil
	}

	d.invalidateCachedDriver(ctx)

	driver, err := driverFactory(d.config)
	if err != nil {
		return nil, err
	}

	d.cachedSession = &cachedDriverSession{
		fingerprint: fingerprint,
		driver:      driver,
	}

	return driver, nil
}

func (d *providerData) invalidateCachedDriver(ctx context.Context) {
	if d == nil || d.cachedSession == nil {
		return
	}
	if d.cachedSession.driver != nil {
		_ = d.cachedSession.driver.Logout(ctx)
	}
	d.cachedSession = nil
}

func (d *providerData) configFingerprint() string {
	if d == nil {
		return ""
	}

	return strings.Join([]string{
		canonicalHostKey(d.config.Host),
		strings.TrimSpace(d.config.Password),
		strings.ToLower(strings.TrimSpace(d.config.Model)),
		fmt.Sprintf("%d", d.config.RequestTimeout),
		d.config.RequestSpacing.String(),
		fmt.Sprintf("%t", d.config.InsecureHTTP),
	}, "\x00")
}

func (d *providerData) resourceID() string {
	if d == nil {
		return ""
	}

	modelName := strings.ToLower(strings.TrimSpace(d.config.Model))
	if modelName == "" {
		modelName = client.ModelGS108Ev3
	}

	return fmt.Sprintf("%s@%s", modelName, canonicalHostKey(d.config.Host))
}

func operationError(summary string, err error) error {
	if err == nil {
		return nil
	}

	return &providerOperationError{
		summary: summary,
		detail:  err.Error(),
		cause:   err,
	}
}

type diagnosticAdder interface {
	AddError(summary, detail string)
}

func addDriverError(diags diagnosticAdder, err error) {
	if err == nil {
		return
	}

	var opErr *providerOperationError
	if errors.As(err, &opErr) {
		diags.AddError(opErr.summary, opErr.detail)
		return
	}

	diags.AddError("Create driver failed", err.Error())
}

func mutexForHost(host string) *sync.Mutex {
	mutexValue, _ := hostMutexes.LoadOrStore(canonicalHostKey(host), &sync.Mutex{})
	return mutexValue.(*sync.Mutex)
}

func waitForHostOperation(ctx context.Context, host string, spacing time.Duration) error {
	if spacing <= 0 {
		return nil
	}

	pacerValue, _ := hostOperationPacers.LoadOrStore(canonicalHostKey(host), &hostOperationPacer{})
	pacer := pacerValue.(*hostOperationPacer)

	pacer.mu.Lock()
	defer pacer.mu.Unlock()

	now := time.Now()
	if !pacer.lastRun.IsZero() {
		wait := spacing - now.Sub(pacer.lastRun)
		if wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
		}
	}

	pacer.lastRun = time.Now()
	return nil
}

func canonicalHostKey(host string) string {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return ""
	}

	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		trimmed = "http://" + trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return strings.ToLower(trimmed)
	}
	if parsed.Host == "" {
		return strings.ToLower(trimmed)
	}

	port := parsed.Port()
	switch {
	case parsed.Scheme == "http" && port == "80":
		return strings.ToLower(parsed.Hostname())
	case parsed.Scheme == "https" && port == "443":
		return strings.ToLower(parsed.Hostname())
	default:
		return strings.ToLower(parsed.Host)
	}
}

func expandVLANState(ctx context.Context, portCount int, vlanModels []vlanAttributeModel, pvids basetypes.MapValue) (model.VLANState, error) {
	pvidMap := make(map[string]int64)
	if diags := pvids.ElementsAs(ctx, &pvidMap, false); diags.HasError() {
		return model.VLANState{}, fmt.Errorf("expand pvids: %s", diags.Errors()[0].Detail())
	}

	state := model.VLANState{
		PortCount: portCount,
		VLANs:     make(map[int]model.Vlan, len(vlanModels)),
		PVIDs:     make(map[int]int, len(pvidMap)),
	}

	for portKey, pvid := range pvidMap {
		port, err := parsePortKey(portKey)
		if err != nil {
			return model.VLANState{}, err
		}
		state.PVIDs[port] = int(pvid)
	}

	for _, vlanModel := range vlanModels {
		portMap := make(map[string]string)
		if diags := vlanModel.Ports.ElementsAs(ctx, &portMap, false); diags.HasError() {
			return model.VLANState{}, fmt.Errorf("expand vlan ports: %s", diags.Errors()[0].Detail())
		}

		ports := make(map[int]model.PortMembership, len(portMap))
		for portKey, membership := range portMap {
			port, err := parsePortKey(portKey)
			if err != nil {
				return model.VLANState{}, err
			}
			ports[port] = model.PortMembership(membership)
		}

		vid := int(vlanModel.ID.ValueInt64())
		state.VLANs[vid] = model.Vlan{
			ID:    vid,
			Ports: ports,
		}
	}

	return state.Normalize(), nil
}

func flattenVLANState(ctx context.Context, state model.VLANState) ([]vlanAttributeModel, basetypes.MapValue, error) {
	state = state.Normalize()

	vlanModels := make([]vlanAttributeModel, 0, len(state.VLANs))
	for _, vid := range state.VLANIDs() {
		ports := make(map[string]string, state.PortCount)
		for _, port := range state.SortedPorts() {
			ports[fmt.Sprintf("%d", port)] = string(state.VLANs[vid].Ports[port])
		}

		portsValue, diags := types.MapValueFrom(ctx, types.StringType, ports)
		if diags.HasError() {
			return nil, basetypes.MapValue{}, fmt.Errorf("flatten vlan %d ports: %s", vid, diags.Errors()[0].Detail())
		}

		vlanModels = append(vlanModels, vlanAttributeModel{
			ID:    types.Int64Value(int64(vid)),
			Ports: portsValue,
		})
	}

	pvids := make(map[string]int64, len(state.PVIDs))
	for _, port := range state.SortedPorts() {
		pvids[fmt.Sprintf("%d", port)] = int64(state.PVIDs[port])
	}

	pvidValue, diags := types.MapValueFrom(ctx, types.Int64Type, pvids)
	if diags.HasError() {
		return nil, basetypes.MapValue{}, fmt.Errorf("flatten pvids: %s", diags.Errors()[0].Detail())
	}

	return vlanModels, pvidValue, nil
}

func parsePortKey(value string) (int, error) {
	var port int
	if _, err := fmt.Sscanf(value, "%d", &port); err != nil {
		return 0, fmt.Errorf("invalid port key %q", value)
	}
	return port, nil
}
