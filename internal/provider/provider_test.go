package provider

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	pschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/cfg"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

type stubDriver struct {
	readSwitchFacts         func(context.Context) (model.SwitchFacts, error)
	readVLANState           func(context.Context) (model.VLANState, error)
	applyVLANState          func(context.Context, model.VLANState) error
	readConfig              func(context.Context) (*cfg.Config, error)
	restoreConfigAndWait    func(context.Context, []byte, time.Duration) error
	logout                  func(context.Context) error
	shouldInvalidateSession func(error) bool
}

func (d *stubDriver) Login(context.Context) error {
	return nil
}

func (d *stubDriver) Logout(ctx context.Context) error {
	if d.logout != nil {
		return d.logout(ctx)
	}
	return nil
}

func (d *stubDriver) ReadSwitchFacts(ctx context.Context) (model.SwitchFacts, error) {
	if d.readSwitchFacts != nil {
		return d.readSwitchFacts(ctx)
	}
	return model.SwitchFacts{}, nil
}

func (d *stubDriver) ReadVLANState(ctx context.Context) (model.VLANState, error) {
	if d.readVLANState != nil {
		return d.readVLANState(ctx)
	}
	return model.VLANState{}, nil
}

func (d *stubDriver) ApplyVLANState(ctx context.Context, state model.VLANState) error {
	if d.applyVLANState != nil {
		return d.applyVLANState(ctx, state)
	}
	return nil
}

func (d *stubDriver) ReadConfig(ctx context.Context) (*cfg.Config, error) {
	if d.readConfig != nil {
		return d.readConfig(ctx)
	}
	return nil, nil
}

func (d *stubDriver) RestoreConfigAndWait(ctx context.Context, cfgBytes []byte, timeout time.Duration) error {
	if d.restoreConfigAndWait != nil {
		return d.restoreConfigAndWait(ctx, cfgBytes, timeout)
	}
	return nil
}

func (d *stubDriver) ShouldInvalidateSession(err error) bool {
	if d.shouldInvalidateSession != nil {
		return d.shouldInvalidateSession(err)
	}
	return false
}

func TestProviderSchemaIncludesRequestSpacing(t *testing.T) {
	t.Parallel()

	var resp frameworkprovider.SchemaResponse
	(&netgearPlusProvider{}).Schema(context.Background(), frameworkprovider.SchemaRequest{}, &resp)

	if _, ok := resp.Schema.Attributes["request_spacing"]; !ok {
		t.Fatal("provider schema should expose request_spacing")
	}
}

func TestProviderDataResourceIDCanonicalizesHost(t *testing.T) {
	t.Parallel()

	data := &providerData{
		config: client.Config{
			Host:  "http://192.0.2.10:80",
			Model: client.ModelGS108Ev3,
		},
	}

	if got, want := data.resourceID(), "gs108ev3@192.0.2.10"; got != want {
		t.Fatalf("resourceID() = %q, want %q", got, want)
	}
}

func TestReadVLANStateDataSourceStateUsesProvidedResourceID(t *testing.T) {
	t.Parallel()

	driver := &stubDriver{
		readSwitchFacts: func(context.Context) (model.SwitchFacts, error) {
			t.Fatal("ReadSwitchFacts() should not be called by VLAN data source state helper")
			return model.SwitchFacts{}, nil
		},
		readVLANState: func(context.Context) (model.VLANState, error) {
			return model.VLANState{
				PortCount: 8,
				VLANs: map[int]model.Vlan{
					1: {
						ID: 1,
						Ports: map[int]model.PortMembership{
							1: model.PortMembershipUntagged,
							2: model.PortMembershipUntagged,
							3: model.PortMembershipIgnored,
							4: model.PortMembershipIgnored,
							5: model.PortMembershipIgnored,
							6: model.PortMembershipIgnored,
							7: model.PortMembershipIgnored,
							8: model.PortMembershipIgnored,
						},
					},
				},
				PVIDs: map[int]int{
					1: 1,
					2: 1,
					3: 1,
					4: 1,
					5: 1,
					6: 1,
					7: 1,
					8: 1,
				},
			}, nil
		},
	}

	state, err := readVLANStateDataSourceState(context.Background(), driver, "gs108ev3@192.0.2.10")
	if err != nil {
		t.Fatalf("readVLANStateDataSourceState() error = %v", err)
	}

	if got, want := state.ID.ValueString(), "gs108ev3@192.0.2.10"; got != want {
		t.Fatalf("state ID = %q, want %q", got, want)
	}
	if len(state.VLANs) != 1 {
		t.Fatalf("VLAN count = %d, want 1", len(state.VLANs))
	}

	pvids := make(map[string]int64)
	if diags := state.PVIDs.ElementsAs(context.Background(), &pvids, false); diags.HasError() {
		t.Fatalf("PVID map decode failed: %v", diags.Errors())
	}
	if got, want := pvids["1"], int64(1); got != want {
		t.Fatalf("PVID for port 1 = %d, want %d", got, want)
	}
}

func TestWithDriverForHostReusesCachedDriverAndSerializesCalls(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondEntered := make(chan struct{}, 1)
	errCh := make(chan error, 2)

	var mu sync.Mutex
	factoryCalls := 0
	logoutCalls := 0
	data := &providerData{
		config: client.Config{Host: "http://192.0.2.10:80", RequestSpacing: time.Millisecond},
		driverFactory: func(client.Config) (client.Driver, error) {
			mu.Lock()
			factoryCalls++
			mu.Unlock()

			return &stubDriver{
				logout: func(context.Context) error {
					mu.Lock()
					logoutCalls++
					mu.Unlock()
					return nil
				},
			}, nil
		},
	}

	go func() {
		errCh <- withDriverForHost(ctx, data, func(client.Driver) error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
	}()

	<-firstEntered

	go func() {
		errCh <- withDriverForHost(ctx, data, func(client.Driver) error {
			secondEntered <- struct{}{}
			return nil
		})
	}()

	select {
	case <-secondEntered:
		t.Fatal("second operation should block until the first call releases the host lock")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseFirst)

	select {
	case <-secondEntered:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for second callback: %v", ctx.Err())
	}

	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("withDriverForHost() error = %v", err)
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for helper result: %v", ctx.Err())
		}
	}

	mu.Lock()
	if factoryCalls != 1 {
		t.Fatalf("driverFactory call count = %d, want 1", factoryCalls)
	}
	if logoutCalls != 0 {
		t.Fatalf("logout call count = %d before invalidation, want 0", logoutCalls)
	}
	mu.Unlock()

	data.invalidateCachedDriver(ctx)

	mu.Lock()
	defer mu.Unlock()
	if logoutCalls != 1 {
		t.Fatalf("logout call count = %d after invalidation, want 1", logoutCalls)
	}
}

func TestWithDriverForHostInvalidatesCachedDriverOnConfigChange(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var mu sync.Mutex
	factoryCalls := 0
	logoutCalls := 0
	data := &providerData{
		config: client.Config{
			Host:           "http://192.0.2.10",
			Password:       "first-password",
			Model:          client.ModelGS108Ev3,
			RequestTimeout: 15,
			InsecureHTTP:   true,
			RequestSpacing: time.Millisecond,
		},
		driverFactory: func(client.Config) (client.Driver, error) {
			mu.Lock()
			factoryCalls++
			mu.Unlock()

			return &stubDriver{
				logout: func(context.Context) error {
					mu.Lock()
					logoutCalls++
					mu.Unlock()
					return nil
				},
			}, nil
		},
	}

	if err := withDriverForHost(ctx, data, func(client.Driver) error { return nil }); err != nil {
		t.Fatalf("first withDriverForHost() error = %v", err)
	}

	data.config.Password = "second-password"

	if err := withDriverForHost(ctx, data, func(client.Driver) error { return nil }); err != nil {
		t.Fatalf("second withDriverForHost() error = %v", err)
	}

	mu.Lock()
	if factoryCalls != 2 {
		t.Fatalf("driverFactory call count = %d, want 2", factoryCalls)
	}
	if logoutCalls != 1 {
		t.Fatalf("logout call count = %d after config change, want 1", logoutCalls)
	}
	mu.Unlock()

	data.invalidateCachedDriver(ctx)

	mu.Lock()
	defer mu.Unlock()
	if logoutCalls != 2 {
		t.Fatalf("logout call count = %d after final invalidation, want 2", logoutCalls)
	}
}

func TestWithDriverForHostInvalidatesCachedDriverOnRequestSpacingChange(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var mu sync.Mutex
	factoryCalls := 0
	logoutCalls := 0
	data := &providerData{
		config: client.Config{
			Host:           "http://192.0.2.10",
			Model:          client.ModelGS108Ev3,
			RequestSpacing: time.Millisecond,
		},
		driverFactory: func(client.Config) (client.Driver, error) {
			mu.Lock()
			factoryCalls++
			mu.Unlock()

			return &stubDriver{
				logout: func(context.Context) error {
					mu.Lock()
					logoutCalls++
					mu.Unlock()
					return nil
				},
			}, nil
		},
	}

	if err := withDriverForHost(ctx, data, func(client.Driver) error { return nil }); err != nil {
		t.Fatalf("first withDriverForHost() error = %v", err)
	}

	data.config.RequestSpacing = 2 * time.Millisecond

	if err := withDriverForHost(ctx, data, func(client.Driver) error { return nil }); err != nil {
		t.Fatalf("second withDriverForHost() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if factoryCalls != 2 {
		t.Fatalf("driverFactory call count = %d, want 2", factoryCalls)
	}
	if logoutCalls != 1 {
		t.Fatalf("logout call count = %d after request spacing change, want 1", logoutCalls)
	}
}

func TestWithDriverForHostInvalidatesCachedDriverOnCallbackError(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var mu sync.Mutex
	factoryCalls := 0
	logoutCalls := 0
	data := &providerData{
		config: client.Config{Host: "http://192.0.2.10", RequestSpacing: time.Millisecond},
		driverFactory: func(client.Config) (client.Driver, error) {
			mu.Lock()
			factoryCalls++
			mu.Unlock()

			return &stubDriver{
				shouldInvalidateSession: func(error) bool { return true },
				logout: func(context.Context) error {
					mu.Lock()
					logoutCalls++
					mu.Unlock()
					return nil
				},
			}, nil
		},
	}

	wantErr := errors.New("boom")
	if err := withDriverForHost(ctx, data, func(client.Driver) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("withDriverForHost() error = %v, want %v", err, wantErr)
	}

	mu.Lock()
	if factoryCalls != 1 {
		t.Fatalf("driverFactory call count = %d, want 1 after error", factoryCalls)
	}
	if logoutCalls != 1 {
		t.Fatalf("logout call count = %d, want 1 after error invalidation", logoutCalls)
	}
	mu.Unlock()

	if err := withDriverForHost(ctx, data, func(client.Driver) error { return nil }); err != nil {
		t.Fatalf("withDriverForHost() after invalidation error = %v", err)
	}

	mu.Lock()
	if factoryCalls != 2 {
		t.Fatalf("driverFactory call count = %d, want 2 after retry", factoryCalls)
	}
	mu.Unlock()
}

func TestWithDriverForHostPreservesCachedDriverOnNonSessionError(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var mu sync.Mutex
	factoryCalls := 0
	logoutCalls := 0
	data := &providerData{
		config: client.Config{Host: "http://192.0.2.11", RequestSpacing: time.Millisecond},
		driverFactory: func(client.Config) (client.Driver, error) {
			mu.Lock()
			factoryCalls++
			mu.Unlock()

			return &stubDriver{
				shouldInvalidateSession: func(error) bool { return false },
				logout: func(context.Context) error {
					mu.Lock()
					logoutCalls++
					mu.Unlock()
					return nil
				},
			}, nil
		},
	}

	wantErr := errors.New("boom")
	if err := withDriverForHost(ctx, data, func(client.Driver) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("withDriverForHost() error = %v, want %v", err, wantErr)
	}

	if err := withDriverForHost(ctx, data, func(client.Driver) error { return nil }); err != nil {
		t.Fatalf("withDriverForHost() after non-session error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if factoryCalls != 1 {
		t.Fatalf("driverFactory call count = %d, want 1 when session is preserved", factoryCalls)
	}
	if logoutCalls != 0 {
		t.Fatalf("logout call count = %d, want 0 when session is preserved", logoutCalls)
	}
}

func TestWithDriverForHostWaitsBetweenOperations(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	const spacing = 20 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	starts := make([]time.Time, 0, 2)
	data := &providerData{
		config: client.Config{Host: "http://192.0.2.12", RequestSpacing: spacing},
		driverFactory: func(client.Config) (client.Driver, error) {
			return &stubDriver{}, nil
		},
	}

	for i := 0; i < 2; i++ {
		if err := withDriverForHost(ctx, data, func(client.Driver) error {
			starts = append(starts, time.Now())
			return nil
		}); err != nil {
			t.Fatalf("withDriverForHost() error = %v", err)
		}
	}

	if len(starts) != 2 {
		t.Fatalf("callback count = %d, want 2", len(starts))
	}
	if gap := starts[1].Sub(starts[0]); gap < spacing {
		t.Fatalf("operation gap = %s, want at least %s", gap, spacing)
	}
}

type stubNSDPClient struct {
	closed bool
}

func (c *stubNSDPClient) Close() error {
	c.closed = true
	return nil
}

func (c *stubNSDPClient) Login() error                               { return nil }
func (c *stubNSDPClient) GetAttr(byte) ([]byte, error)               { return nil, nil }
func (c *stubNSDPClient) GetAttrs(...byte) (map[byte][]byte, error)  { return nil, nil }
func (c *stubNSDPClient) GetSystemName() (string, error)             { return "", nil }
func (c *stubNSDPClient) SetSystemName(string) error                 { return nil }
func (c *stubNSDPClient) SetRaw(uint16, []byte) error                { return nil }
func (c *stubNSDPClient) GetBlock(byte, []byte) ([]nsdp.Attr, error) { return nil, nil }
func (c *stubNSDPClient) SetPortConfig(int, bool, bool) error        { return nil }
func (c *stubNSDPClient) SetQoSPriority(int, nsdp.QoSPriority) error { return nil }
func (c *stubNSDPClient) SetIngressRate(int, nsdp.BandwidthLimit) error {
	return nil
}
func (c *stubNSDPClient) SetEgressRate(int, nsdp.BandwidthLimit) error {
	return nil
}
func (c *stubNSDPClient) SetQoSMode(nsdp.QoSMode) error       { return nil }
func (c *stubNSDPClient) SetBlockUnknownMulticast(bool) error { return nil }
func (c *stubNSDPClient) SetPortMirroring(int, []int) error   { return nil }
func (c *stubNSDPClient) SetPortBasedVLAN(int, []int) error   { return nil }

// providerConfigureRequest builds a framework ConfigureRequest whose config
// carries the given attribute values; every other schema attribute is
// null. This exercises Configure without a running Terraform core.
func providerConfigureRequest(t *testing.T, values map[string]tftypes.Value) frameworkprovider.ConfigureRequest {
	t.Helper()
	ctx := context.Background()

	var schemaResp frameworkprovider.SchemaResponse
	(&netgearPlusProvider{}).Schema(ctx, frameworkprovider.SchemaRequest{}, &schemaResp)

	attrTypes := make(map[string]tftypes.Type, len(schemaResp.Schema.Attributes))
	for name, attr := range schemaResp.Schema.Attributes {
		attrTypes[name] = attr.GetType().TerraformType(ctx)
	}
	for name, typ := range attrTypes {
		if _, ok := values[name]; !ok {
			values[name] = tftypes.NewValue(typ, nil)
		}
	}

	return frameworkprovider.ConfigureRequest{
		Config: tfsdk.Config{
			Raw:    tftypes.NewValue(tftypes.Object{AttributeTypes: attrTypes}, values),
			Schema: schemaResp.Schema,
		},
	}
}

func configureProvider(t *testing.T, values map[string]tftypes.Value) (*providerData, diag.Diagnostics) {
	t.Helper()

	var resp frameworkprovider.ConfigureResponse
	(&netgearPlusProvider{}).Configure(context.Background(), providerConfigureRequest(t, values), &resp)

	var data *providerData
	if !resp.Diagnostics.HasError() {
		data = resp.ResourceData.(*providerData)
	}
	return data, resp.Diagnostics
}

func diagnosticsText(diags diag.Diagnostics) string {
	var sb strings.Builder
	for _, d := range diags {
		sb.WriteString(d.Summary())
		sb.WriteString(" ")
		sb.WriteString(d.Detail())
		sb.WriteString(" ")
	}
	return sb.String()
}

func TestProviderSchemaHostOptionalAndNSDPAttributes(t *testing.T) {
	t.Parallel()

	var resp frameworkprovider.SchemaResponse
	(&netgearPlusProvider{}).Schema(context.Background(), frameworkprovider.SchemaRequest{}, &resp)

	host, ok := resp.Schema.Attributes["host"]
	if !ok {
		t.Fatal("provider schema should expose host")
	}
	if host.IsRequired() {
		t.Fatal("host must be optional so NSDP-only configurations are valid")
	}
	if !host.IsOptional() {
		t.Fatal("host must be optional")
	}

	agentMAC, ok := resp.Schema.Attributes["agent_mac"]
	if !ok {
		t.Fatal("provider schema should expose agent_mac")
	}
	if !agentMAC.IsOptional() || agentMAC.IsRequired() {
		t.Fatal("agent_mac must be optional and not required")
	}
	if len(agentMAC.(pschema.StringAttribute).Validators) == 0 {
		t.Fatal("agent_mac must carry a format validator")
	}

	ifaceName, ok := resp.Schema.Attributes["interface"]
	if !ok {
		t.Fatal("provider schema should expose interface")
	}
	if !ifaceName.IsOptional() || ifaceName.IsRequired() {
		t.Fatal("interface must be optional and not required")
	}

	password, ok := resp.Schema.Attributes["password"]
	if !ok {
		t.Fatal("provider schema should expose password")
	}
	if !password.IsRequired() {
		t.Fatal("password must stay required")
	}
}

func TestAgentMACPatternAcceptsColonMACsOnly(t *testing.T) {
	t.Parallel()

	for _, valid := range []string{"8c:3b:ad:25:1b:88", "8C:3B:AD:25:1B:88", "00:11:22:33:44:55"} {
		if !agentMACPattern.MatchString(valid) {
			t.Fatalf("agentMACPattern should accept %q", valid)
		}
	}
	for _, invalid := range []string{
		"8c-3b-ad-25-1b-88",    // hyphens are not the wire/config format
		"8c.3b.ad.25.1b.88",    // dot form
		"8c3bad251b88",         // no separators
		"8c:3b:ad:25:1b",       // too short
		"8c:3b:ad:25:1b:88:99", // too long
		"",
		" 8c:3b:ad:25:1b:88",
	} {
		if agentMACPattern.MatchString(invalid) {
			t.Fatalf("agentMACPattern should reject %q", invalid)
		}
	}
}

func TestConfigureRequiresHostOrAgentMAC(t *testing.T) {
	t.Parallel()

	_, diags := configureProvider(t, map[string]tftypes.Value{
		"password": tftypes.NewValue(tftypes.String, "secret"),
	})
	if !diags.HasError() {
		t.Fatal("Configure must fail when both host and agent_mac are unset")
	}

	text := diagnosticsText(diags)
	if !strings.Contains(text, "host") || !strings.Contains(text, "agent_mac") {
		t.Fatalf("diagnostic should name both host and agent_mac, got: %q", text)
	}
}

func TestConfigureAcceptsAgentMACOnly(t *testing.T) {
	t.Parallel()

	data, diags := configureProvider(t, map[string]tftypes.Value{
		"password":  tftypes.NewValue(tftypes.String, "secret"),
		"agent_mac": tftypes.NewValue(tftypes.String, "8C:3B:AD:25:1B:88"),
	})
	if diags.HasError() {
		t.Fatalf("Configure with agent_mac only should succeed, got: %v", diags)
	}

	if got, want := data.agentMAC, "8c:3b:ad:25:1b:88"; got != want {
		t.Fatalf("agentMAC = %q, want normalized %q", got, want)
	}
	if got, want := data.deviceLockKey(), "8c:3b:ad:25:1b:88"; got != want {
		t.Fatalf("deviceLockKey() = %q, want %q", got, want)
	}
	if data.config.Host != "" {
		t.Fatalf("config.Host = %q, want empty for NSDP-only configuration", data.config.Host)
	}
}

func TestConfigureDeviceKeyPrefersAgentMACOverHost(t *testing.T) {
	t.Parallel()

	data, diags := configureProvider(t, map[string]tftypes.Value{
		"host":      tftypes.NewValue(tftypes.String, "http://192.0.2.10:80"),
		"password":  tftypes.NewValue(tftypes.String, "secret"),
		"agent_mac": tftypes.NewValue(tftypes.String, "8c:3b:ad:25:1b:88"),
	})
	if diags.HasError() {
		t.Fatalf("Configure with host and agent_mac should succeed, got: %v", diags)
	}

	if got, want := data.deviceLockKey(), "8c:3b:ad:25:1b:88"; got != want {
		t.Fatalf("deviceLockKey() = %q, want agent MAC %q so HTTP and NSDP operations serialize on one key", got, want)
	}
	// HTTP state identity must stay keyed by host.
	if got, want := data.resourceID(), "gs108ev3@192.0.2.10"; got != want {
		t.Fatalf("resourceID() = %q, want unchanged %q", got, want)
	}
}

func TestConfigureDeviceKeyFallsBackToCanonicalHost(t *testing.T) {
	t.Parallel()

	data, diags := configureProvider(t, map[string]tftypes.Value{
		"host":     tftypes.NewValue(tftypes.String, "http://192.0.2.10:80"),
		"password": tftypes.NewValue(tftypes.String, "secret"),
	})
	if diags.HasError() {
		t.Fatalf("Configure with host only should succeed, got: %v", diags)
	}

	if got, want := data.deviceLockKey(), "192.0.2.10"; got != want {
		t.Fatalf("deviceLockKey() = %q, want canonical host key %q", got, want)
	}
}

func TestConfigureRejectsInvalidAgentMAC(t *testing.T) {
	t.Parallel()

	_, diags := configureProvider(t, map[string]tftypes.Value{
		"password":  tftypes.NewValue(tftypes.String, "secret"),
		"agent_mac": tftypes.NewValue(tftypes.String, "8c-3b-ad-25-1b-88"),
	})
	if !diags.HasError() {
		t.Fatal("Configure must reject a non-colon-separated agent_mac")
	}
	if text := diagnosticsText(diags); !strings.Contains(text, "agent_mac") {
		t.Fatalf("diagnostic should name agent_mac, got: %q", text)
	}
}

func TestNSDPClientRequiresAgentMAC(t *testing.T) {
	t.Parallel()

	data := &providerData{config: client.Config{Password: "secret"}}
	_, err := data.nsdpClient(context.Background())
	if err == nil {
		t.Fatal("nsdpClient() must fail when agent_mac is unset")
	}
	if !strings.Contains(err.Error(), "agent_mac") {
		t.Fatalf("nsdpClient() error should be diagnostic-ready and name agent_mac, got: %v", err)
	}

	err = withNSDPClient(context.Background(), data, func(nsdpClient) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "agent_mac") {
		t.Fatalf("withNSDPClient() should surface the same agent_mac requirement, got: %v", err)
	}
}

func TestNSDPClientCacheFingerprinting(t *testing.T) {
	t.Parallel()

	var gotOpts []nsdp.Options
	data := &providerData{
		config:    client.Config{Password: "first-password"},
		agentMAC:  "8c:3b:ad:25:1b:88",
		ifaceName: "en0",
		nsdpFactory: func(opts nsdp.Options) (nsdpClient, error) {
			gotOpts = append(gotOpts, opts)
			return &stubNSDPClient{}, nil
		},
	}

	ctx := context.Background()

	first, err := data.nsdpClient(ctx)
	if err != nil {
		t.Fatalf("first nsdpClient() error = %v", err)
	}
	second, err := data.nsdpClient(ctx)
	if err != nil {
		t.Fatalf("second nsdpClient() error = %v", err)
	}

	if first != second {
		t.Fatal("nsdpClient() must return the same cached instance for the same fingerprint")
	}
	if len(gotOpts) != 1 {
		t.Fatalf("nsdpFactory call count = %d, want 1 while the fingerprint is unchanged", len(gotOpts))
	}

	if gotOpts[0].IfaceName != "en0" {
		t.Fatalf("nsdpFactory iface = %q, want en0", gotOpts[0].IfaceName)
	}
	if gotOpts[0].AgentMAC != "8c:3b:ad:25:1b:88" {
		t.Fatalf("nsdpFactory agent MAC = %q, want normalized 8c:3b:ad:25:1b:88", gotOpts[0].AgentMAC)
	}
	if string(gotOpts[0].Password) != "first-password" {
		t.Fatalf("nsdpFactory password = %q, want first-password", gotOpts[0].Password)
	}

	// A different password changes the fingerprint: a new instance is
	// built and the previous client is closed.
	data.config.Password = "second-password"

	third, err := data.nsdpClient(ctx)
	if err != nil {
		t.Fatalf("third nsdpClient() error = %v", err)
	}
	if third == first {
		t.Fatal("nsdpClient() must build a new instance for a different password fingerprint")
	}
	if len(gotOpts) != 2 {
		t.Fatalf("nsdpFactory call count = %d, want 2 after fingerprint change", len(gotOpts))
	}
	if !first.(*stubNSDPClient).closed {
		t.Fatal("the previous NSDP client should be closed on cache invalidation")
	}
}

func TestNSDPClientPreservesEmptyInterfaceDefault(t *testing.T) {
	t.Parallel()

	var gotIface string
	data := &providerData{
		config:   client.Config{Password: "secret"},
		agentMAC: "8c:3b:ad:25:1b:88",
		nsdpFactory: func(opts nsdp.Options) (nsdpClient, error) {
			gotIface = opts.IfaceName
			return &stubNSDPClient{}, nil
		},
	}

	if _, err := data.nsdpClient(context.Background()); err != nil {
		t.Fatalf("nsdpClient() error = %v", err)
	}
	if gotIface != "" {
		t.Fatalf("nsdpFactory iface = %q, want empty so the nsdp package default interface applies", gotIface)
	}
}

func TestNSDPClientFingerprintIndependentOfHTTPConfig(t *testing.T) {
	t.Parallel()

	data := &providerData{
		config:    client.Config{Host: "http://192.0.2.10", Password: "secret"},
		agentMAC:  "8c:3b:ad:25:1b:88",
		ifaceName: "en0",
	}

	first := data.nsdpConfigFingerprint()

	// HTTP-only config fields must not leak into the NSDP fingerprint:
	// the NSDP client cache lifecycle is independent of the HTTP driver
	// session.
	data.config.Host = "http://192.0.2.99"
	data.config.Model = client.ModelGS108Ev3
	data.config.RequestTimeout = 99
	if second := data.nsdpConfigFingerprint(); first != second {
		t.Fatalf("NSDP fingerprint must not track HTTP config fields: %q != %q", first, second)
	}

	// The interface IS part of the fingerprint.
	data.ifaceName = "en1"
	if third := data.nsdpConfigFingerprint(); first == third {
		t.Fatal("NSDP fingerprint must change when the interface changes")
	}
}

func TestWithNSDPClientRetriesAuthFailureExactlyOnce(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	factoryCalls := 0
	data := &providerData{
		config:    client.Config{Password: "secret", RequestSpacing: time.Millisecond},
		agentMAC:  "8c:3b:ad:25:1b:88",
		deviceKey: "8c:3b:ad:25:1b:88",
		nsdpFactory: func(nsdp.Options) (nsdpClient, error) {
			factoryCalls++
			return &stubNSDPClient{}, nil
		},
	}

	authErr := &nsdp.ErrStatus{Status: 0x0d, FailingTag: 0x001a, Source: "SET system name"}
	err := withNSDPClient(ctx, data, func(nsdpClient) error { return authErr })
	if err == nil {
		t.Fatal("withNSDPClient() should surface the retried auth failure")
	}
	var statusErr *nsdp.ErrStatus
	if !errors.As(err, &statusErr) || statusErr != authErr {
		t.Fatalf("withNSDPClient() error = %v, want the auth status error", err)
	}
	if factoryCalls != 2 {
		t.Fatalf("nsdpFactory call count = %d, want 2 (fresh client after ONE invalidation, never more)", factoryCalls)
	}
}

func TestWithNSDPClientDoesNotRetryNonAuthFailure(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	factoryCalls := 0
	data := &providerData{
		config:    client.Config{Password: "secret", RequestSpacing: time.Millisecond},
		agentMAC:  "8c:3b:ad:25:1b:88",
		deviceKey: "8c:3b:ad:25:1b:88",
		nsdpFactory: func(nsdp.Options) (nsdpClient, error) {
			factoryCalls++
			return &stubNSDPClient{}, nil
		},
	}

	plainErr := errors.New("boom")
	if err := withNSDPClient(ctx, data, func(nsdpClient) error { return plainErr }); !errors.Is(err, plainErr) {
		t.Fatalf("withNSDPClient() error = %v, want %v", err, plainErr)
	}
	if factoryCalls != 1 {
		t.Fatalf("nsdpFactory call count = %d, want 1 (no re-login on non-auth failure)", factoryCalls)
	}
}

func TestWithNSDPClientDoesNotRetryUnexpectedLoginStatus(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	factoryCalls := 0
	data := &providerData{
		config:    client.Config{Password: "secret", RequestSpacing: time.Millisecond},
		agentMAC:  "8c:3b:ad:25:1b:88",
		deviceKey: "8c:3b:ad:25:1b:88",
		nsdpFactory: func(nsdp.Options) (nsdpClient, error) {
			factoryCalls++
			return &stubNSDPClient{}, nil
		},
	}

	// An unexpected login error may signal the 3-strikes ~30-minute SET
	// lockout: it must never trigger a re-login.
	unexpected := &nsdp.ErrStatus{Status: 0x05, Source: "SET login"}
	if err := withNSDPClient(ctx, data, func(nsdpClient) error { return unexpected }); !errors.Is(err, unexpected) {
		t.Fatalf("withNSDPClient() error = %v, want %v", err, unexpected)
	}
	if factoryCalls != 1 {
		t.Fatalf("nsdpFactory call count = %d, want 1 (lockout-suspect errors are never retried)", factoryCalls)
	}
}

func TestHTTPAndNSDPOperationsShareDeviceLock(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	data := &providerData{
		config:    client.Config{Host: "http://192.0.2.10:80", RequestSpacing: time.Millisecond},
		agentMAC:  "8c:3b:ad:25:1b:88",
		deviceKey: "8c:3b:ad:25:1b:88",
		driverFactory: func(client.Config) (client.Driver, error) {
			return &stubDriver{}, nil
		},
		nsdpFactory: func(nsdp.Options) (nsdpClient, error) {
			return &stubNSDPClient{}, nil
		},
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	nsdpErr := make(chan error, 1)
	httpErr := make(chan error, 1)

	go func() {
		nsdpErr <- withNSDPClient(ctx, data, func(nsdpClient) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	go func() {
		httpErr <- withDriverForHost(ctx, data, func(client.Driver) error { return nil })
	}()

	select {
	case <-httpErr:
		t.Fatal("HTTP operation must block behind an NSDP operation on the same physical switch")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	for i := 0; i < 2; i++ {
		select {
		case err := <-nsdpErr:
			if err != nil {
				t.Fatalf("withNSDPClient() error = %v", err)
			}
		case err := <-httpErr:
			if err != nil {
				t.Fatalf("withDriverForHost() error = %v", err)
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for operations: %v", ctx.Err())
		}
	}
}
