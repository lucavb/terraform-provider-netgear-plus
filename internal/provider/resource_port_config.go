package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client/gs108tv2"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// portConfigPortCount is the fixed GS108Ev3 port count; one resource
// instance is the authoritative table for ALL of them.
const portConfigPortCount = 8

// NSDP block GET identifiers (byte prefix of the 0xNN00 family tags).
const (
	nsdpBlockPortConfig  = 0x94 // 0x9400 per-port {port, admin, flow}
	nsdpBlockPortQoS     = 0x38 // 0x3800 per-port {port, priority}
	nsdpBlockIngressRate = 0x4c // 0x4c00 per-port {port, 00 00, limit}
	nsdpBlockEgressRate  = 0x50 // 0x5000 per-port {port, 00 00, limit}
)

// Factory defaults the schema descriptions advertise (a from-factory apply
// plans as a no-op): admin enabled everywhere, flow control off, QoS low
// (enum 4), no rate limits (enum 0).
const (
	defaultPortEnabled     = true
	defaultPortFlowControl = false
	defaultPortQoSPriority = "low"
	defaultPortRateLimit   = "none"
)

// qosPriorities and rateLimits are the config vocabularies, in wire order.
var qosPriorities = []string{"high", "middle", "normal", "low"}
var rateLimits = []string{"none", "512k", "1m", "2m", "4m", "8m", "16m", "32m", "64m", "128m", "256m", "512m"}

type portConfigResource struct {
	data *providerData
}

type portConfigResourceModel struct {
	ID             types.String          `tfsdk:"id"`
	Ports          []portConfigPortModel `tfsdk:"ports"`
	RebootToApply  types.Bool            `tfsdk:"reboot_to_apply"`
	ChangesPending types.Bool            `tfsdk:"changes_pending"`
}

type portConfigPortModel struct {
	Port        types.Int64  `tfsdk:"port"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	FlowControl types.Bool   `tfsdk:"flow_control"`
	QoSPriority types.String `tfsdk:"qos_priority"`
	IngressRate types.String `tfsdk:"ingress_rate"`
	EgressRate  types.String `tfsdk:"egress_rate"`
}

// NewPortConfigResource returns the authoritative NSDP per-port
// configuration resource.
func NewPortConfigResource() resource.Resource {
	return &portConfigResource{}
}

func (r *portConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_port_config"
}

func (r *portConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = rschema.Schema{
		Description: "Authoritative per-port configuration for all 8 ports of a switch: admin enable, flow control, per-port QoS priority, and ingress/egress rate limits. Runs over NSDP block SETs on gs108ev3 and over the FASTPATH text-config channel on gs108tv2 (where qos_priority/ingress_rate/egress_rate refuse non-default values until that firmware's grammar is pinned).",
		Attributes: map[string]rschema.Attribute{
			"id": rschema.StringAttribute{
				Computed:    true,
				Description: "Stable switch identifier (nsdp@<agent MAC> over NSDP; gs108tv2@<host> over the text-config channel).",
			},
			"reboot_to_apply": rschema.BoolAttribute{
				// Optional + StaticBool(false) default resolves to a
				// known plan value (no Computed perpetual diff); the
				// framework merely requires the flag for Defaults.
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "gs108tv2 only. When `true`, every apply that stages changes also reboots the switch after staging and waits for it to come back with the staged startup-config intact — the changes are ACTIVE when Terraform reports success. When `false`, gs108tv2 applies stage the startup-config without rebooting. gs108ev3 is refused (its NSDP SETs apply live). Leaving it true reboots the switch on later unrelated diffs too.",
			},
			"changes_pending": rschema.BoolAttribute{
				Computed:    true,
				Description: "gs108tv2: true while the last Terraform apply staged changes without a Terraform-driven reboot. false after a rebooting apply, on no-op applies, and on gs108ev3. Reads pass the prior value through: running state is unobservable on gs108tv2 between applies, so it clears on the next apply and says nothing about an out-of-band reboot.",
			},
		},
		Blocks: map[string]rschema.Block{
			"ports": rschema.ListNestedBlock{
				Description: "Complete authoritative per-port configuration. Exactly 8 entries, one per physical port; the port numbers must be exactly the set 1-8.",
				Validators: []validator.List{
					listvalidator.SizeBetween(portConfigPortCount, portConfigPortCount),
				},
				NestedObject: rschema.NestedBlockObject{
					Attributes: map[string]rschema.Attribute{
						"port": rschema.Int64Attribute{
							Required:    true,
							Description: "Physical port number, 1-8.",
							Validators: []validator.Int64{
								int64validator.Between(1, portConfigPortCount),
							},
						},
						"enabled": rschema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Default:     booldefault.StaticBool(defaultPortEnabled),
							Description: "Port admin enable. Defaults to true, the factory value on all ports.",
						},
						"flow_control": rschema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Default:     booldefault.StaticBool(defaultPortFlowControl),
							Description: "Port flow control. Defaults to false, the factory value on all ports.",
						},
						"qos_priority": rschema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString(defaultPortQoSPriority),
							Description: "Per-port QoS priority. Defaults to `low`, the factory value on all ports.",
							Validators: []validator.String{
								stringvalidator.OneOf(qosPriorities...),
							},
						},
						"ingress_rate": rschema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString(defaultPortRateLimit),
							Description: "Ingress (incoming) rate limit. Defaults to `none`, the factory value on all ports.",
							Validators: []validator.String{
								stringvalidator.OneOf(rateLimits...),
							},
						},
						"egress_rate": rschema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString(defaultPortRateLimit),
							Description: "Egress (outgoing) rate limit. Defaults to `none`, the factory value on all ports.",
							Validators: []validator.String{
								stringvalidator.OneOf(rateLimits...),
							},
						},
					},
				},
			},
		},
	}
}

func (r *portConfigResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.data = req.ProviderData.(*providerData)
}

func (r *portConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan portConfigResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *portConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var current portConfigResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &current)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if r.data == nil {
		resp.Diagnostics.AddError("Provider not configured", "Configure the `netgear_plus` provider before reading `netgear_plus_port_config`.")
		return
	}

	// gs108tv2: port settings read over the composite text-config
	// transport (startup-config decode). Routing precedes the NSDP
	// branch, so the nsdpV1Guard refusal never fires on this model.
	if r.data.isGS108Tv2Model() {
		if err := withSwitchTransport(ctx, r.data, func(transport switchTransport) error {
			reader, ok := transport.(portSettingsTransport)
			if !ok {
				return fmt.Errorf("the gs108tv2 port_config transport cannot read port settings")
			}
			actual, err := reader.ReadPortSettings(ctx)
			if err != nil {
				return operationError("Read port configuration failed", err)
			}

			// Preserve a pre-existing ID (import passthrough); compute
			// it when absent (gs108tv2@<host> convention).
			id := current.ID
			if id.IsNull() || id.IsUnknown() || strings.TrimSpace(id.ValueString()) == "" {
				id = types.StringValue(transport.ResourceID())
			}

			readState, err := flattenPortConfigs(textPortSettingsToConfigs(actual), id)
			if err != nil {
				return operationError("Flatten port configuration failed", err)
			}
			// Running state is unobservable on gs108tv2 between
			// applies: pass both plan-owned flags through unchanged.
			readState.RebootToApply = current.RebootToApply
			readState.ChangesPending = current.ChangesPending

			resp.Diagnostics.Append(resp.State.Set(ctx, &readState)...)
			return nil
		}); err != nil {
			addNSDPOperationError(&resp.Diagnostics, err)
		}
		return
	}

	if err := withNSDPClient(ctx, r.data, func(c nsdpClient) error {
		if err := nsdpV1Guard(c, "Port configuration management"); err != nil {
			return err
		}
		actual, err := readPortConfigs(c)
		if err != nil {
			return operationError("Read port configuration failed", err)
		}

		// Preserve a pre-existing ID (import passthrough); compute it
		// when absent.
		id := current.ID
		if id.IsNull() || id.IsUnknown() || strings.TrimSpace(id.ValueString()) == "" {
			id = types.StringValue(portConfigResourceID(r.data))
		}

		readState, err := flattenPortConfigs(actual, id)
		if err != nil {
			return operationError("Flatten port configuration failed", err)
		}
		// Pass-through flags on Read (running NSDP state applied live;
		// changes_pending always false on gs108ev3, values preserved
		// for plan-owned fields).
		readState.RebootToApply = current.RebootToApply
		readState.ChangesPending = current.ChangesPending

		resp.Diagnostics.Append(resp.State.Set(ctx, &readState)...)
		return nil
	}); err != nil {
		addNSDPOperationError(&resp.Diagnostics, err)
	}
}

func (r *portConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan portConfigResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *portConfigResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning(
		"Delete leaves switch configuration unchanged",
		"Destroying `netgear_plus_port_config` removes Terraform state only. The existing switch port configuration is preserved: silently reconfiguring physical ports on destroy would be an unsafe implicit rollback.",
	)
}

func (r *portConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// apply is the diff-apply-verify core shared by Create and Update, mirroring
// vlanStateResource.apply: expand + validate the plan, then inside the
// device lock (withNSDPClient): fresh GETs of all four blocks, SET only the
// changed ports/fields, tolerate lost SET replies, verify, run ONE
// corrective pass on mismatch, and surface a typed drift error when the
// device still disagrees.
func (r *portConfigResource) apply(ctx context.Context, plan portConfigResourceModel, target *tfsdk.State, diags *diag.Diagnostics) {
	if r.data == nil {
		diags.AddError("Provider not configured", "Configure the `netgear_plus` provider before managing `netgear_plus_port_config`.")
		return
	}

	// reboot_to_apply preflight for every model: gs108ev3 (and any
	// other non-text-config model) simply refuses the option; gs108tv2
	// additionally refuses while the reboot endpoint sentinel is
	// unpinned (phase 0b). Zero transport work either way.
	if err := preflightRebootToApply(r.data, plan.RebootToApply); err != nil {
		addNSDPOperationError(diags, err)
		return
	}

	// gs108tv2: the port configuration rides the composite text-config
	// transport (routing precedes the NSDP branch, so nsdpV1Guard never
	// fires on this model).
	if r.data.isGS108Tv2Model() {
		r.applyTextcfg(ctx, plan, target, diags)
		return
	}

	desired, err := expandPortConfigs(ctx, plan)
	if err != nil {
		diags.AddError("Invalid port configuration", err.Error())
		return
	}

	if err := withNSDPClient(ctx, r.data, func(c nsdpClient) error {
		if err := nsdpV1Guard(c, "Port configuration management"); err != nil {
			return err
		}
		actual, err := readPortConfigs(c)
		if err != nil {
			return operationError("Read current port configuration failed", err)
		}

		changes := portConfigChanges(desired, actual)
		if len(changes) == 0 {
			diags.AddWarning(
				"Port configuration already in sync",
				"All 8 ports already match the requested configuration; no SET operations were sent to the switch.",
			)
		} else if err := applyPortConfigChanges(c, changes, diags); err != nil {
			return operationError("Apply port configuration failed", err)
		}

		verified, err := readPortConfigs(c)
		if err != nil {
			return operationError("Read back port configuration failed", err)
		}

		// Silent no-ops exist on this firmware: one corrective pass
		// re-SETs whatever the verify GET shows as still wrong.
		if mismatches := portConfigChanges(desired, verified); len(mismatches) > 0 {
			if err := applyPortConfigChanges(c, mismatches, diags); err != nil {
				return operationError("Corrective port configuration pass failed", err)
			}

			verified, err = readPortConfigs(c)
			if err != nil {
				return operationError("Read back port configuration failed", err)
			}

			if mismatches := portConfigChanges(desired, verified); len(mismatches) > 0 {
				return &providerOperationError{
					summary: "Post-apply verification failed",
					detail: fmt.Sprintf(
						"switch port configuration did not converge to the requested configuration for %s: %s",
						portConfigResourceID(r.data),
						describePortConfigDrift(desired, verified),
					),
				}
			}
		}

		nextState, err := flattenPortConfigs(verified, types.StringValue(portConfigResourceID(r.data)))
		if err != nil {
			return operationError("Flatten verified port configuration failed", err)
		}
		// gs108ev3 semantics: NSDP SETs apply LIVE (nothing pending), and
		// the plan flags land in state unchanged (reboot_to_apply never
		// true here — the apply() preflight refuses it for this model).
		nextState.RebootToApply = normalizedBool(plan.RebootToApply)
		nextState.ChangesPending = types.BoolValue(false)

		diags.Append(target.Set(ctx, &nextState)...)
		return nil
	}); err != nil {
		addNSDPOperationError(diags, err)
	}
}

// portConfigResourceID is the stable state identity, house style
// ("gs108ev3@host" for HTTP resources, "nsdp@<device key>" for NSDP ones).
func portConfigResourceID(data *providerData) string {
	return "nsdp@" + data.deviceLockKey()
}

// portConfig is one port's configuration, either desired (from plan) or
// actual (decoded from the switch).
type portConfig struct {
	Port        int
	Enabled     bool
	FlowControl bool
	QoSPriority nsdp.QoSPriority
	IngressRate nsdp.BandwidthLimit
	EgressRate  nsdp.BandwidthLimit
}

// portConfigChange is the minimal SET plan for one changed port. The
// firmware 0x9400 SET handler always writes all three bytes per port, so
// one SetPortConfig call carries BOTH target flag values when either
// differs.
type portConfigChange struct {
	Port           int
	NeedPortConfig bool
	Enabled        bool
	FlowControl    bool
	NeedQoS        bool
	QoSPriority    nsdp.QoSPriority
	NeedIngress    bool
	IngressRate    nsdp.BandwidthLimit
	NeedEgress     bool
	EgressRate     nsdp.BandwidthLimit
}

func (ch portConfigChange) isEmpty() bool {
	return !ch.NeedPortConfig && !ch.NeedQoS && !ch.NeedIngress && !ch.NeedEgress
}

// expandPortConfigs converts the plan model to the desired per-port
// configuration, validating the port set (exactly 1-8, once each — with a
// diagnostic-ready message listing missing and duplicated numbers) and
// every enum value. Nulls fall back to the factory defaults the schema
// advertises, so a from-factory apply plans as a no-op.
func expandPortConfigs(ctx context.Context, model portConfigResourceModel) (map[int]portConfig, error) {
	_ = ctx

	ports := make(map[int]portConfig, portConfigPortCount)
	var duplicated []int
	for i := range model.Ports {
		p := model.Ports[i]

		var port int
		if p.Port.IsNull() {
			return nil, fmt.Errorf("`ports` entry %d has no port number", i+1)
		}
		port = int(p.Port.ValueInt64())
		if port < 1 || port > portConfigPortCount {
			return nil, fmt.Errorf("port %d out of range [1,%d]", port, portConfigPortCount)
		}
		if _, exists := ports[port]; exists {
			duplicated = append(duplicated, port)
			continue
		}

		enabled, err := expandPortBool(p.Enabled, defaultPortEnabled, port, "enabled")
		if err != nil {
			return nil, err
		}
		flow, err := expandPortBool(p.FlowControl, defaultPortFlowControl, port, "flow_control")
		if err != nil {
			return nil, err
		}
		qos, err := qosPriorityFromString(expandPortString(p.QoSPriority, defaultPortQoSPriority), port)
		if err != nil {
			return nil, err
		}
		ingress, err := bandwidthLimitFromString(expandPortString(p.IngressRate, defaultPortRateLimit), port, "ingress_rate")
		if err != nil {
			return nil, err
		}
		egress, err := bandwidthLimitFromString(expandPortString(p.EgressRate, defaultPortRateLimit), port, "egress_rate")
		if err != nil {
			return nil, err
		}

		ports[port] = portConfig{
			Port:        port,
			Enabled:     enabled,
			FlowControl: flow,
			QoSPriority: qos,
			IngressRate: ingress,
			EgressRate:  egress,
		}
	}

	var missing []int
	for port := 1; port <= portConfigPortCount; port++ {
		if _, ok := ports[port]; !ok {
			missing = append(missing, port)
		}
	}

	if len(missing) > 0 || len(duplicated) > 0 {
		var parts []string
		if len(missing) > 0 {
			parts = append(parts, fmt.Sprintf("missing port numbers %s", formatIntList(missing)))
		}
		if len(duplicated) > 0 {
			parts = append(parts, fmt.Sprintf("duplicated port numbers %s", formatIntList(duplicated)))
		}
		return nil, fmt.Errorf("`ports` must contain exactly the port numbers 1-%d once each: %s", portConfigPortCount, strings.Join(parts, "; "))
	}

	return ports, nil
}

func expandPortBool(value types.Bool, def bool, port int, field string) (bool, error) {
	switch {
	case value.IsNull():
		return def, nil
	case value.IsUnknown():
		return false, fmt.Errorf("port %d: `%s` is unknown at apply time", port, field)
	}
	return value.ValueBool(), nil
}

func expandPortString(value types.String, def string) string {
	if value.IsNull() || value.IsUnknown() {
		return def
	}
	return value.ValueString()
}

// flattenPortConfigs renders the verified device configuration as resource
// state. Unknown device enum values are a hard error: storing them would
// silently corrupt later diffs.
func flattenPortConfigs(configs map[int]portConfig, id types.String) (portConfigResourceModel, error) {
	model := portConfigResourceModel{
		ID:    id,
		Ports: make([]portConfigPortModel, 0, portConfigPortCount),
	}

	for port := 1; port <= portConfigPortCount; port++ {
		cfg, ok := configs[port]
		if !ok {
			return portConfigResourceModel{}, fmt.Errorf("port %d missing from the verified device configuration", port)
		}

		qos, err := qosPriorityToString(cfg.QoSPriority)
		if err != nil {
			return portConfigResourceModel{}, fmt.Errorf("port %d: %w", port, err)
		}
		ingress, err := bandwidthLimitToString(cfg.IngressRate)
		if err != nil {
			return portConfigResourceModel{}, fmt.Errorf("port %d: %w", port, err)
		}
		egress, err := bandwidthLimitToString(cfg.EgressRate)
		if err != nil {
			return portConfigResourceModel{}, fmt.Errorf("port %d: %w", port, err)
		}

		model.Ports = append(model.Ports, portConfigPortModel{
			Port:        types.Int64Value(int64(port)),
			Enabled:     types.BoolValue(cfg.Enabled),
			FlowControl: types.BoolValue(cfg.FlowControl),
			QoSPriority: types.StringValue(qos),
			IngressRate: types.StringValue(ingress),
			EgressRate:  types.StringValue(egress),
		})
	}

	return model, nil
}

// readPortConfigs GETs all four configuration blocks and decodes them into
// the per-port map. Every block must cover all 8 ports; anything else is a
// read error, never a guess.
func readPortConfigs(c nsdpClient) (map[int]portConfig, error) {
	adminAttrs, err := c.GetBlock(nsdpBlockPortConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("read port admin/flow-control block 0x9400: %w", err)
	}
	qosAttrs, err := c.GetBlock(nsdpBlockPortQoS, nil)
	if err != nil {
		return nil, fmt.Errorf("read per-port QoS block 0x3800: %w", err)
	}
	ingressAttrs, err := c.GetBlock(nsdpBlockIngressRate, nil)
	if err != nil {
		return nil, fmt.Errorf("read ingress rate block 0x4c00: %w", err)
	}
	egressAttrs, err := c.GetBlock(nsdpBlockEgressRate, nil)
	if err != nil {
		return nil, fmt.Errorf("read egress rate block 0x5000: %w", err)
	}

	admin := indexPortAdminStatus(collectPortAdminStatus(adminAttrs))
	qos := indexPortQoS(collectPortQoS(qosAttrs))
	ingress := indexBandwidth(collectBandwidth(ingressAttrs))
	egress := indexBandwidth(collectBandwidth(egressAttrs))

	configs := make(map[int]portConfig, portConfigPortCount)
	for port := 1; port <= portConfigPortCount; port++ {
		adminEntry, okAdmin := admin[port]
		qosEntry, okQoS := qos[port]
		ingressEntry, okIngress := ingress[port]
		egressEntry, okEgress := egress[port]

		var missing []string
		if !okAdmin {
			missing = append(missing, "0x9400 admin/flow-control")
		}
		if !okQoS {
			missing = append(missing, "0x3800 QoS priority")
		}
		if !okIngress {
			missing = append(missing, "0x4c00 ingress rate")
		}
		if !okEgress {
			missing = append(missing, "0x5000 egress rate")
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("port %d missing from block reply(s): %s", port, strings.Join(missing, ", "))
		}

		configs[port] = portConfig{
			Port:        port,
			Enabled:     adminEntry.Admin != 0,
			FlowControl: adminEntry.Flow != 0,
			QoSPriority: qosEntry.Priority,
			IngressRate: nsdp.BandwidthLimit(ingressEntry.Limit),
			EgressRate:  nsdp.BandwidthLimit(egressEntry.Limit),
		}
	}

	return configs, nil
}

func collectPortAdminStatus(attrs []nsdp.Attr) []nsdp.PortAdminStatusEntry {
	var entries []nsdp.PortAdminStatusEntry
	for _, a := range attrs {
		if decoded, ok := a.Decoded.([]nsdp.PortAdminStatusEntry); ok {
			entries = append(entries, decoded...)
		}
	}
	return entries
}

func collectPortQoS(attrs []nsdp.Attr) []nsdp.PortQoSEntry {
	var entries []nsdp.PortQoSEntry
	for _, a := range attrs {
		if decoded, ok := a.Decoded.([]nsdp.PortQoSEntry); ok {
			entries = append(entries, decoded...)
		}
	}
	return entries
}

// collectBandwidth accepts both wire shapes the decoder produces: live
// 0x4c00/0x5000 replies carry ONE 5-byte TLV per port (single BandwidthEntry
// per Attr), while a packed table would decode as a slice.
func collectBandwidth(attrs []nsdp.Attr) []nsdp.BandwidthEntry {
	var entries []nsdp.BandwidthEntry
	for _, a := range attrs {
		switch decoded := a.Decoded.(type) {
		case nsdp.BandwidthEntry:
			entries = append(entries, decoded)
		case []nsdp.BandwidthEntry:
			entries = append(entries, decoded...)
		}
	}
	return entries
}

func indexPortAdminStatus(entries []nsdp.PortAdminStatusEntry) map[int]nsdp.PortAdminStatusEntry {
	byPort := make(map[int]nsdp.PortAdminStatusEntry, len(entries))
	for _, e := range entries {
		byPort[int(e.Port)] = e
	}
	return byPort
}

func indexPortQoS(entries []nsdp.PortQoSEntry) map[int]nsdp.PortQoSEntry {
	byPort := make(map[int]nsdp.PortQoSEntry, len(entries))
	for _, e := range entries {
		byPort[int(e.Port)] = e
	}
	return byPort
}

func indexBandwidth(entries []nsdp.BandwidthEntry) map[int]nsdp.BandwidthEntry {
	byPort := make(map[int]nsdp.BandwidthEntry, len(entries))
	for _, e := range entries {
		byPort[int(e.Port)] = e
	}
	return byPort
}

// portConfigChanges computes the minimal SET list: for each port, only the
// fields whose target differs from actual. An empty result means the device
// already matches the plan.
func portConfigChanges(desired, actual map[int]portConfig) []portConfigChange {
	var changes []portConfigChange
	for port := 1; port <= portConfigPortCount; port++ {
		d, a := desired[port], actual[port]

		var change portConfigChange
		if d.Enabled != a.Enabled || d.FlowControl != a.FlowControl {
			change.NeedPortConfig = true
			change.Enabled = d.Enabled
			change.FlowControl = d.FlowControl
		}
		if d.QoSPriority != a.QoSPriority {
			change.NeedQoS = true
			change.QoSPriority = d.QoSPriority
		}
		if d.IngressRate != a.IngressRate {
			change.NeedIngress = true
			change.IngressRate = d.IngressRate
		}
		if d.EgressRate != a.EgressRate {
			change.NeedEgress = true
			change.EgressRate = d.EgressRate
		}

		if !change.isEmpty() {
			change.Port = port
			changes = append(changes, change)
		}
	}
	return changes
}

// applyPortConfigChanges sends the SETs for the changed ports/fields, in
// port order. NSDP SET replies can be lost while the write still applies:
// on ErrNoReply the SET is never re-sent — a warning is recorded and the
// verify GET (read is truth) settles the question later.
func applyPortConfigChanges(c nsdpClient, changes []portConfigChange, diags *diag.Diagnostics) error {
	for _, change := range changes {
		if change.NeedPortConfig {
			if err := c.SetPortConfig(change.Port, change.Enabled, change.FlowControl); err != nil {
				if !errors.Is(err, nsdp.ErrNoReply) {
					return fmt.Errorf("set port %d admin/flow-control config: %w", change.Port, err)
				}
				diags.AddWarning(
					"SET reply lost",
					fmt.Sprintf("The switch did not answer the port %d admin/flow-control SET. The write may still have applied; continuing to verification (device read is truth).", change.Port),
				)
			}
		}
		if change.NeedQoS {
			if err := c.SetQoSPriority(change.Port, change.QoSPriority); err != nil {
				if !errors.Is(err, nsdp.ErrNoReply) {
					return fmt.Errorf("set port %d QoS priority: %w", change.Port, err)
				}
				diags.AddWarning(
					"SET reply lost",
					fmt.Sprintf("The switch did not answer the port %d QoS priority SET. The write may still have applied; continuing to verification (device read is truth).", change.Port),
				)
			}
		}
		if change.NeedIngress {
			if err := c.SetIngressRate(change.Port, change.IngressRate); err != nil {
				if !errors.Is(err, nsdp.ErrNoReply) {
					return fmt.Errorf("set port %d ingress rate limit: %w", change.Port, err)
				}
				diags.AddWarning(
					"SET reply lost",
					fmt.Sprintf("The switch did not answer the port %d ingress rate SET. The write may still have applied; continuing to verification (device read is truth).", change.Port),
				)
			}
		}
		if change.NeedEgress {
			if err := c.SetEgressRate(change.Port, change.EgressRate); err != nil {
				if !errors.Is(err, nsdp.ErrNoReply) {
					return fmt.Errorf("set port %d egress rate limit: %w", change.Port, err)
				}
				diags.AddWarning(
					"SET reply lost",
					fmt.Sprintf("The switch did not answer the port %d egress rate SET. The write may still have applied; continuing to verification (device read is truth).", change.Port),
				)
			}
		}
	}
	return nil
}

// describePortConfigDrift renders the remaining per-port per-field drift,
// vlan_state describer style: "port 3: qos_priority=low (wanted normal)".
// Device enum values render in the config vocabulary (lowercased wire enum
// names) so expected and actual are directly comparable.
func describePortConfigDrift(desired, actual map[int]portConfig) string {
	var parts []string
	for port := 1; port <= portConfigPortCount; port++ {
		d, a := desired[port], actual[port]

		var fields []string
		if d.Enabled != a.Enabled {
			fields = append(fields, fmt.Sprintf("enabled=%t (wanted %t)", a.Enabled, d.Enabled))
		}
		if d.FlowControl != a.FlowControl {
			fields = append(fields, fmt.Sprintf("flow_control=%t (wanted %t)", a.FlowControl, d.FlowControl))
		}
		if d.QoSPriority != a.QoSPriority {
			fields = append(fields, fmt.Sprintf("qos_priority=%s (wanted %s)", strings.ToLower(a.QoSPriority.String()), strings.ToLower(d.QoSPriority.String())))
		}
		if d.IngressRate != a.IngressRate {
			fields = append(fields, fmt.Sprintf("ingress_rate=%s (wanted %s)", strings.ToLower(a.IngressRate.String()), strings.ToLower(d.IngressRate.String())))
		}
		if d.EgressRate != a.EgressRate {
			fields = append(fields, fmt.Sprintf("egress_rate=%s (wanted %s)", strings.ToLower(a.EgressRate.String()), strings.ToLower(d.EgressRate.String())))
		}

		if len(fields) > 0 {
			parts = append(parts, fmt.Sprintf("port %d: %s", port, strings.Join(fields, ", ")))
		}
	}

	if len(parts) == 0 {
		return "device readback differed from plan"
	}

	return strings.Join(parts, "; ")
}

// qosPriorityFromString maps the config vocabulary to the wire enum
// (1=High, 2=Middle, 3=Normal, 4=Low; factory 4=Low).
func qosPriorityFromString(value string, port int) (nsdp.QoSPriority, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return 1, nil
	case "middle":
		return 2, nil
	case "normal":
		return 3, nil
	case "low":
		return 4, nil
	}
	return 0, fmt.Errorf("port %d: invalid `qos_priority` %q: want one of %s", port, value, strings.Join(qosPriorities, ", "))
}

func qosPriorityToString(priority nsdp.QoSPriority) (string, error) {
	switch priority {
	case 1:
		return "high", nil
	case 2:
		return "middle", nil
	case 3:
		return "normal", nil
	case 4:
		return "low", nil
	}
	return "", fmt.Errorf("switch reported unknown QoS priority %d", byte(priority))
}

// bandwidthLimitFromString maps the config vocabulary to the wire enum
// (0=None, 1=512K … 0x0b=512M; factory 0=None).
func bandwidthLimitFromString(value string, port int, field string) (nsdp.BandwidthLimit, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "none":
		return nsdp.BandwidthNone, nil
	case "512k":
		return nsdp.Bandwidth512K, nil
	case "1m":
		return nsdp.Bandwidth1M, nil
	case "2m":
		return nsdp.Bandwidth2M, nil
	case "4m":
		return nsdp.Bandwidth4M, nil
	case "8m":
		return nsdp.Bandwidth8M, nil
	case "16m":
		return nsdp.Bandwidth16M, nil
	case "32m":
		return nsdp.Bandwidth32M, nil
	case "64m":
		return nsdp.Bandwidth64M, nil
	case "128m":
		return nsdp.Bandwidth128M, nil
	case "256m":
		return nsdp.Bandwidth256M, nil
	case "512m":
		return nsdp.Bandwidth512M, nil
	}
	return 0, fmt.Errorf("port %d: invalid `%s` %q: want one of %s", port, field, value, strings.Join(rateLimits, ", "))
}

func bandwidthLimitToString(limit nsdp.BandwidthLimit) (string, error) {
	switch limit {
	case nsdp.BandwidthNone:
		return "none", nil
	case nsdp.Bandwidth512K:
		return "512k", nil
	case nsdp.Bandwidth1M:
		return "1m", nil
	case nsdp.Bandwidth2M:
		return "2m", nil
	case nsdp.Bandwidth4M:
		return "4m", nil
	case nsdp.Bandwidth8M:
		return "8m", nil
	case nsdp.Bandwidth16M:
		return "16m", nil
	case nsdp.Bandwidth32M:
		return "32m", nil
	case nsdp.Bandwidth64M:
		return "64m", nil
	case nsdp.Bandwidth128M:
		return "128m", nil
	case nsdp.Bandwidth256M:
		return "256m", nil
	case nsdp.Bandwidth512M:
		return "512m", nil
	}
	return "", fmt.Errorf("switch reported unknown bandwidth limit %d", uint16(limit))
}

// addNSDPOperationError appends err as a diagnostic. NSDP auth failures get
// the actionable lockout guidance: a wrong password OR the ~30-minute SET
// lockout (three failed logins) look identical from the wire.
func addNSDPOperationError(diags diagnosticAdder, err error) {
	if err == nil {
		return
	}

	if !isNSDPAuthFailure(err) {
		addDriverError(diags, err)
		return
	}

	summary := "NSDP authentication failed"
	detail := err.Error() + "\n\nVerify the provider `password` is correct. If it is, the switch's ~30-minute SET lockout is probably active: three failed NSDP login attempts lock ALL SET operations, and the lockout does not clear early. Wait for it to expire, then re-apply."

	var opErr *providerOperationError
	if errors.As(err, &opErr) {
		summary = opErr.summary
		detail = opErr.detail + "\n\nVerify the provider `password` is correct. If it is, the switch's ~30-minute SET lockout is probably active: three failed NSDP login attempts lock ALL SET operations, and the lockout does not clear early. Wait for it to expire, then re-apply."
	}

	diags.AddError(summary, detail)
}

// ---------------------------------------------------------------------------
// gs108tv2 text-config path (milestone 3): the per-port configuration
// rides the composite transport. Same diff→apply→verify shape as the
// NSDP branch, different verify truth: the startup-config decode is the
// single source of truth before (and after) the switch's ingest window,
// and running state changes only on reboot.
// ---------------------------------------------------------------------------

// applyTextcfg is the gs108tv2 apply shared by Create and Update.
//
// Preflight order (all BEFORE any staging and any transport work):
//  1. provider-layer capability refusals: for every port requesting a
//     NON-DEFAULT value of an Unsupported attribute (qos_priority !=
//     "low", ingress_rate/egress_rate != "none"), a typed per-port
//     diagnostic naming port, attribute, requested value, and the
//     capability reason — mirroring the driver's
//     ErrUnsupportedAttribute pre-upload refusals but surfaced as
//     coherent per-port diagnostics instead of the first error;
//  2. the gs108tv2 serial-pin rail (requireGS108Tv2SerialPin);
//  3. the reboot endpoint preflight already ran in apply() above.
func (r *portConfigResource) applyTextcfg(ctx context.Context, plan portConfigResourceModel, target *tfsdk.State, diags *diag.Diagnostics) {
	desired, err := expandPortConfigs(ctx, plan)
	if err != nil {
		diags.AddError("Invalid port configuration", err.Error())
		return
	}

	desiredSettings := configsToTextPortSettings(desired)

	// 1. Capability refusals, per port, per attribute.
	for _, refusal := range portCapabilityRefusals(desiredSettings) {
		diags.AddError(refusal.summary, refusal.detail)
	}
	if diags.HasError() {
		return
	}

	// 2. The same serial-pin safety rail vlan_state uses (fail-closed
	// before any staging — the whole-startup-config rewrite must never
	// land on an unpinned target).
	if err := requireGS108Tv2SerialPin(r.data); err != nil {
		addNSDPOperationError(diags, err)
		return
	}

	if err := withSwitchTransport(ctx, r.data, func(transport switchTransport) error {
		reader, ok := transport.(portSettingsTransport)
		if !ok {
			return fmt.Errorf("the gs108tv2 transport cannot read port settings")
		}
		applier, ok := transport.(detailedPortSettingsApplier)
		if !ok {
			return fmt.Errorf("the gs108tv2 transport cannot apply port settings")
		}

		current, err := reader.ReadPortSettings(ctx)
		if err != nil {
			return operationError("Read current port configuration failed", err)
		}
		changed := !textPortSettingsEqual(current, desiredSettings)

		if !changed {
			diags.AddWarning(
				"Port configuration already in sync",
				"All 8 ports already match the requested configuration in the staged startup-config; no configuration restore was sent to the switch.",
			)
		}

		outcome, err := applier.ApplyPortSettingsDetailed(ctx, desiredSettings)
		if err != nil {
			return operationError("Apply port configuration failed", err)
		}

		verified, err := reader.ReadPortSettings(ctx)
		if err != nil {
			return operationError("Read back port configuration failed", err)
		}
		if !textPortSettingsEqual(verified, desiredSettings) {
			return &providerOperationError{
				summary: "Post-apply verification failed",
				detail: fmt.Sprintf(
					"switch port configuration did not converge to the requested configuration for %s: %s",
					transport.ResourceID(),
					describeTextPortSettingsDrift(desiredSettings, verified),
				),
			}
		}

		// changes_pending + reboot_to_apply. RECOVERY SHAPE after a
		// failed reboot: the resource state is NOT written (this error
		// path returns before target.Set) — the next apply sends only
		// the driver's idempotent short-circuit (the startup-config
		// already decodes Equal to the desired port map, zero restore
		// POSTs) followed by RebootAndWait again. The reboot is the
		// only retried side effect.
		changesPending := changed
		if changed && rebootToApplyEnabled(plan.RebootToApply) {
			rebooter, ok := transport.(textcfgRebooter)
			if !ok {
				return fmt.Errorf("the gs108tv2 transport cannot reboot")
			}
			if _, err := rebooter.Reboot(ctx); err != nil {
				return operationError("gs108tv2: reboot for apply failed", err)
			}
			// Success: the change is ACTIVE, not pending.
			changesPending = false
		}

		nextState, err := flattenPortConfigs(textPortSettingsToConfigs(verified), types.StringValue(transport.ResourceID()))
		if err != nil {
			return operationError("Flatten verified port configuration failed", err)
		}
		nextState.RebootToApply = normalizedBool(plan.RebootToApply)
		nextState.ChangesPending = types.BoolValue(changesPending)

		diags.Append(target.Set(ctx, &nextState)...)

		addGS108Tv2StagedWarnings(diags, outcome, "Port configuration changes", changesPending)
		return nil
	}); err != nil {
		addNSDPOperationError(diags, err)
	}
}

// portCapabilityRefusals mirrors the driver's capability table
// (gs108tv2.validatePortSettings) at the provider layer: for every
// port requesting a NON-DEFAULT value of an Unsupported attribute it
// returns a typed per-port refusal (an ErrUnsupportedAttribute as the
// cause). The default values render by absence and are accepted.
func portCapabilityRefusals(desired map[int]gs108tv2.PortSettings) []*providerOperationError {
	var refusals []*providerOperationError

	check := func(port int, attribute, value, def string) {
		capability, ok := gs108tv2.PortSettingCapabilities[attribute]
		if !ok || capability.Status != gs108tv2.AttributeUnsupported || value == def {
			return
		}
		typed := &gs108tv2.ErrUnsupportedAttribute{Port: port, Attribute: attribute, Value: value, Reason: capability.Reason}
		refusals = append(refusals, &providerOperationError{
			summary: fmt.Sprintf("Port %d: %q is not supported on gs108tv2 over the text-config channel", port, attribute),
			detail: fmt.Sprintf(
				"The requested %s for port %d is %q, but port %d has no %s grammar on this FASTPATH firmware yet: only the default value %q renders (its absence line IS the value). %s. Keep the default for port %d, or drop the attribute override.",
				attributeNameForHumans(attribute), port, typed.Value, port, attribute, def, capability.Reason, port,
			),
			cause: typed,
		})
	}

	for port := 1; port <= portConfigPortCount; port++ {
		ps, ok := desired[port]
		if !ok {
			refusals = append(refusals, &providerOperationError{
				summary: fmt.Sprintf("Port %d missing from the gs108tv2 port configuration", port),
				detail:  "The text-config port map must cover all 8 ports (missing entries are refused, not defaulted); expandPortConfigs already guarantees this — this refusal is the defensive mirror of the driver's check.",
			})
			continue
		}
		check(port, "qos_priority", ps.QoSPriority, defaultPortQoSPriority)
		check(port, "ingress_rate", ps.IngressRate, defaultPortRateLimit)
		check(port, "egress_rate", ps.EgressRate, defaultPortRateLimit)
	}
	return refusals
}

// attributeNameForHumans renders attribute keys in the refusal text
// (identity function today, kept for future key renames).
func attributeNameForHumans(attribute string) string {
	return attribute
}

// configsToTextPortSettings maps the provider portConfig map (NSDP enum
// fields) onto the driver's text-config value set (schema vocabulary
// strings; the driver renders defaults by absence).
func configsToTextPortSettings(configs map[int]portConfig) map[int]gs108tv2.PortSettings {
	out := make(map[int]gs108tv2.PortSettings, portConfigPortCount)
	for port := 1; port <= portConfigPortCount; port++ {
		cfg := configs[port]
		qos, _ := qosPriorityToString(cfg.QoSPriority)
		ingress, _ := bandwidthLimitToString(cfg.IngressRate)
		egress, _ := bandwidthLimitToString(cfg.EgressRate)
		out[port] = gs108tv2.PortSettings{
			Enabled:     cfg.Enabled,
			FlowControl: cfg.FlowControl,
			QoSPriority: qos,
			IngressRate: ingress,
			EgressRate:  egress,
		}
	}
	return out
}

// textPortSettingsToConfigs maps the driver's PortSettings decode back
// onto the provider model (enum strings → wire enums; the decode only
// ever produces the schema vocabulary, so the mappers cannot fail
// there — errors are impossible-value defenses with hard errors).
func textPortSettingsToConfigs(ports map[int]gs108tv2.PortSettings) map[int]portConfig {
	configs := make(map[int]portConfig, portConfigPortCount)
	for port := 1; port <= portConfigPortCount; port++ {
		ps, ok := ports[port]
		if !ok {
			ps = gs108tv2.DefaultPortSettings()
		}
		qos, err := qosPriorityFromString(ps.QoSPriority, port)
		if err != nil {
			qos = 4 // nsdp.QoSPriority low — defensive, unreachable via the codec
		}
		ingress, err := bandwidthLimitFromString(ps.IngressRate, port, "ingress_rate")
		if err != nil {
			ingress = nsdp.BandwidthNone
		}
		egress, err := bandwidthLimitFromString(ps.EgressRate, port, "egress_rate")
		if err != nil {
			egress = nsdp.BandwidthNone
		}
		configs[port] = portConfig{
			Port:        port,
			Enabled:     ps.Enabled,
			FlowControl: ps.FlowControl,
			QoSPriority: qos,
			IngressRate: ingress,
			EgressRate:  egress,
		}
	}
	return configs
}

// textPortSettingsEqual compares two full 1..8 gs108tv2.PortSettings
// maps field by field (the codec's comparator is package-internal).
func textPortSettingsEqual(a, b map[int]gs108tv2.PortSettings) bool {
	if len(a) != len(b) {
		return false
	}
	for port, sa := range a {
		sb, ok := b[port]
		if !ok || sa != sb {
			return false
		}
	}
	return true
}

// describeTextPortSettingsDrift renders the human diff between the
// desired and the re-read port settings for verification errors.
func describeTextPortSettingsDrift(desired, actual map[int]gs108tv2.PortSettings) string {
	var deltas []string
	for port := 1; port <= portConfigPortCount; port++ {
		want, wok := desired[port]
		got, gok := actual[port]
		if !wok || !gok {
			deltas = append(deltas, fmt.Sprintf("port %d missing (want=%v got=%v)", port, wok, gok))
			continue
		}
		if want != got {
			deltas = append(deltas, fmt.Sprintf("port %d: enabled=%v/%v flow_control=%v/%v qos=%q/%q ingress=%q/%q egress=%q/%q",
				port,
				want.Enabled, got.Enabled,
				want.FlowControl, got.FlowControl,
				want.QoSPriority, got.QoSPriority,
				want.IngressRate, got.IngressRate,
				want.EgressRate, got.EgressRate))
		}
	}
	if len(deltas) == 0 {
		return "identical"
	}
	return strings.Join(deltas, "; ")
}
