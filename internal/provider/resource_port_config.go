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
	ID    types.String          `tfsdk:"id"`
	Ports []portConfigPortModel `tfsdk:"ports"`
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
		Description: "Authoritative per-port configuration for all 8 ports of an NSDP-managed switch: admin enable, flow control, per-port QoS priority, and ingress/egress rate limits.",
		Attributes: map[string]rschema.Attribute{
			"id": rschema.StringAttribute{
				Computed:    true,
				Description: "Stable switch identifier (nsdp@<agent MAC>).",
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

	if err := withNSDPClient(ctx, r.data, func(c nsdpClient) error {
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

	desired, err := expandPortConfigs(ctx, plan)
	if err != nil {
		diags.AddError("Invalid port configuration", err.Error())
		return
	}

	if err := withNSDPClient(ctx, r.data, func(c nsdpClient) error {
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
