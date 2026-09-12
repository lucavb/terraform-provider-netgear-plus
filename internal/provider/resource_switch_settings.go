package provider

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// NSDP block GET identifiers for the global switch settings (byte prefix
// of the 0xNN00 family tags).
const (
	nsdpBlockQoSMode          = 0x34 // 0x3400 global QoS scheduling mode
	nsdpBlockUnknownMulticast = 0x6c // 0x6c00 global 1-byte boolean
	nsdpBlockPortMirroring    = 0x5c // 0x5c00 {dst, reserved, src bitmap}
	nsdpBlockVLANEngineMode   = 0x20 // 0x2000 VLAN engine mode (port_based_vlan guard)
	nsdpBlockPortBasedVLAN    = 0x24 // 0x2400 port-based VLAN table
)

// Factory defaults the schema descriptions advertise (a from-factory apply
// plans as a no-op).
const (
	defaultSwitchQoSMode               = "port-based"
	defaultSwitchBlockUnknownMulticast = false
	defaultMirrorDestinationPort       = 0 // 0 = mirroring disabled
)

// switchSettingsQoSModes is the qos_mode config vocabulary, wire order.
var switchSettingsQoSModes = []string{"port-based", "802.1p"}

type switchSettingsResource struct {
	data *providerData
}

type switchSettingsResourceModel struct {
	ID                    types.String `tfsdk:"id"`
	QoSMode               types.String `tfsdk:"qos_mode"`
	BlockUnknownMulticast types.Bool   `tfsdk:"block_unknown_multicast"`
	MirrorDestinationPort types.Int64  `tfsdk:"mirror_destination_port"`
	MirrorSourcePorts     types.Set    `tfsdk:"mirror_source_ports"`
}

// NewSwitchSettingsResource returns the global switch settings resource.
func NewSwitchSettingsResource() resource.Resource {
	return &switchSettingsResource{}
}

func (r *switchSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_switch_settings"
}

func (r *switchSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = rschema.Schema{
		Description: "Global NSDP-managed switch settings: QoS scheduling mode, unknown-multicast blocking, and port mirroring. One instance models the whole switch.",
		Attributes: map[string]rschema.Attribute{
			"id": rschema.StringAttribute{
				Computed:    true,
				Description: "Stable switch identifier (nsdp@<agent MAC>).",
			},
			"qos_mode": rschema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(defaultSwitchQoSMode),
				Description: "Global QoS scheduling mode: `port-based` (per-port priorities via netgear_plus_port_config) or `802.1p` (priority carried in tagged frames). Defaults to `port-based`, the factory value. The 0x3400 SET is source-confirmed (ProSafeLinux + firmware) but not yet live-proven; a failed write surfaces as a verification drift error.",
				Validators: []validator.String{
					stringvalidator.OneOf(switchSettingsQoSModes...),
				},
			},
			"block_unknown_multicast": rschema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(defaultSwitchBlockUnknownMulticast),
				Description: "Block unknown multicast traffic (global toggle). Defaults to `false`, the factory value. The 0x6c00 SET is source-confirmed (ProSafeLinux + firmware) but not yet live-proven; a failed write surfaces as a verification drift error.",
			},
			"mirror_destination_port": rschema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(defaultMirrorDestinationPort),
				Description: "Mirror destination port, 1-8; `0` disables port mirroring (factory default). The 0x5c00 SET is source-confirmed (ProSafeLinux + firmware) but not yet live-proven; a failed write surfaces as a verification drift error.",
				Validators: []validator.Int64{
					int64validator.Between(0, portConfigPortCount),
				},
			},
			"mirror_source_ports": rschema.SetAttribute{
				Optional:    true,
				Computed:    true,
				Default:     setdefault.StaticValue(types.SetValueMust(types.Int64Type, []attr.Value{})),
				ElementType: types.Int64Type,
				Description: "Mirror source ports (set of 1-8). Must be non-empty when `mirror_destination_port` is set, empty when mirroring is disabled (destination 0), and must not contain the destination port.",
				Validators: []validator.Set{
					setvalidator.ValueInt64sAre(int64validator.Between(1, portConfigPortCount)),
				},
			},
		},
	}
}

func (r *switchSettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.data = req.ProviderData.(*providerData)
}

func (r *switchSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan switchSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *switchSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var current switchSettingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &current)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if r.data == nil {
		resp.Diagnostics.AddError("Provider not configured", "Configure the `netgear_plus` provider before reading `netgear_plus_switch_settings`.")
		return
	}

	if err := withNSDPClient(ctx, r.data, func(c nsdpClient) error {
		actual, err := readSwitchSettings(c)
		if err != nil {
			return operationError("Read switch settings failed", err)
		}

		// Preserve a pre-existing ID (import passthrough); compute it
		// when absent.
		id := current.ID
		if id.IsNull() || id.IsUnknown() || strings.TrimSpace(id.ValueString()) == "" {
			id = types.StringValue(portConfigResourceID(r.data))
		}

		readState, err := flattenSwitchSettings(ctx, actual, id)
		if err != nil {
			return operationError("Flatten switch settings failed", err)
		}

		resp.Diagnostics.Append(resp.State.Set(ctx, &readState)...)
		return nil
	}); err != nil {
		addNSDPOperationError(&resp.Diagnostics, err)
	}
}

func (r *switchSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan switchSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *switchSettingsResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning(
		"Delete leaves switch configuration unchanged",
		"Destroying `netgear_plus_switch_settings` removes Terraform state only. The existing switch settings are preserved: silently reconfiguring QoS mode, multicast blocking, or port mirroring on destroy would be an unsafe implicit rollback.",
	)
}

func (r *switchSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// apply is the diff-apply-verify core shared by Create and Update,
// mirroring the port_config / vlan_state house template.
func (r *switchSettingsResource) apply(ctx context.Context, plan switchSettingsResourceModel, target *tfsdk.State, diags *diag.Diagnostics) {
	if r.data == nil {
		diags.AddError("Provider not configured", "Configure the `netgear_plus` provider before managing `netgear_plus_switch_settings`.")
		return
	}

	desired, err := expandSwitchSettings(ctx, plan)
	if err != nil {
		diags.AddError("Invalid switch settings", err.Error())
		return
	}

	if err := withNSDPClient(ctx, r.data, func(c nsdpClient) error {
		actual, err := readSwitchSettings(c)
		if err != nil {
			return operationError("Read current switch settings failed", err)
		}

		changes := switchSettingsChanges(desired, actual)
		if changes.isEmpty() {
			diags.AddWarning(
				"Switch settings already in sync",
				"The switch already matches the requested settings; no SET operations were sent to the switch.",
			)
		} else if err := applySwitchSettingsChanges(c, changes, diags); err != nil {
			return operationError("Apply switch settings failed", err)
		}

		verified, err := readSwitchSettings(c)
		if err != nil {
			return operationError("Read back switch settings failed", err)
		}

		// Silent no-ops exist on this firmware: one corrective pass
		// re-SETs whatever the verify GET shows as still wrong.
		if correction := switchSettingsChanges(desired, verified); !correction.isEmpty() {
			if err := applySwitchSettingsChanges(c, correction, diags); err != nil {
				return operationError("Corrective switch settings pass failed", err)
			}

			verified, err = readSwitchSettings(c)
			if err != nil {
				return operationError("Read back switch settings failed", err)
			}

			if correction := switchSettingsChanges(desired, verified); !correction.isEmpty() {
				return &providerOperationError{
					summary: "Post-apply verification failed",
					detail: fmt.Sprintf(
						"switch settings did not converge to the requested configuration for %s: %s",
						portConfigResourceID(r.data),
						describeSwitchSettingsDrift(desired, verified),
					),
				}
			}
		}

		nextState, err := flattenSwitchSettings(ctx, verified, types.StringValue(portConfigResourceID(r.data)))
		if err != nil {
			return operationError("Flatten verified switch settings failed", err)
		}

		diags.Append(target.Set(ctx, &nextState)...)
		return nil
	}); err != nil {
		addNSDPOperationError(diags, err)
	}
}

// switchSettings is the global settings, desired or actual.
type switchSettings struct {
	QoSMode               nsdp.QoSMode
	BlockUnknownMulticast bool
	MirrorDst             int   // 0 = mirroring disabled
	MirrorSrc             []int // sorted source ports
}

// switchSettingsChange is the minimal SET plan: one flag per changed
// field. The mirror SET always carries destination and sources together.
type switchSettingsChange struct {
	NeedQoSMode      bool
	QoSMode          nsdp.QoSMode
	NeedBlockUnknown bool
	BlockUnknown     bool
	NeedMirror       bool
	MirrorDst        int
	MirrorSrc        []int
}

func (ch switchSettingsChange) isEmpty() bool {
	return !ch.NeedQoSMode && !ch.NeedBlockUnknown && !ch.NeedMirror
}

// expandSwitchSettings converts the plan model to the desired settings,
// applying the factory defaults for nulls (so a from-factory apply plans
// as a no-op) and validating the mirror rules with clear diagnostics.
func expandSwitchSettings(ctx context.Context, model switchSettingsResourceModel) (switchSettings, error) {
	settings := switchSettings{
		QoSMode:               nsdp.QoSModePortBased,
		BlockUnknownMulticast: defaultSwitchBlockUnknownMulticast,
		MirrorDst:             defaultMirrorDestinationPort,
	}

	if !model.QoSMode.IsNull() && !model.QoSMode.IsUnknown() {
		mode, err := switchQoSModeFromString(model.QoSMode.ValueString())
		if err != nil {
			return settings, err
		}
		settings.QoSMode = mode
	}

	if !model.BlockUnknownMulticast.IsNull() && !model.BlockUnknownMulticast.IsUnknown() {
		settings.BlockUnknownMulticast = model.BlockUnknownMulticast.ValueBool()
	}

	if !model.MirrorDestinationPort.IsNull() && !model.MirrorDestinationPort.IsUnknown() {
		dst := model.MirrorDestinationPort.ValueInt64()
		if dst < 0 || dst > portConfigPortCount {
			return settings, fmt.Errorf("`mirror_destination_port` must be 0 (mirroring disabled) or a port number in [1,%d], got %d", portConfigPortCount, dst)
		}
		settings.MirrorDst = int(dst)
	}

	if !model.MirrorSourcePorts.IsNull() && !model.MirrorSourcePorts.IsUnknown() {
		var srcs []int64
		if diags := model.MirrorSourcePorts.ElementsAs(ctx, &srcs, false); diags.HasError() {
			return settings, fmt.Errorf("expand mirror_source_ports: %s", diags.Errors()[0].Detail())
		}
		for _, src := range srcs {
			if src < 1 || src > portConfigPortCount {
				return settings, fmt.Errorf("`mirror_source_ports` contains port %d, out of range [1,%d]", src, portConfigPortCount)
			}
			settings.MirrorSrc = append(settings.MirrorSrc, int(src))
		}
		slices.Sort(settings.MirrorSrc)
		settings.MirrorSrc = slices.Compact(settings.MirrorSrc)
	}

	switch {
	case settings.MirrorDst == 0 && len(settings.MirrorSrc) > 0:
		return switchSettings{}, fmt.Errorf("`mirror_source_ports` must be empty when `mirror_destination_port` is 0 (mirroring disabled), got %s", formatIntList(settings.MirrorSrc))
	case settings.MirrorDst != 0 && len(settings.MirrorSrc) == 0:
		return switchSettings{}, fmt.Errorf("`mirror_source_ports` must name at least one source port when `mirror_destination_port` is %d", settings.MirrorDst)
	case settings.MirrorDst != 0 && slices.Contains(settings.MirrorSrc, settings.MirrorDst):
		return switchSettings{}, fmt.Errorf("`mirror_destination_port` %d must not also appear in `mirror_source_ports`", settings.MirrorDst)
	}

	return settings, nil
}

// flattenSwitchSettings renders the verified device settings as resource
// state. An unknown device QoS mode is a hard error: storing it would
// silently corrupt later diffs.
func flattenSwitchSettings(ctx context.Context, settings switchSettings, id types.String) (switchSettingsResourceModel, error) {
	mode, err := switchQoSModeToString(settings.QoSMode)
	if err != nil {
		return switchSettingsResourceModel{}, err
	}

	srcPorts := make([]attr.Value, 0, len(settings.MirrorSrc))
	for _, port := range settings.MirrorSrc {
		srcPorts = append(srcPorts, types.Int64Value(int64(port)))
	}

	return switchSettingsResourceModel{
		ID:                    id,
		QoSMode:               types.StringValue(mode),
		BlockUnknownMulticast: types.BoolValue(settings.BlockUnknownMulticast),
		MirrorDestinationPort: types.Int64Value(int64(settings.MirrorDst)),
		MirrorSourcePorts:     types.SetValueMust(types.Int64Type, srcPorts),
	}, nil
}

// readSwitchSettings GETs the three global settings blocks and decodes
// them. A block reply that carries none of its typed values is a read
// error, never a guess.
func readSwitchSettings(c nsdpClient) (switchSettings, error) {
	qosAttrs, err := c.GetBlock(nsdpBlockQoSMode, nil)
	if err != nil {
		return switchSettings{}, fmt.Errorf("read QoS mode block 0x3400: %w", err)
	}
	multicastAttrs, err := c.GetBlock(nsdpBlockUnknownMulticast, nil)
	if err != nil {
		return switchSettings{}, fmt.Errorf("read unknown-multicast block 0x6c00: %w", err)
	}
	mirrorAttrs, err := c.GetBlock(nsdpBlockPortMirroring, nil)
	if err != nil {
		return switchSettings{}, fmt.Errorf("read port mirroring block 0x5c00: %w", err)
	}

	var mode *nsdp.QoSMode
	for _, a := range qosAttrs {
		if decoded, ok := a.Decoded.(nsdp.QoSMode); ok {
			mode = &decoded
			break
		}
	}
	if mode == nil {
		return switchSettings{}, fmt.Errorf("QoS mode block 0x3400 reply carried no 1-byte mode value")
	}

	var blocked *bool
	for _, a := range multicastAttrs {
		if decoded, ok := a.Decoded.(byte); ok {
			value := decoded != 0
			blocked = &value
			break
		}
	}
	if blocked == nil {
		return switchSettings{}, fmt.Errorf("unknown-multicast block 0x6c00 reply carried no 1-byte boolean value")
	}

	var mirror *nsdp.PortMirrorConfig
	for _, a := range mirrorAttrs {
		if decoded, ok := a.Decoded.(nsdp.PortMirrorConfig); ok {
			mirror = &decoded
			break
		}
	}
	if mirror == nil {
		return switchSettings{}, fmt.Errorf("port mirroring block 0x5c00 reply carried no 3-byte mirror config")
	}

	return switchSettings{
		QoSMode:               *mode,
		BlockUnknownMulticast: *blocked,
		MirrorDst:             int(mirror.DstPort),
		MirrorSrc:             portsFromBitmap(mirror.SrcPorts),
	}, nil
}

// portsFromBitmap decodes a port bitmap (bit 0x80 = port 1 … 0x01 = port
// 8, matching nsdp.PortBitmap) into the sorted port list.
func portsFromBitmap(bitmap byte) []int {
	var ports []int
	for port := 1; port <= portConfigPortCount; port++ {
		if bitmap&(1<<(8-port)) != 0 {
			ports = append(ports, port)
		}
	}
	return ports
}

// switchSettingsChanges computes the minimal SET plan. The mirror SET is
// one atomic change covering destination and sources together.
func switchSettingsChanges(desired, actual switchSettings) switchSettingsChange {
	var change switchSettingsChange
	if desired.QoSMode != actual.QoSMode {
		change.NeedQoSMode = true
		change.QoSMode = desired.QoSMode
	}
	if desired.BlockUnknownMulticast != actual.BlockUnknownMulticast {
		change.NeedBlockUnknown = true
		change.BlockUnknown = desired.BlockUnknownMulticast
	}
	if desired.MirrorDst != actual.MirrorDst || !slices.Equal(desired.MirrorSrc, actual.MirrorSrc) {
		change.NeedMirror = true
		change.MirrorDst = desired.MirrorDst
		change.MirrorSrc = desired.MirrorSrc
	}
	return change
}

// applySwitchSettingsChanges sends the changed settings' SETs in a fixed
// order. On ErrNoReply the SET is never re-sent — a warning is recorded
// and the verify GET (read is truth) settles the question later.
func applySwitchSettingsChanges(c nsdpClient, change switchSettingsChange, diags *diag.Diagnostics) error {
	if change.NeedQoSMode {
		if err := c.SetQoSMode(change.QoSMode); err != nil {
			if !errors.Is(err, nsdp.ErrNoReply) {
				return fmt.Errorf("set QoS mode: %w", err)
			}
			diags.AddWarning(
				"SET reply lost",
				"The switch did not answer the QoS mode SET. The write may still have applied; continuing to verification (device read is truth).",
			)
		}
	}
	if change.NeedBlockUnknown {
		if err := c.SetBlockUnknownMulticast(change.BlockUnknown); err != nil {
			if !errors.Is(err, nsdp.ErrNoReply) {
				return fmt.Errorf("set block-unknown-multicast: %w", err)
			}
			diags.AddWarning(
				"SET reply lost",
				"The switch did not answer the block-unknown-multicast SET. The write may still have applied; continuing to verification (device read is truth).",
			)
		}
	}
	if change.NeedMirror {
		if err := c.SetPortMirroring(change.MirrorDst, change.MirrorSrc); err != nil {
			if !errors.Is(err, nsdp.ErrNoReply) {
				return fmt.Errorf("set port mirroring: %w", err)
			}
			diags.AddWarning(
				"SET reply lost",
				fmt.Sprintf("The switch did not answer the port mirroring SET (destination %d). The write may still have applied; continuing to verification (device read is truth).", change.MirrorDst),
			)
		}
	}
	return nil
}

// describeSwitchSettingsDrift renders the remaining per-field drift,
// house describer style: "qos_mode=port-based (wanted 802.1p)".
func describeSwitchSettingsDrift(desired, actual switchSettings) string {
	var fields []string
	if desired.QoSMode != actual.QoSMode {
		fields = append(fields, fmt.Sprintf("qos_mode=%s (wanted %s)", actual.QoSMode.String(), desired.QoSMode.String()))
	}
	if desired.BlockUnknownMulticast != actual.BlockUnknownMulticast {
		fields = append(fields, fmt.Sprintf("block_unknown_multicast=%t (wanted %t)", actual.BlockUnknownMulticast, desired.BlockUnknownMulticast))
	}
	if desired.MirrorDst != actual.MirrorDst {
		fields = append(fields, fmt.Sprintf("mirror_destination_port=%d (wanted %d)", actual.MirrorDst, desired.MirrorDst))
	}
	if !slices.Equal(desired.MirrorSrc, actual.MirrorSrc) {
		fields = append(fields, fmt.Sprintf("mirror_source_ports=%s (wanted %s)", formatIntList(actual.MirrorSrc), formatIntList(desired.MirrorSrc)))
	}
	if len(fields) == 0 {
		return "device readback differed from plan"
	}
	return strings.Join(fields, "; ")
}

// switchQoSModeFromString maps the config vocabulary to the wire enum
// (1=port-based, 2=802.1p; factory 1).
func switchQoSModeFromString(value string) (nsdp.QoSMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "port-based":
		return nsdp.QoSModePortBased, nil
	case "802.1p":
		return nsdp.QoSMode8021p, nil
	}
	return 0, fmt.Errorf("invalid `qos_mode` %q: want one of %s", value, strings.Join(switchSettingsQoSModes, ", "))
}

func switchQoSModeToString(mode nsdp.QoSMode) (string, error) {
	switch mode {
	case nsdp.QoSModePortBased:
		return "port-based", nil
	case nsdp.QoSMode8021p:
		return "802.1p", nil
	}
	return "", fmt.Errorf("switch reported unknown QoS mode %d", byte(mode))
}
