package provider

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// vlanEngineModePortBased is the only mode in which the port-based VLAN
// table is the live grouping mechanism (GS108Ev3 wire values: 1
// port-based, 2 id-based, 3 802.1q port-based, 4 802.1q extended). There
// are deliberately no other constants here: this resource refuses to
// operate in every other mode, so only "is it port-based?" matters.
const vlanEngineModePortBased nsdp.VLANEngineMode = 1

const (
	portBasedVLANIDMin = 1
	portBasedVLANIDMax = 4094
)

type portBasedVLANResource struct {
	data *providerData
}

type portBasedVLANBlockModel struct {
	VLANID types.Int64 `tfsdk:"vlan_id"`
	Ports  types.Set   `tfsdk:"ports"`
}

type portBasedVLANResourceModel struct {
	ID    types.String              `tfsdk:"id"`
	VLANs []portBasedVLANBlockModel `tfsdk:"vlans"`
}

// NewPortBasedVLANResource returns the authoritative port-based VLAN
// table resource.
func NewPortBasedVLANResource() resource.Resource {
	return &portBasedVLANResource{}
}

func (r *portBasedVLANResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_port_based_vlan"
}

func (r *portBasedVLANResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = rschema.Schema{
		Description: "The authoritative port-based VLAN table of the switch, managed over NSDP block 0x2400. Only applies while the VLAN engine is in port-based mode (0x2000 = 1); in any 802.1Q mode this resource refuses to touch the table — manage those VLANs with `netgear_plus_vlan_state` instead. VLANs may overlap (that is how port-based VLANs work); there is no protocol-level VLAN delete, so VLANs present on the device but absent from this resource cause a refusal listing them as unmanaged.",
		Blocks: map[string]rschema.Block{
			"vlans": rschema.ListNestedBlock{
				Description: "One entry per port-based VLAN. Must include every VLAN present on the device.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
				},
				NestedObject: rschema.NestedBlockObject{
					Attributes: map[string]rschema.Attribute{
						"vlan_id": rschema.Int64Attribute{
							Required:    true,
							Description: "Port-based VLAN ID, 1-4094. Must be unique within this resource. The 0x2400 SET is source-confirmed (ProSafeLinux + firmware) but not yet live-proven; a failed write surfaces as a verification drift error.",
							Validators: []validator.Int64{
								int64validator.Between(portBasedVLANIDMin, portBasedVLANIDMax),
							},
						},
						"ports": rschema.SetAttribute{
							Required:    true,
							ElementType: types.Int64Type,
							Description: "Member ports of the VLAN (set of 1-8). May overlap with other VLANs' port sets. Factory default: VLAN 1 contains all ports.",
							Validators: []validator.Set{
								setvalidator.SizeAtLeast(1),
								setvalidator.ValueInt64sAre(int64validator.Between(1, portConfigPortCount)),
							},
						},
					},
				},
			},
		},
		Attributes: map[string]rschema.Attribute{
			"id": rschema.StringAttribute{
				Computed:    true,
				Description: "Stable switch identifier (nsdp@<agent MAC>).",
			},
		},
	}
}

func (r *portBasedVLANResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.data = req.ProviderData.(*providerData)
}

func (r *portBasedVLANResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan portBasedVLANResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *portBasedVLANResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var current portBasedVLANResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &current)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if r.data == nil {
		resp.Diagnostics.AddError("Provider not configured", "Configure the `netgear_plus` provider before reading `netgear_plus_port_based_vlan`.")
		return
	}

	if err := withNSDPClient(ctx, r.data, func(c nsdpClient) error {
		// The guard applies to reads too: in a non-port-based mode the
		// stale table would be surfaced as if it were live config.
		if err := requirePortBasedEngineMode(c); err != nil {
			return err
		}

		table, err := readPortBasedVLANTable(c)
		if err != nil {
			return operationError("Read port-based VLAN table failed", err)
		}

		id := current.ID
		if id.IsNull() || id.IsUnknown() || strings.TrimSpace(id.ValueString()) == "" {
			id = types.StringValue(portConfigResourceID(r.data))
		}

		readState := flattenPortBasedVLANs(ctx, table, id)
		resp.Diagnostics.Append(resp.State.Set(ctx, &readState)...)
		return nil
	}); err != nil {
		addNSDPOperationError(&resp.Diagnostics, err)
	}
}

func (r *portBasedVLANResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan portBasedVLANResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *portBasedVLANResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning(
		"Delete leaves the VLAN table unchanged",
		"Destroying `netgear_plus_port_based_vlan` removes Terraform state only. There is no protocol-level port-based VLAN delete; silently re-grouping ports on destroy would be an unsafe implicit rollback.",
	)
}

func (r *portBasedVLANResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// requirePortBasedEngineMode GETs the VLAN engine mode (0x2000) and
// refuses everything but port-based mode (1). In any other mode the
// port-based table is not the live grouping mechanism — writes could
// corrupt a table the user manages via netgear_plus_vlan_state, so this
// resource touches nothing.
func requirePortBasedEngineMode(c nsdpClient) error {
	attrs, err := c.GetBlock(nsdpBlockVLANEngineMode, nil)
	if err != nil {
		return operationError("VLAN engine mode guard failed", fmt.Errorf("read engine mode block 0x2000: %w", err))
	}

	var mode *nsdp.VLANEngineMode
	for _, a := range attrs {
		if decoded, ok := a.Decoded.(nsdp.VLANEngineMode); ok {
			mode = &decoded
			break
		}
	}
	if mode == nil {
		return operationError("VLAN engine mode guard failed", fmt.Errorf("engine mode block 0x2000 reply carried no mode value"))
	}

	if *mode != vlanEngineModePortBased {
		return &providerOperationError{
			summary: "Refusing to manage the port-based VLAN table",
			detail: fmt.Sprintf(
				"The switch's VLAN engine mode is %d, not port-based (%d). `netgear_plus_port_based_vlan` only applies while the VLAN engine is in port-based mode; in this mode the 802.1Q VLANs are managed by the `netgear_plus_vlan_state` resource. This resource refuses to touch the port-based table and sent no configuration to the switch.",
				byte(*mode), byte(vlanEngineModePortBased),
			),
		}
	}
	return nil
}

// apply is the diff-apply-verify core shared by Create and Update. Every
// write path starts with the engine-mode guard and the unmanaged-VLAN
// refusal — both happen before any SET leaves.
func (r *portBasedVLANResource) apply(ctx context.Context, plan portBasedVLANResourceModel, target *tfsdk.State, diags *diag.Diagnostics) {
	if r.data == nil {
		diags.AddError("Provider not configured", "Configure the `netgear_plus` provider before managing `netgear_plus_port_based_vlan`.")
		return
	}

	desired, err := expandPortBasedVLANs(ctx, plan)
	if err != nil {
		diags.AddError("Invalid port-based VLAN table", err.Error())
		return
	}

	if err := withNSDPClient(ctx, r.data, func(c nsdpClient) error {
		if err := requirePortBasedEngineMode(c); err != nil {
			return err
		}

		actual, err := readPortBasedVLANTable(c)
		if err != nil {
			return operationError("Read port-based VLAN table failed", err)
		}

		// Authoritative-table rule: VLANs on the device that the plan
		// does not mention would silently fall out of management
		// (there is no protocol-level delete). Refuse instead, before
		// any SET is sent.
		if unmanaged := unmanagedVLANs(desired, actual); len(unmanaged) > 0 {
			return &providerOperationError{
				summary: "Refusing to manage a partial port-based VLAN table",
				detail: fmt.Sprintf(
					"The switch has port-based VLANs %s that are not in this resource's `vlans` block. `netgear_plus_port_based_vlan` manages the whole table and NSDP has no port-based VLAN delete, so applying this plan would leave those VLANs unmanaged. Add %s to `vlans` and apply again. No configuration was sent to the switch.",
					formatIntList(unmanaged), formatIntList(unmanaged),
				),
			}
		}

		changes := computePortBasedVLANChanges(desired, actual)
		if changes.isEmpty() {
			diags.AddWarning(
				"Port-based VLAN table already in sync",
				"The switch's port-based VLAN table already matches the requested configuration; no SET operations were sent to the switch.",
			)
		} else if err := applyPortBasedVLANChanges(c, changes, diags); err != nil {
			return operationError("Apply port-based VLAN changes failed", err)
		}

		verified, err := readPortBasedVLANTable(c)
		if err != nil {
			return operationError("Read back port-based VLAN table failed", err)
		}

		// Silent no-ops exist on this firmware: one corrective pass
		// re-SETs whatever the verify GET shows as still wrong.
		if correction := computePortBasedVLANChanges(desired, verified); !correction.isEmpty() {
			if err := applyPortBasedVLANChanges(c, correction, diags); err != nil {
				return operationError("Corrective port-based VLAN pass failed", err)
			}

			verified, err = readPortBasedVLANTable(c)
			if err != nil {
				return operationError("Read back port-based VLAN table failed", err)
			}

			if correction := computePortBasedVLANChanges(desired, verified); !correction.isEmpty() {
				return &providerOperationError{
					summary: "Post-apply verification failed",
					detail: fmt.Sprintf(
						"port-based VLAN table did not converge to the requested configuration for %s: %s",
						portConfigResourceID(r.data),
						describePortBasedVLANDrift(desired, verified),
					),
				}
			}
		}

		nextState := flattenPortBasedVLANs(ctx, verified, types.StringValue(portConfigResourceID(r.data)))
		diags.Append(target.Set(ctx, &nextState)...)
		return nil
	}); err != nil {
		addNSDPOperationError(diags, err)
	}
}

// expandPortBasedVLANs converts the plan model to the desired table,
// enforcing unique vlan_id (overlapping port sets are fine — that is
// how port-based VLANs work).
func expandPortBasedVLANs(ctx context.Context, model portBasedVLANResourceModel) (map[int][]int, error) {
	table := make(map[int][]int, len(model.VLANs))
	for _, block := range model.VLANs {
		if block.VLANID.IsNull() || block.VLANID.IsUnknown() {
			return nil, fmt.Errorf("every `vlans` block needs a `vlan_id`")
		}
		vlanID := int(block.VLANID.ValueInt64())
		if vlanID < portBasedVLANIDMin || vlanID > portBasedVLANIDMax {
			return nil, fmt.Errorf("`vlan_id` %d out of range [%d,%d]", vlanID, portBasedVLANIDMin, portBasedVLANIDMax)
		}
		if _, dup := table[vlanID]; dup {
			return nil, fmt.Errorf("duplicate `vlan_id` %d in `vlans`", vlanID)
		}

		if block.Ports.IsNull() || block.Ports.IsUnknown() {
			return nil, fmt.Errorf("`vlans` block for VLAN %d needs a non-empty `ports` set", vlanID)
		}
		var ports []int64
		if diags := block.Ports.ElementsAs(ctx, &ports, false); diags.HasError() {
			return nil, fmt.Errorf("expand ports for VLAN %d: %s", vlanID, diags.Errors()[0].Detail())
		}
		if len(ports) == 0 {
			return nil, fmt.Errorf("`ports` for VLAN %d must not be empty", vlanID)
		}
		expanded := make([]int, 0, len(ports))
		for _, port := range ports {
			if port < 1 || port > portConfigPortCount {
				return nil, fmt.Errorf("`ports` for VLAN %d contains port %d, out of range [1,%d]", vlanID, port, portConfigPortCount)
			}
			expanded = append(expanded, int(port))
		}
		slices.Sort(expanded)
		expanded = slices.Compact(expanded)
		table[vlanID] = expanded
	}
	return table, nil
}

// flattenPortBasedVLANs renders the verified device table as resource
// state (stable order: VLAN ID ascending).
func flattenPortBasedVLANs(ctx context.Context, table map[int][]int, id types.String) portBasedVLANResourceModel {
	vlans := make([]portBasedVLANBlockModel, 0, len(table))
	for _, vlanID := range slices.Sorted(maps.Keys(table)) {
		ports := make([]attr.Value, 0, len(table[vlanID]))
		for _, port := range table[vlanID] {
			ports = append(ports, types.Int64Value(int64(port)))
		}
		vlans = append(vlans, portBasedVLANBlockModel{
			VLANID: types.Int64Value(int64(vlanID)),
			Ports:  types.SetValueMust(types.Int64Type, ports),
		})
	}
	return portBasedVLANResourceModel{
		ID:    id,
		VLANs: vlans,
	}
}

// readPortBasedVLANTable GETs block 0x2400 and decodes the live shape —
// one Attr per 3-byte TLV, each carrying exactly one VLAN entry.
func readPortBasedVLANTable(c nsdpClient) (map[int][]int, error) {
	attrs, err := c.GetBlock(nsdpBlockPortBasedVLAN, nil)
	if err != nil {
		return nil, fmt.Errorf("read port-based VLAN block 0x2400: %w", err)
	}

	table := make(map[int][]int, len(attrs))
	for _, a := range attrs {
		entries, ok := a.Decoded.([]nsdp.PortBasedVLANEntry)
		if !ok {
			return nil, fmt.Errorf("port-based VLAN block 0x2400 reply carried an unexpected payload shape")
		}
		for _, entry := range entries {
			table[int(entry.VLANID)] = portsFromBitmap(entry.Ports)
		}
	}
	return table, nil
}

// unmanagedVLANs lists device VLANs absent from the plan, ascending.
func unmanagedVLANs(desired, actual map[int][]int) []int {
	var unmanaged []int
	for vlanID := range actual {
		if _, wanted := desired[vlanID]; !wanted {
			unmanaged = append(unmanaged, vlanID)
		}
	}
	slices.Sort(unmanaged)
	return unmanaged
}

// portBasedVLANChange is the minimal SET plan: VLANs whose port sets
// differ (or that are missing from the device) are re-SET wholesale.
type portBasedVLANChange struct {
	VLANID int
	Ports  []int
}

func (ch portBasedVLANChange) String() string {
	return fmt.Sprintf("vlan %d -> ports %v", ch.VLANID, ch.Ports)
}

// portBasedVLANChanges is the SET plan for one apply pass, in ascending
// VLAN order. Device-only VLANs never appear here — the
// unmanaged-VLAN refusal handles them before apply.
type portBasedVLANChanges []portBasedVLANChange

func (changes portBasedVLANChanges) isEmpty() bool {
	return len(changes) == 0
}

// computePortBasedVLANChanges diffs the desired table against the device
// read, producing the minimal SET plan.
func computePortBasedVLANChanges(desired, actual map[int][]int) portBasedVLANChanges {
	var changes portBasedVLANChanges
	for _, vlanID := range slices.Sorted(maps.Keys(desired)) {
		ports, exists := actual[vlanID]
		if !exists || !slices.Equal(ports, desired[vlanID]) {
			changes = append(changes, portBasedVLANChange{VLANID: vlanID, Ports: desired[vlanID]})
		}
	}
	return changes
}

// applyPortBasedVLANChanges sends one 0x2400 SET per changed VLAN, in
// order. On ErrNoReply the SET is never re-sent — a warning is recorded
// and the verify GET (read is truth) settles the question later.
func applyPortBasedVLANChanges(c nsdpClient, changes portBasedVLANChanges, diags *diag.Diagnostics) error {
	for _, change := range changes {
		if err := c.SetPortBasedVLAN(change.VLANID, change.Ports); err != nil {
			if !errors.Is(err, nsdp.ErrNoReply) {
				return fmt.Errorf("set port-based VLAN %d: %w", change.VLANID, err)
			}
			diags.AddWarning(
				"SET reply lost",
				fmt.Sprintf("The switch did not answer the port-based VLAN %d SET. The write may still have applied; continuing to verification (device read is truth).", change.VLANID),
			)
		}
	}
	return nil
}

// describePortBasedVLANDrift renders the remaining per-VLAN drift, house
// describer style.
func describePortBasedVLANDrift(desired, actual map[int][]int) string {
	var fields []string
	for _, vlanID := range slices.Sorted(maps.Keys(desired)) {
		ports, exists := actual[vlanID]
		if !exists {
			fields = append(fields, fmt.Sprintf("vlan %d: missing (wanted ports %s)", vlanID, formatIntList(desired[vlanID])))
			continue
		}
		if !slices.Equal(ports, desired[vlanID]) {
			fields = append(fields, fmt.Sprintf("vlan %d: ports=%s (wanted %s)", vlanID, formatIntList(ports), formatIntList(desired[vlanID])))
		}
	}
	if len(fields) == 0 {
		return "device readback differed from plan"
	}
	return strings.Join(fields, "; ")
}
