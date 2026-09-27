package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/client/gs108tv2"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// detailedVLANStateApplier is the optional seam the gs108tv2 composite
// text-config transport implements to surface the staged-apply outcome
// (see textcfgSwitchTransport.ApplyVLANStateDetailed). The resource
// type-asserts for it: transports WITHOUT it (HTTP, NSDP) keep the
// plain interface call; transports WITH it get their outcome inspected
// for the staged-changes / canonical-divergence warning diagnostics.
type detailedVLANStateApplier interface {
	ApplyVLANStateDetailed(ctx context.Context, desired model.VLANState) (gs108tv2.ApplyOutcome, error)
}

type vlanStateResource struct {
	data *providerData
}

type vlanStateResourceModel struct {
	ID                   types.String         `tfsdk:"id"`
	ExpectedSerialNumber types.String         `tfsdk:"expected_serial_number"`
	AllowVLANDeletions   types.Bool           `tfsdk:"allow_vlan_deletions"`
	RebootToApply        types.Bool           `tfsdk:"reboot_to_apply"`
	ChangesPending       types.Bool           `tfsdk:"changes_pending"`
	VLANs                []vlanAttributeModel `tfsdk:"vlan"`
	PVIDs                types.Map            `tfsdk:"pvids"`
}

// NewVLANStateResource returns the authoritative VLAN state resource.
func NewVLANStateResource() resource.Resource {
	return &vlanStateResource{}
}

func (r *vlanStateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_vlan_state"
}

func (r *vlanStateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = rschema.Schema{
		Attributes: map[string]rschema.Attribute{
			"id": rschema.StringAttribute{
				Computed:    true,
				Description: "Stable switch identifier.",
			},
			"expected_serial_number": rschema.StringAttribute{
				Optional:    true,
				Description: "Expected device serial number. Create and update fail if the connected switch does not match.",
			},
			"allow_vlan_deletions": rschema.BoolAttribute{
				Optional:    true,
				Description: "Allow authoritative removal of VLANs that exist on the switch but are omitted from configuration. Defaults to false for safer live use.",
			},
			"reboot_to_apply": rschema.BoolAttribute{
				// Optional + StaticBool(false) default resolves to a
				// known plan value, so there is no Computed perpetual
				// diff; the framework merely requires the flag for
				// Default attributes.
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "gs108tv2 only. When `true`, every apply that stages changes also reboots the switch after staging and waits for it to come back with the staged startup-config intact — the changes are ACTIVE in the running config when Terraform reports success. When `false` (default), applies STAGE the startup-config without rebooting (gs108tv2 running VLAN state cannot be observed; the changes activate on the switch's own next reboot). WARNING: leaving this true reboots the switch on later unrelated diffs too. On gs108ev3 this option is refused (the ev3 driver applies live).",
				Description:         "gs108tv2 only. When `true`, every apply that stages changes also reboots the switch after staging and waits for it to come back with the staged startup-config intact — the changes are ACTIVE when Terraform reports success. When `false`, gs108tv2 applies stage the startup-config without rebooting. gs108ev3 is refused (its driver applies live). Leaving it true reboots the switch on later unrelated diffs too.",
			},
			"changes_pending": rschema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "gs108tv2: `true` while the last Terraform apply staged changes without a Terraform-driven reboot (the switch still runs its pre-apply config). `false` after a successful rebooting apply, on every no-op apply, and always on gs108ev3. Reads pass the prior value through unchanged: the running state is not observable on gs108tv2 between applies (an out-of-band reboot is not detectable from the startup-config), so the flag clears on the next apply — it reflects 'staged by Terraform and not yet applied by a Terraform-driven reboot', not the live switch state.",
				Description:         "gs108tv2: true while the last Terraform apply staged changes without a Terraform-driven reboot. false after a rebooting apply, on no-op applies, and on gs108ev3. Reads pass the prior value through: running state is unobservable on gs108tv2 between applies, so it clears on the next apply and says nothing about an out-of-band reboot.",
			},
			"pvids": rschema.MapAttribute{
				Required:    true,
				ElementType: types.Int64Type,
				Description: "Complete per-port PVID map for the switch.",
			},
		},
		Blocks: map[string]rschema.Block{
			"vlan": rschema.ListNestedBlock{
				Description: "Complete authoritative VLAN definition for the switch.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
				},
				NestedObject: rschema.NestedBlockObject{
					Attributes: map[string]rschema.Attribute{
						"id": rschema.Int64Attribute{
							Required: true,
						},
						"ports": rschema.MapAttribute{
							Required:    true,
							ElementType: types.StringType,
							Description: "Per-port membership map using `untagged` or `tagged`. Omitted ports are normalized to `ignored`.",
						},
					},
				},
			},
		},
	}
}

func (r *vlanStateResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.data = req.ProviderData.(*providerData)
}

func (r *vlanStateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan vlanStateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *vlanStateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var current vlanStateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &current)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if r.data == nil {
		resp.Diagnostics.AddError("Provider not configured", "Configure the `netgear_plus` provider before reading `netgear_plus_vlan_state`.")
		return
	}

	if err := withSwitchTransport(ctx, r.data, func(transport switchTransport) error {
		facts, err := transport.ReadSwitchFacts(ctx)
		if err != nil {
			return operationError("Read switch facts failed", err)
		}

		if err := assertExpectedSerialNumber(current.ExpectedSerialNumber, facts.SerialNumber); err != nil {
			return operationError("Switch identity check failed", err)
		}

		state, err := transport.ReadVLANState(ctx)
		if err != nil {
			return operationError("Read VLAN state failed", err)
		}

		vlans, pvids, err := flattenVLANState(ctx, state)
		if err != nil {
			return operationError("Flatten VLAN state failed", err)
		}

		// The state ID follows the transport's identity convention
		// (gs108ev3@<host> over HTTP, nsdp@<agent MAC> over NSDP) —
		// switching transports changes the ID; users must re-import
		// rather than destroy/recreate. See switchTransport.ResourceID.
		//
		// changes_pending passes through UNCHANGED on Read: running
		// VLAN state is unobservable on gs108tv2 between applies (an
		// out-of-band reboot is not detectable from the startup-config),
		// so the flag only clears on the next apply.
		readState := vlanStateResourceModel{
			ID:                   types.StringValue(transport.ResourceID()),
			ExpectedSerialNumber: current.ExpectedSerialNumber,
			AllowVLANDeletions:   current.AllowVLANDeletions,
			RebootToApply:        current.RebootToApply,
			ChangesPending:       current.ChangesPending,
			VLANs:                vlans,
			PVIDs:                pvids,
		}

		resp.Diagnostics.Append(resp.State.Set(ctx, &readState)...)
		return nil
	}); err != nil {
		addNSDPOperationError(&resp.Diagnostics, err)
	}
}

func (r *vlanStateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan vlanStateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.apply(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *vlanStateResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning(
		"Delete leaves switch configuration unchanged",
		"Destroying `netgear_plus_vlan_state` removes Terraform state only. The existing switch VLAN configuration is preserved to avoid unsafe implicit rollback on GS108Ev3.",
	)
}

func (r *vlanStateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *vlanStateResource) apply(ctx context.Context, plan vlanStateResourceModel, target *tfsdk.State, diags *diag.Diagnostics) {
	if r.data == nil {
		diags.AddError("Provider not configured", "Configure the `netgear_plus` provider before managing `netgear_plus_vlan_state`.")
		return
	}

	// gs108tv2 SERIAL-PIN SAFETY RAIL (fail-closed, before any
	// staging): the text-config channel rewrites the WHOLE
	// startup-config file, and that channel cannot read the serial
	// number at all — only NSDP v1 identity carries it. Without
	// agent_mac the expected_serial_number pin cannot be enforced, so
	// the whole apply refuses up front instead of staging against an
	// unpinned target.
	if err := requireGS108Tv2SerialPin(r.data); err != nil {
		addNSDPOperationError(diags, err)
		return
	}

	// reboot_to_apply preflight (still zero transport work: the
	// endpooint sentinel is judged before anything reaches the switch —
	// staging never happens when the reboot cannot be honored).
	if err := preflightRebootToApply(r.data, plan.RebootToApply); err != nil {
		addNSDPOperationError(diags, err)
		return
	}

	desired, err := expandVLANState(ctx, 8, plan.VLANs, plan.PVIDs)
	if err != nil {
		diags.AddError("Expand plan failed", err.Error())
		return
	}

	if err := desired.Validate(); err != nil {
		diags.AddError("Invalid VLAN state", err.Error())
		return
	}

	if err := withSwitchTransport(ctx, r.data, func(transport switchTransport) error {
		facts, err := transport.ReadSwitchFacts(ctx)
		if err != nil {
			return operationError("Read switch facts failed", err)
		}

		if err := requireExpectedSerialNumber(plan.ExpectedSerialNumber); err != nil {
			return operationError("Missing switch identity pin", err)
		}
		if err := assertExpectedSerialNumber(plan.ExpectedSerialNumber, facts.SerialNumber); err != nil {
			return operationError("Switch identity check failed", err)
		}

		current, err := transport.ReadVLANState(ctx)
		if err != nil {
			return operationError("Read current VLAN state failed", err)
		}

		removed := blockedVLANRemovals(current, desired, plan.AllowVLANDeletions)
		if len(removed) > 0 {
			return &providerOperationError{
				summary: "Authoritative VLAN deletions are disabled",
				detail:  fmt.Sprintf("The plan would remove VLANs %s from the switch. Set `allow_vlan_deletions = true` only after validating delete behavior on the target device.", formatIntList(removed)),
			}
		}

		// The apply: when the transport implements the gs108tv2
		// detailed-applier seam, use it — the plain interface method
		// would run the same staged apply a second time — and keep
		// the outcome for the staged-changes warnings below.
		var outcome gs108tv2.ApplyOutcome
		onTextConfig := false
		if detailed, ok := transport.(detailedVLANStateApplier); ok {
			onTextConfig = true
			var err error
			outcome, err = detailed.ApplyVLANStateDetailed(ctx, desired)
			if err != nil {
				return operationError("Apply VLAN state failed", err)
			}
		} else if err := transport.ApplyVLANState(ctx, desired); err != nil {
			return operationError("Apply VLAN state failed", err)
		}

		facts, err = transport.ReadSwitchFacts(ctx)
		if err != nil {
			return operationError("Read switch facts failed", err)
		}

		verified, err := transport.ReadVLANState(ctx)
		if err != nil {
			return operationError("Read back VLAN state failed", err)
		}

		if !verified.Equal(desired) {
			return &providerOperationError{
				summary: "Post-apply verification failed",
				detail:  fmt.Sprintf("switch state did not converge to the requested configuration for %s: %s", transport.ResourceID(), describeStateDrift(verified, desired)),
			}
		}

		// changes_pending + reboot_to_apply (gs108tv2 text-config path
		// only): the staged flow did NOT reboot, so the changes are
		// pending until either Terraform reboots (option) or the switch
		// reboots on its own. A no-op apply (current==desired) leaves
		// nothing pending and does not reboot even when asked.
		//
		// RECOVERY SHAPE after a failed reboot: the resource state is
		// NOT written (this error path returns before target.Set) — the
		// provider keeps seeing stale state, and the NEXT apply sends
		// only the driver's apply short-circuit (the startup-config
		// already decodes Equal to the desired state, zero restore
		// POSTs) followed by RebootAndWait again. The reboot is the
		// only retried side effect.
		changesPending := false
		if onTextConfig {
			changesPending = !current.Equal(desired)
			if changesPending && rebootToApplyEnabled(plan.RebootToApply) {
				if _, err := transport.(textcfgRebooter).Reboot(ctx); err != nil {
					return operationError("gs108tv2: reboot for apply failed", err)
				}
				// Success: the change is ACTIVE, not pending.
				changesPending = false
			}
		}

		vlans, pvids, err := flattenVLANState(ctx, verified)
		if err != nil {
			return operationError("Flatten verified VLAN state failed", err)
		}

		nextState := vlanStateResourceModel{
			ID:                   types.StringValue(transport.ResourceID()),
			ExpectedSerialNumber: plan.ExpectedSerialNumber,
			AllowVLANDeletions:   normalizedBool(plan.AllowVLANDeletions),
			RebootToApply:        normalizedBool(plan.RebootToApply),
			ChangesPending:       types.BoolValue(changesPending),
			VLANs:                vlans,
			PVIDs:                pvids,
		}

		diags.Append(target.Set(ctx, &nextState)...)

		// gs108tv2 staged semantics (milestone 3): warnings only when
		// the change is still pending — HTTP and NSDP applies on
		// gs108ev3 are live and stay warning-free.
		addGS108Tv2StagedWarnings(diags, outcome, "VLAN changes", changesPending)

		return nil
	}); err != nil {
		addNSDPOperationError(diags, err)
	}
}

// requireGS108Tv2SerialPin is the gs108tv2 fail-closed safety rail for
// vlan_state Create/Update: without agent_mac the whole apply refuses
// BEFORE the transport is even built — the text-config channel
// rewrites the entire startup-config file, and it cannot read the
// serial number (only NSDP v1 identity carries it), so the
// expected_serial_number pin cannot be enforced.
func requireGS108Tv2SerialPin(data *providerData) error {
	if data == nil || !data.isGS108Tv2Model() || data.agentMAC != "" {
		return nil
	}

	return &providerOperationError{
		summary: fmt.Sprintf("Model %s requires agent_mac before managing VLAN state", client.ModelGS108Tv2),
		detail: fmt.Sprintf(
			"Managing VLAN state on model %s stages a startup-config restore that REWRITES THE WHOLE CONFIGURATION FILE — it must not land on the wrong switch. The expected_serial_number pin of `netgear_plus_vlan_state` can only be checked against the serial number, which this model's text-config channel cannot read: the serial is carried only by the legacy NSDP v1 identity. Set the provider attribute agent_mac (the switch's MAC, colon-separated form — the config backup itself carries it in the `spanning-tree configuration name` line, see `netgear_plus_switch_config`); with `host` also set, NSDP rides unicast to that same L3 address, so one address serves both transports.",
			client.ModelGS108Tv2,
		),
	}
}

func requireExpectedSerialNumber(value types.String) error {
	if value.IsNull() || value.IsUnknown() || strings.TrimSpace(value.ValueString()) == "" {
		return fmt.Errorf("set `expected_serial_number` on the resource before applying changes to a live switch")
	}

	return nil
}

func assertExpectedSerialNumber(expected types.String, actual string) error {
	if expected.IsNull() || expected.IsUnknown() {
		return nil
	}

	want := strings.TrimSpace(expected.ValueString())
	if want == "" {
		return nil
	}
	if actual == want {
		return nil
	}

	return fmt.Errorf("connected switch serial number is %q, expected %q", actual, want)
}

func blockedVLANRemovals(current, desired model.VLANState, allow types.Bool) []int {
	if !allow.IsNull() && !allow.IsUnknown() && allow.ValueBool() {
		return nil
	}

	return model.RemovedVLANs(current, desired)
}

func normalizedBool(value types.Bool) types.Bool {
	if value.IsNull() || value.IsUnknown() {
		return types.BoolValue(false)
	}

	return value
}

func describeStateDrift(actual, desired model.VLANState) string {
	actual = actual.Normalize()
	desired = desired.Normalize()

	var parts []string

	if missing := model.RemovedVLANs(desired, actual); len(missing) > 0 {
		parts = append(parts, fmt.Sprintf("missing VLANs %s", formatIntList(missing)))
	}
	if extra := model.RemovedVLANs(actual, desired); len(extra) > 0 {
		parts = append(parts, fmt.Sprintf("unexpected VLANs %s", formatIntList(extra)))
	}

	var pvidMismatches []string
	for _, port := range desired.SortedPorts() {
		if actual.PVIDs[port] != desired.PVIDs[port] {
			pvidMismatches = append(pvidMismatches, fmt.Sprintf("port %d=%d (wanted %d)", port, actual.PVIDs[port], desired.PVIDs[port]))
		}
	}
	if len(pvidMismatches) > 0 {
		parts = append(parts, "pvid mismatches "+strings.Join(pvidMismatches, ", "))
	}

	for _, vid := range desired.VLANIDs() {
		actualVLAN, ok := actual.VLANs[vid]
		if !ok {
			continue
		}

		var portDiffs []string
		for _, port := range desired.SortedPorts() {
			if actualVLAN.Ports[port] != desired.VLANs[vid].Ports[port] {
				portDiffs = append(portDiffs, fmt.Sprintf("port %d=%s (wanted %s)", port, actualVLAN.Ports[port], desired.VLANs[vid].Ports[port]))
			}
		}
		if len(portDiffs) > 0 {
			parts = append(parts, fmt.Sprintf("vlan %d membership differs: %s", vid, strings.Join(portDiffs, ", ")))
		}
	}

	if len(parts) == 0 {
		return "device readback differed from plan"
	}

	return strings.Join(parts, "; ")
}

func formatIntList(values []int) string {
	if len(values) == 0 {
		return "[]"
	}

	sorted := slices.Clone(values)
	slices.Sort(sorted)

	parts := make([]string, 0, len(sorted))
	for _, value := range sorted {
		parts = append(parts, fmt.Sprintf("%d", value))
	}

	return "[" + strings.Join(parts, ", ") + "]"
}
