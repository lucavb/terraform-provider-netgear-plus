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
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

type vlanStateResource struct {
	data *providerData
}

type vlanStateResourceModel struct {
	ID                   types.String         `tfsdk:"id"`
	ExpectedSerialNumber types.String         `tfsdk:"expected_serial_number"`
	AllowVLANDeletions   types.Bool           `tfsdk:"allow_vlan_deletions"`
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

	if err := withDriverForHost(ctx, r.data, func(driver client.Driver) error {
		facts, err := driver.ReadSwitchFacts(ctx)
		if err != nil {
			return operationError("Read switch facts failed", err)
		}

		if err := assertExpectedSerialNumber(current.ExpectedSerialNumber, facts.SerialNumber); err != nil {
			return operationError("Switch identity check failed", err)
		}

		state, err := driver.ReadVLANState(ctx)
		if err != nil {
			return operationError("Read VLAN state failed", err)
		}

		vlans, pvids, err := flattenVLANState(ctx, state)
		if err != nil {
			return operationError("Flatten VLAN state failed", err)
		}

		readState := vlanStateResourceModel{
			ID:                   types.StringValue(facts.ResourceID()),
			ExpectedSerialNumber: current.ExpectedSerialNumber,
			AllowVLANDeletions:   current.AllowVLANDeletions,
			VLANs:                vlans,
			PVIDs:                pvids,
		}

		resp.Diagnostics.Append(resp.State.Set(ctx, &readState)...)
		return nil
	}); err != nil {
		addDriverError(&resp.Diagnostics, err)
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

	desired, err := expandVLANState(ctx, 8, plan.VLANs, plan.PVIDs)
	if err != nil {
		diags.AddError("Expand plan failed", err.Error())
		return
	}

	if err := desired.Validate(); err != nil {
		diags.AddError("Invalid VLAN state", err.Error())
		return
	}

	if err := withDriverForHost(ctx, r.data, func(driver client.Driver) error {
		facts, err := driver.ReadSwitchFacts(ctx)
		if err != nil {
			return operationError("Read switch facts failed", err)
		}

		if err := requireExpectedSerialNumber(plan.ExpectedSerialNumber); err != nil {
			return operationError("Missing switch identity pin", err)
		}
		if err := assertExpectedSerialNumber(plan.ExpectedSerialNumber, facts.SerialNumber); err != nil {
			return operationError("Switch identity check failed", err)
		}

		current, err := driver.ReadVLANState(ctx)
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

		if err := driver.ApplyVLANState(ctx, desired); err != nil {
			return operationError("Apply VLAN state failed", err)
		}

		facts, err = driver.ReadSwitchFacts(ctx)
		if err != nil {
			return operationError("Read switch facts failed", err)
		}

		verified, err := driver.ReadVLANState(ctx)
		if err != nil {
			return operationError("Read back VLAN state failed", err)
		}

		if !verified.Equal(desired) {
			return &providerOperationError{
				summary: "Post-apply verification failed",
				detail:  fmt.Sprintf("switch state did not converge to the requested configuration for %s: %s", facts.ResourceID(), describeStateDrift(verified, desired)),
			}
		}

		vlans, pvids, err := flattenVLANState(ctx, verified)
		if err != nil {
			return operationError("Flatten verified VLAN state failed", err)
		}

		nextState := vlanStateResourceModel{
			ID:                   types.StringValue(facts.ResourceID()),
			ExpectedSerialNumber: plan.ExpectedSerialNumber,
			AllowVLANDeletions:   normalizedBool(plan.AllowVLANDeletions),
			VLANs:                vlans,
			PVIDs:                pvids,
		}

		diags.Append(target.Set(ctx, &nextState)...)
		return nil
	}); err != nil {
		addDriverError(diags, err)
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
