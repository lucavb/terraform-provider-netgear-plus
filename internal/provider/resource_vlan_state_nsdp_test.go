package provider

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	tftypes "github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// ---------------------------------------------------------------------------
// Direct-drive helpers for the vlan_state resource family over the NSDP
// transport (mirroring the port_config patterns; the resource CRUD
// requests carry no ProviderData, so r.data is set directly).
// ---------------------------------------------------------------------------

func vlanStateSchema(t *testing.T) rschema.Schema {
	t.Helper()

	var resp resource.SchemaResponse
	(&vlanStateResource{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if diags := resp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatalf("schema validation returned errors: %v", diags)
	}
	return resp.Schema
}

func vlanStateRawValue(t *testing.T, schema rschema.Schema, model vlanStateResourceModel) tftypes.Value {
	t.Helper()

	var value attr.Value
	if diags := tfsdk.ValueFrom(context.Background(), model, schema.Type(), &value); diags.HasError() {
		t.Fatalf("tfsdk.ValueFrom(model) failed: %v", diags)
	}
	raw, err := value.ToTerraformValue(context.Background())
	if err != nil {
		t.Fatalf("ToTerraformValue() error = %v", err)
	}
	return raw
}

func vlanStateTestPlan(t *testing.T, model vlanStateResourceModel) tfsdk.Plan {
	t.Helper()

	schema := vlanStateSchema(t)
	return tfsdk.Plan{Raw: vlanStateRawValue(t, schema, model), Schema: schema}
}

func vlanStateTestState(t *testing.T, model vlanStateResourceModel) tfsdk.State {
	t.Helper()

	schema := vlanStateSchema(t)
	return tfsdk.State{Raw: vlanStateRawValue(t, schema, model), Schema: schema}
}

func stateVLANStateModel(t *testing.T, state tfsdk.State) vlanStateResourceModel {
	t.Helper()

	var model vlanStateResourceModel
	if diags := state.Get(context.Background(), &model); diags.HasError() {
		t.Fatalf("reading state into model failed: %v", diags)
	}
	return model
}

// vlanStateBlocks builds the vlan blocks: id → port → membership
// ("untagged"/"tagged"; ports omitted from the inner map are ignored).
func vlanStateBlocks(table map[int]map[string]string) []vlanAttributeModel {
	blocks := make([]vlanAttributeModel, 0, len(table))
	for vid, ports := range table {
		values := make(map[string]attr.Value, len(ports))
		for port, membership := range ports {
			values[port] = types.StringValue(membership)
		}
		blocks = append(blocks, vlanAttributeModel{
			ID:    types.Int64Value(int64(vid)),
			Ports: types.MapValueMust(types.StringType, values),
		})
	}
	return blocks
}

func vlanStatePVIDs(pvids map[string]int64) types.Map {
	values := make(map[string]attr.Value, len(pvids))
	for port, pvid := range pvids {
		values[port] = types.Int64Value(pvid)
	}
	return types.MapValueMust(types.Int64Type, values)
}

// nsdpVLANStatePlan builds a complete plan model: VLAN 1 untagged on the
// always-safe ports, VLAN 10 untagged on 3/4, PVIDs to match. Every port
// is an active member of its PVID VLAN, as the resource's Validate
// requires.
func nsdpVLANStatePlan() vlanStateResourceModel {
	return vlanStateResourceModel{
		ID:                   types.StringNull(),
		ExpectedSerialNumber: types.StringValue("UH77B5R033EE"),
		AllowVLANDeletions:   types.BoolNull(),
		VLANs: vlanStateBlocks(map[int]map[string]string{
			1:  {"1": "untagged", "2": "untagged", "5": "untagged", "6": "untagged", "7": "untagged", "8": "untagged"},
			10: {"3": "untagged", "4": "untagged"},
		}),
		PVIDs: vlanStatePVIDs(map[string]int64{
			"1": 1, "2": 1, "3": 10, "4": 10, "5": 1, "6": 1, "7": 1, "8": 1,
		}),
	}
}

func createVLANState(t *testing.T, data *providerData, model vlanStateResourceModel) resource.CreateResponse {
	t.Helper()

	r := &vlanStateResource{}
	r.data = data
	plan := vlanStateTestPlan(t, model)
	req := resource.CreateRequest{Plan: plan}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: plan.Schema}}
	r.Create(context.Background(), req, &resp)
	return resp
}

func updateVLANState(t *testing.T, data *providerData, model vlanStateResourceModel, prior vlanStateResourceModel) resource.UpdateResponse {
	t.Helper()

	r := &vlanStateResource{}
	r.data = data
	plan := vlanStateTestPlan(t, model)
	req := resource.UpdateRequest{
		Config: tfsdk.Config{Raw: plan.Raw, Schema: plan.Schema},
		Plan:   plan,
		State:  vlanStateTestState(t, prior),
	}
	resp := resource.UpdateResponse{State: tfsdk.State{Schema: plan.Schema}}
	r.Update(context.Background(), req, &resp)
	return resp
}

// newNSDPVLANStateFake returns a fake switch prepared for the 802.1Q
// path: engine mode 3, factory 802.1Q table (VLAN 1 untagged everywhere,
// PVID 1 per port).
func newNSDPVLANStateFake() *fakeSwitch {
	fake := newFakeSwitch()
	fake.engineMode = 3
	return fake
}

// ---------------------------------------------------------------------------
// Resource-level: vlan_state over NSDP
// ---------------------------------------------------------------------------

func TestVLANStateNSDPCreateAppliesAndVerifies(t *testing.T) {
	t.Parallel()

	fake := newNSDPVLANStateFake()
	data := newNSDPSelectedTestData(fake)

	resp := createVLANState(t, data, nsdpVLANStatePlan())
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create over NSDP failed: %v", resp.Diagnostics)
	}

	// The HTTP driver's exact op order, mapped to NSDP primitives:
	// step1 (widen memberships: VLAN 1 merged all-untagged; VLAN 10 is
	// ADDED, so it exists in step1 only with its desired membership),
	// one SetPVID per port over the full desired PVID batch map, step2
	// (exact desired membership for COMMON VLANs only — VLAN 1), no
	// deletes.
	want := []string{
		"Set8021QVLAN(vlan=1, tagged=[], untagged=[1 2 3 4 5 6 7 8])",
		"Set8021QVLAN(vlan=10, tagged=[], untagged=[3 4])",
		"SetPVID(port=1, vlan=1)",
		"SetPVID(port=2, vlan=1)",
		"SetPVID(port=5, vlan=1)",
		"SetPVID(port=6, vlan=1)",
		"SetPVID(port=7, vlan=1)",
		"SetPVID(port=8, vlan=1)",
		"SetPVID(port=3, vlan=10)",
		"SetPVID(port=4, vlan=10)",
		"Set8021QVLAN(vlan=1, tagged=[], untagged=[1 2 5 6 7 8])",
	}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want the HTTP-mirrored sequence %v", got, want)
	}

	// The state carries the NSDP resource ID convention and the
	// verified VLAN table.
	state := stateVLANStateModel(t, resp.State)
	if got, want := state.ID.ValueString(), "nsdp@8c:3b:ad:25:1b:88"; got != want {
		t.Fatalf("state ID = %q, want %q", got, want)
	}
	if len(state.VLANs) != 2 {
		t.Fatalf("state should carry VLANs 1 and 10, got %+v", state.VLANs)
	}
}

func TestVLANStateNSDPConvergenceSendsNoSets(t *testing.T) {
	t.Parallel()

	fake := newNSDPVLANStateFake()
	data := newNSDPSelectedTestData(fake)

	first := createVLANState(t, data, nsdpVLANStatePlan())
	if first.Diagnostics.HasError() {
		t.Fatalf("Create over NSDP failed: %v", first.Diagnostics)
	}
	callsAfterCreate := len(fake.calls)

	// A second identical apply is a no-op: ApplyVLANState's
	// equal-short-circuit fires before any SET.
	second := updateVLANState(t, data, nsdpVLANStatePlan(), stateVLANStateModel(t, first.State))
	if second.Diagnostics.HasError() {
		t.Fatalf("convergence apply failed: %v", second.Diagnostics)
	}
	if len(fake.calls) != callsAfterCreate {
		t.Fatalf("convergence apply sent new SETs: %v", fake.callStrings()[callsAfterCreate:])
	}
}

func TestVLANStateNSDPDeletionGuardStaysResourceLayered(t *testing.T) {
	t.Parallel()

	fake := newNSDPVLANStateFake()
	fake.vlan8021Q = append(fake.vlan8021Q, nsdp.VLAN8021QMembership{
		VLANID: 999, Untagged: nsdp.PortBitmap([]int{5}),
	})
	data := newNSDPSelectedTestData(fake)

	// allow_vlan_deletions unset: the resource layer refuses BEFORE the
	// transport sees a write (semantics unchanged from the HTTP path).
	resp := createVLANState(t, data, nsdpVLANStatePlan())
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create must refuse to delete an unmanaged VLAN by default")
	}
	text := diagnosticsDetailText(resp.Diagnostics)
	if !strings.Contains(text, "Authoritative VLAN deletions are disabled") || !strings.Contains(text, "999") {
		t.Fatalf("refusal should name the deletion guard and VLAN 999, got: %q", text)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("refused Create must send zero SETs, got %v", fake.callStrings())
	}

	// allow_vlan_deletions = true: the transport deletes the removed
	// VLAN (it never re-decides — the resource already permitted it).
	plan := nsdpVLANStatePlan()
	plan.AllowVLANDeletions = types.BoolValue(true)
	resp = createVLANState(t, data, plan)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create with allow_vlan_deletions failed: %v", resp.Diagnostics)
	}
	calls := fake.callStrings()
	if !containsString(calls, "Delete8021QVLAN(vlan=999)") {
		t.Fatalf("permitted delete must reach Delete8021QVLAN(999), calls = %v", calls)
	}
	// Removed VLANs are pre-cleared to all-ignored before the delete.
	if !containsString(calls, "Set8021QVLAN(vlan=999, tagged=[], untagged=[])") {
		t.Fatalf("delete flow must pre-clear VLAN 999 to all-ignored, calls = %v", calls)
	}
}

func TestVLANStateNSDPEngineModeRefusal(t *testing.T) {
	t.Parallel()

	fake := newNSDPVLANStateFake()
	fake.engineMode = 1 // port-based: the 802.1Q NSDP path must refuse
	data := newNSDPSelectedTestData(fake)

	resp := createVLANState(t, data, nsdpVLANStatePlan())
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create must refuse in port-based engine mode")
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{"Refusing to manage 802.1Q VLAN state over NSDP", "netgear_plus_port_based_vlan", "engine mode is 1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("engine-mode refusal should mention %q, got: %q", want, text)
		}
	}
	if len(fake.calls) != 0 {
		t.Fatalf("refusal must send zero SETs, got %v", fake.callStrings())
	}
}

// TestVLANStateNSDPMembershipDropFailsVerification pins the
// verify-corrective safety contract against the REAL firmware behavior
// observed on the casalta GS108Ev3 (ROUND 19, 2026-09-12): a 0x2800 SET
// whose tagged bits are not a subset of its member bits is silently
// dropped — reply OK, VLAN stored with EMPTY membership. With the
// fake's Reply8021QMembershipDropped knob replaying that drop, the
// apply still writes the desired membership but the verify read
// reports the empty one — the apply must surface a typed
// verification/drift error, NEVER silent success.
func TestVLANStateNSDPMembershipDropFailsVerification(t *testing.T) {
	t.Parallel()

	fake := newNSDPVLANStateFake()
	fake.Reply8021QMembershipDropped = true
	data := newNSDPSelectedTestData(fake)

	// VLAN 10 with a tagged member (port 3): the silent drop makes the
	// read-back report VLAN 10 (and VLAN 1) with empty membership.
	plan := nsdpVLANStatePlan()
	plan.VLANs = vlanStateBlocks(map[int]map[string]string{
		1:  {"1": "untagged", "2": "untagged", "4": "untagged", "5": "untagged", "6": "untagged", "7": "untagged", "8": "untagged"},
		10: {"3": "tagged"},
	})
	plan.PVIDs = vlanStatePVIDs(map[string]int64{
		"1": 1, "2": 1, "3": 10, "4": 1, "5": 1, "6": 1, "7": 1, "8": 1,
	})

	resp := createVLANState(t, data, plan)
	if !resp.Diagnostics.HasError() {
		t.Fatal("silently-dropped membership must fail the apply — silent success would mask the firmware's empty-store behavior")
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{"Post-apply verification failed", "vlan 10", "port 3"} {
		if !strings.Contains(text, want) {
			t.Fatalf("membership-drop drift error should mention %q, got: %q", want, text)
		}
	}
}

func TestVLANStateNSDPReadSurfacesLiveState(t *testing.T) {
	t.Parallel()

	fake := newNSDPVLANStateFake()
	fake.vlan8021Q = []nsdp.VLAN8021QMembership{
		{VLANID: 1, Untagged: 0xff},
		{VLANID: 10, Tagged: nsdp.PortBitmap([]int{8}), Untagged: nsdp.PortBitmap([]int{3, 4})},
	}
	fake.pvid[3] = 10
	fake.pvid[4] = 10
	data := newNSDPSelectedTestData(fake)

	r := &vlanStateResource{}
	r.data = data
	req := resource.ReadRequest{State: vlanStateTestState(t, nsdpVLANStatePlan())}
	resp := resource.ReadResponse{State: tfsdk.State{Schema: vlanStateSchema(t)}}
	r.Read(context.Background(), req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read over NSDP failed: %v", resp.Diagnostics)
	}

	state := stateVLANStateModel(t, resp.State)
	if got, want := state.ID.ValueString(), "nsdp@8c:3b:ad:25:1b:88"; got != want {
		t.Fatalf("Read should preserve/derive the NSDP ID, got %q want %q", got, want)
	}
	if len(state.VLANs) != 2 {
		t.Fatalf("Read should surface the live 2-VLAN table, got %+v", state.VLANs)
	}

	pvids := map[string]int64{}
	if diags := state.PVIDs.ElementsAs(context.Background(), &pvids, false); diags.HasError() {
		t.Fatalf("PVID map decode failed: %v", diags.Errors())
	}
	if got, want := pvids["3"], int64(10); got != want {
		t.Fatalf("port 3 PVID = %d, want live value 10", got)
	}
}

func TestVLANStateNSDPAuthFailureNamesLockout(t *testing.T) {
	t.Parallel()

	fake := newNSDPVLANStateFake()
	fake.AuthFailOnSet = true
	data := newNSDPSelectedTestData(fake)

	resp := createVLANState(t, data, nsdpVLANStatePlan())
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create must fail on persistent NSDP auth failures")
	}

	// withNSDPClient retries exactly once: the operation runs twice,
	// each against the one SET the plan needs to reach (PVID writes
	// come after step1, so exactly one auth-failing SET per pass).
	if got, want := len(fake.calls), 2; got != want {
		t.Fatalf("SET calls = %v, want exactly %d (initial + one retry)", got, want)
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{"password", "30-minute SET lockout"} {
		if !strings.Contains(text, want) {
			t.Fatalf("auth-failure diagnostic should mention %q, got: %q", want, text)
		}
	}
}

// ---------------------------------------------------------------------------
// Data sources over NSDP
// ---------------------------------------------------------------------------

func TestSwitchDataSourceOverNSDPReportsIdentity(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch() // identity GETs need no engine mode
	data := newNSDPSelectedTestData(fake)

	d := &switchDataSource{}
	d.data = data
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("switch data source over NSDP failed: %v", resp.Diagnostics)
	}

	var state switchDataSourceModel
	if diags := resp.State.Get(context.Background(), &state); diags.HasError() {
		t.Fatalf("reading data source state failed: %v", diags)
	}
	if got, want := state.ID.ValueString(), "nsdp@8c:3b:ad:25:1b:88"; got != want {
		t.Fatalf("data source ID = %q, want %q", got, want)
	}
	if got, want := state.SerialNumber.ValueString(), "UH77B5R033EE"; got != want {
		t.Fatalf("serial number = %q, want %q", got, want)
	}
	if got, want := state.Model.ValueString(), "GS108Ev3"; got != want {
		t.Fatalf("model = %q, want %q", got, want)
	}
	// No NSDP source: the bootloader version reads empty, never fails.
	if got := state.BootloaderVersion.ValueString(); got != "" {
		t.Fatalf("bootloader version over NSDP = %q, want empty", got)
	}
}

func TestVLANStateDataSourceOverNSDPReportsLiveTable(t *testing.T) {
	t.Parallel()

	fake := newNSDPVLANStateFake()
	data := newNSDPSelectedTestData(fake)

	d := &vlanStateDataSource{}
	d.data = data
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("vlan_state data source over NSDP failed: %v", resp.Diagnostics)
	}

	var state vlanStateDataSourceModel
	if diags := resp.State.Get(context.Background(), &state); diags.HasError() {
		t.Fatalf("reading data source state failed: %v", diags)
	}
	if got, want := state.ID.ValueString(), "nsdp@8c:3b:ad:25:1b:88"; got != want {
		t.Fatalf("data source ID = %q, want %q", got, want)
	}
	if len(state.VLANs) != 1 || state.VLANs[0].ID.ValueInt64() != 1 {
		t.Fatalf("data source should surface the factory VLAN 1 table, got %+v", state.VLANs)
	}
}

func TestVLANStateDataSourceOverNSDPRefusesNon8021QMode(t *testing.T) {
	t.Parallel()

	fake := newNSDPVLANStateFake()
	fake.engineMode = 1 // port-based: the guarded read refuses
	data := newNSDPSelectedTestData(fake)

	d := &vlanStateDataSource{}
	d.data = data
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{}, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("vlan_state data source must refuse in port-based engine mode (never surface a stale table)")
	}
	if !strings.Contains(diagnosticsDetailText(resp.Diagnostics), "netgear_plus_port_based_vlan") {
		t.Fatalf("refusal should point at netgear_plus_port_based_vlan, got: %q", diagnosticsDetailText(resp.Diagnostics))
	}
}

// ---------------------------------------------------------------------------
// Small local helpers.
// ---------------------------------------------------------------------------

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// TF_ACC-gated hardware acceptance skeletons (NSDP).
// ---------------------------------------------------------------------------

func acceptanceNSDPProviderData(t *testing.T) *providerData {
	t.Helper()

	agentMAC := normalizeAgentMAC(os.Getenv("NETGEAR_PLUS_AGENT_MAC"))
	password := os.Getenv("NETGEAR_PLUS_PASSWORD")
	ifaceName := os.Getenv("NETGEAR_PLUS_IFACE")
	if agentMAC == "" || password == "" {
		t.Skip("NETGEAR_PLUS_AGENT_MAC / NETGEAR_PLUS_PASSWORD not set: skipping NSDP hardware acceptance test")
	}

	// Optional: with NETGEAR_PLUS_HOST set, NSDP runs unicast to the
	// switch's routable address (host + agent_mac semantics) instead of
	// limited-broadcast — enables hardware acceptance runs from a
	// remote subnet. Unset keeps today's broadcast behavior.
	host := strings.TrimSpace(os.Getenv("NETGEAR_PLUS_HOST"))

	return &providerData{
		config: client.Config{
			Host:           host,
			Password:       password,
			RequestSpacing: defaultRequestSpacing,
		},
		agentMAC:  agentMAC,
		ifaceName: ifaceName,
		deviceKey: agentMAC,
	}
}

// TestAccVLANStateNSDPResource is the NSDP 802.1Q write acceptance
// skeleton.
//
// The corrected 0x2800 write path (ROUND 19 member/tagged payload,
// 2026-09-12) passed the full hardware acceptance run on 2026-09-12:
// create, read, update, verify, and delete all green against the
// GS108Ev3 (fw 2.06.24) through the provider CRUD spine. The extra
// NETGEAR_PLUS_ACC_8021Q_NSDP=1 opt-in gate is therefore gone — this
// test runs under plain TF_ACC like the rest of the hardware suite.
//
// Sacrificial discipline, identical to nsdp-gaps.sh: VLAN 999 and free
// ports 3/5 ONLY; the PVID change is on port 3 ONLY; ports 1, 2, and 8
// are NEVER written. The original state is read first, restored last,
// and the restore is verified.
func TestAccVLANStateNSDPResource(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set: skipping NSDP hardware acceptance test")
	}

	data := acceptanceNSDPProviderData(t)
	ctx := context.Background()

	var original model.VLANState

	// Phase 0: capture the original state (read-only) and require the
	// 802.1Q engine mode.
	if err := withSwitchTransport(ctx, data, func(transport switchTransport) error {
		state, err := transport.ReadVLANState(ctx)
		if err != nil {
			return err
		}
		original = state
		return nil
	}); err != nil {
		t.Fatalf("acceptance pre-read failed: %v", err)
	}

	// Phase 1: additive-only probe — VLAN 999 with port 3 tagged and
	// port 5 untagged, PVID of port 3 set to 999. Nothing else moves.
	desired := original.Normalize().Clone()
	if _, exists := desired.VLANs[999]; exists {
		t.Fatal("VLAN 999 already exists on the switch — pick another sacrificial VLAN")
	}
	desired.VLANs[999] = model.Vlan{
		ID: 999,
		Ports: map[int]model.PortMembership{
			3: model.PortMembershipTagged,
			5: model.PortMembershipUntagged,
		},
	}
	desired.PVIDs[3] = 999

	if err := withSwitchTransport(ctx, data, func(transport switchTransport) error {
		return transport.ApplyVLANState(ctx, desired)
	}); err != nil {
		t.Fatalf("acceptance additive apply failed: %v", err)
	}

	// Phase 2: verify the probe landed exactly.
	if err := withSwitchTransport(ctx, data, func(transport switchTransport) error {
		verified, err := transport.ReadVLANState(ctx)
		if err != nil {
			return err
		}
		if !verified.Equal(desired) {
			return &providerOperationError{
				summary: "acceptance verify failed",
				detail:  describeStateDrift(verified, desired),
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("acceptance verify failed: %v", err)
	}

	// Phase 3: restore the original state and verify the restore.
	if err := withSwitchTransport(ctx, data, func(transport switchTransport) error {
		return transport.ApplyVLANState(ctx, original)
	}); err != nil {
		t.Fatalf("acceptance restore apply failed: %v", err)
	}
	if err := withSwitchTransport(ctx, data, func(transport switchTransport) error {
		restored, err := transport.ReadVLANState(ctx)
		if err != nil {
			return err
		}
		if !restored.Equal(original.Normalize()) {
			return &providerOperationError{
				summary: "acceptance restore verify failed",
				detail:  describeStateDrift(restored, original),
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("acceptance restore verify failed: %v", err)
	}
}

// TestAccSwitchDataSourceNSDP reads switch identity over NSDP on real
// hardware: reads only, harmless GETs in any engine mode — standard
// TF_ACC gating, no extra env gate.
func TestAccSwitchDataSourceNSDP(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set: skipping NSDP hardware acceptance test")
	}
	data := acceptanceNSDPProviderData(t)

	d := &switchDataSource{}
	d.data = data
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("switch data source over NSDP failed: %v", resp.Diagnostics)
	}

	var state switchDataSourceModel
	if diags := resp.State.Get(context.Background(), &state); diags.HasError() {
		t.Fatalf("reading data source state failed: %v", diags)
	}
	if state.SerialNumber.ValueString() == "" {
		t.Fatal("serial number over NSDP should not be empty")
	}
	if got, want := state.ID.ValueString(), "nsdp@"+normalizeAgentMAC(os.Getenv("NETGEAR_PLUS_AGENT_MAC")); got != want {
		t.Fatalf("data source ID = %q, want %q", got, want)
	}
}

// TestAccVLANStateDataSourceNSDP reads the live 802.1Q VLAN/PVID state
// over NSDP on real hardware: reads only — but the engine-mode guard
// applies, so the switch must be in an 802.1Q engine mode (3 or 4) for
// this to pass. Standard TF_ACC gating, no extra env gate.
func TestAccVLANStateDataSourceNSDP(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set: skipping NSDP hardware acceptance test")
	}
	data := acceptanceNSDPProviderData(t)

	d := &vlanStateDataSource{}
	d.data = data
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	d.Read(context.Background(), datasource.ReadRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("vlan_state data source over NSDP failed: %v", resp.Diagnostics)
	}

	var state vlanStateDataSourceModel
	if diags := resp.State.Get(context.Background(), &state); diags.HasError() {
		t.Fatalf("reading data source state failed: %v", diags)
	}
	if state.ID.ValueString() == "" {
		t.Fatal("data source ID should not be empty")
	}
}
