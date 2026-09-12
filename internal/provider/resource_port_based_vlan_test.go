package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	tftypes "github.com/hashicorp/terraform-plugin-go/tftypes"
)

// ---------------------------------------------------------------------------
// Direct-drive helpers (mirroring the port_config patterns: resource CRUD
// requests carry no ProviderData, so r.data is set directly).
// ---------------------------------------------------------------------------

func portBasedVLANSchema(t *testing.T) rschema.Schema {
	t.Helper()

	var resp resource.SchemaResponse
	(&portBasedVLANResource{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if diags := resp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatalf("schema validation returned errors: %v", diags)
	}
	return resp.Schema
}

func portBasedVLANRawValue(t *testing.T, schema rschema.Schema, model portBasedVLANResourceModel) tftypes.Value {
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

func portBasedVLANTestPlan(t *testing.T, vlans []portBasedVLANBlockModel) tfsdk.Plan {
	t.Helper()

	schema := portBasedVLANSchema(t)
	model := portBasedVLANResourceModel{ID: types.StringNull(), VLANs: vlans}
	return tfsdk.Plan{Raw: portBasedVLANRawValue(t, schema, model), Schema: schema}
}

func portBasedVLANTestState(t *testing.T, model portBasedVLANResourceModel) tfsdk.State {
	t.Helper()

	schema := portBasedVLANSchema(t)
	return tfsdk.State{Raw: portBasedVLANRawValue(t, schema, model), Schema: schema}
}

func statePortBasedVLANModel(t *testing.T, state tfsdk.State) portBasedVLANResourceModel {
	t.Helper()

	var model portBasedVLANResourceModel
	if diags := state.Get(context.Background(), &model); diags.HasError() {
		t.Fatalf("reading state into model failed: %v", diags)
	}
	return model
}

// vlanBlocks builds one vlans block per VLAN (id, sorted ports).
func vlanBlocks(t *testing.T, table map[int][]int) []portBasedVLANBlockModel {
	t.Helper()

	blocks := make([]portBasedVLANBlockModel, 0, len(table))
	for _, vlanID := range sortedIntPorts(mapKeys(table)) {
		ports := make([]attr.Value, 0, len(table[vlanID]))
		for _, port := range table[vlanID] {
			ports = append(ports, types.Int64Value(int64(port)))
		}
		blocks = append(blocks, portBasedVLANBlockModel{
			VLANID: types.Int64Value(int64(vlanID)),
			Ports:  types.SetValueMust(types.Int64Type, ports),
		})
	}
	return blocks
}

func mapKeys(m map[int][]int) []int {
	keys := make([]int, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// factoryDefaultVLANBlocks returns the factory table: VLAN 1 on all ports.
func factoryDefaultVLANBlocks(t *testing.T) []portBasedVLANBlockModel {
	t.Helper()

	return vlanBlocks(t, map[int][]int{1: {1, 2, 3, 4, 5, 6, 7, 8}})
}

func createPortBasedVLAN(t *testing.T, data *providerData, vlans []portBasedVLANBlockModel) resource.CreateResponse {
	t.Helper()

	r := &portBasedVLANResource{}
	r.data = data
	plan := portBasedVLANTestPlan(t, vlans)
	req := resource.CreateRequest{Plan: plan}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: plan.Schema}}
	r.Create(context.Background(), req, &resp)
	return resp
}

func updatePortBasedVLAN(t *testing.T, data *providerData, vlans []portBasedVLANBlockModel, prior portBasedVLANResourceModel) resource.UpdateResponse {
	t.Helper()

	r := &portBasedVLANResource{}
	r.data = data
	plan := portBasedVLANTestPlan(t, vlans)
	req := resource.UpdateRequest{
		Config: tfsdk.Config{Raw: plan.Raw, Schema: plan.Schema},
		Plan:   plan,
		State:  portBasedVLANTestState(t, prior),
	}
	resp := resource.UpdateResponse{State: tfsdk.State{Schema: plan.Schema}}
	r.Update(context.Background(), req, &resp)
	return resp
}

// ---------------------------------------------------------------------------
// Schema and expand validation
// ---------------------------------------------------------------------------

func TestPortBasedVLANSchemaShape(t *testing.T) {
	t.Parallel()

	schema := portBasedVLANSchema(t)

	if _, ok := schema.Attributes["id"]; !ok {
		t.Fatal("schema should expose computed id attribute")
	}
	block, ok := schema.Blocks["vlans"]
	if !ok {
		t.Fatal("schema should expose vlans block")
	}
	listBlock, ok := block.(rschema.ListNestedBlock)
	if !ok {
		t.Fatalf("vlans block type = %T, want resource/schema.ListNestedBlock", block)
	}
	if len(listBlock.Validators) == 0 {
		t.Fatal("vlans block must require at least one entry")
	}

	nested := listBlock.NestedObject.Attributes
	vlanID, ok := nested["vlan_id"].(rschema.Int64Attribute)
	if !ok || !vlanID.Required || len(vlanID.Validators) == 0 {
		t.Fatal("vlan_id must be Required with a range validator")
	}
	ports, ok := nested["ports"].(rschema.SetAttribute)
	if !ok || !ports.Required || len(ports.Validators) == 0 {
		t.Fatal("ports must be a Required set with size and range validators")
	}
}

func TestExpandPortBasedVLANsRejectsDuplicates(t *testing.T) {
	t.Parallel()

	table := map[int][]int{
		10: {1, 2},
		20: {2, 3},
	}
	blocks := vlanBlocks(t, table)
	dup := append(append([]portBasedVLANBlockModel{}, blocks...), portBasedVLANBlockModel{
		VLANID: types.Int64Value(10), // duplicate of the first block
		Ports:  types.SetValueMust(types.Int64Type, []attr.Value{types.Int64Value(4)}),
	})

	_, err := expandPortBasedVLANs(context.Background(), portBasedVLANResourceModel{VLANs: dup})
	if err == nil || !strings.Contains(err.Error(), "duplicate `vlan_id` 10") {
		t.Fatalf("expandPortBasedVLANs() duplicate error = %v, want duplicate vlan_id 10", err)
	}
}

func TestExpandPortBasedVLANsAllowsOverlappingPorts(t *testing.T) {
	t.Parallel()

	// Overlapping port sets are legal in port-based VLANs — expand must
	// not reject them.
	table := map[int][]int{
		10: {1, 2},
		20: {2, 3},
	}
	expanded, err := expandPortBasedVLANs(context.Background(), portBasedVLANResourceModel{VLANs: vlanBlocks(t, table)})
	if err != nil {
		t.Fatalf("expandPortBasedVLANs(overlapping) failed: %v", err)
	}
	if !reflect.DeepEqual(expanded, table) {
		t.Fatalf("expandPortBasedVLANs(overlapping) = %v, want %v", expanded, table)
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestPortBasedVLANCreateFromFactoryPlanSendsNoSets(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)

	resp := createPortBasedVLAN(t, data, factoryDefaultVLANBlocks(t))
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create failed: %v", resp.Diagnostics)
	}

	if len(fake.calls) != 0 {
		t.Fatalf("SET calls = %v, want none (factory table is a no-op)", fake.callStrings())
	}
	if !hasWarningWithSummary(resp.Diagnostics, "Port-based VLAN table already in sync") {
		t.Fatalf("Create should warn the table is already in sync, diags: %v", resp.Diagnostics)
	}

	model := statePortBasedVLANModel(t, resp.State)
	if got := model.ID.ValueString(); got != "nsdp@8c:3b:ad:25:1b:88" {
		t.Fatalf("state id = %q, want nsdp@<agent mac>", got)
	}
	if len(model.VLANs) != 1 || model.VLANs[0].VLANID.ValueInt64() != 1 || len(model.VLANs[0].Ports.Elements()) != 8 {
		t.Fatalf("state should carry the factory table (VLAN 1, all ports), got %+v", model.VLANs)
	}
}

func TestPortBasedVLANCreateAppliesChangedVLANs(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)

	plan := vlanBlocks(t, map[int][]int{
		1:  {1, 2, 3, 4, 5, 6, 7, 8}, // unchanged factory entry
		10: {1, 2, 3},                // new VLAN
	})

	resp := createPortBasedVLAN(t, data, plan)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create failed: %v", resp.Diagnostics)
	}

	want := []string{"SetPortBasedVLAN(vlan=10, ports=[1 2 3])"}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want only the new VLAN %v", got, want)
	}

	if got := fake.pbvlans[10]; !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Fatalf("device VLAN 10 = %v, want [1 2 3]", got)
	}
}

func TestPortBasedVLANCreateLandsOverlappingVLANs(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)

	// Overlapping VLANs are the point of port-based VLANs: both must
	// land, in ascending VLAN order.
	plan := vlanBlocks(t, map[int][]int{
		1:  {1, 2, 3, 4, 5, 6, 7, 8},
		10: {1, 2},
		20: {2, 3},
	})

	resp := createPortBasedVLAN(t, data, plan)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create failed: %v", resp.Diagnostics)
	}

	want := []string{
		"SetPortBasedVLAN(vlan=10, ports=[1 2])",
		"SetPortBasedVLAN(vlan=20, ports=[2 3])",
	}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want %v", got, want)
	}

	if got := fake.pbvlans[10]; !reflect.DeepEqual(got, []int{1, 2}) {
		t.Fatalf("device VLAN 10 = %v, want [1 2]", got)
	}
	if got := fake.pbvlans[20]; !reflect.DeepEqual(got, []int{2, 3}) {
		t.Fatalf("device VLAN 20 = %v, want [2 3]", got)
	}
}

func TestPortBasedVLANCreateRefusesUnmanagedVLANs(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.pbvlans = map[int][]int{ // device carries an extra VLAN 5
		1: {1, 2, 3, 4, 5, 6, 7, 8},
		5: {4, 5},
	}
	data := newPortConfigTestData(fake)

	// Plan omits VLAN 5 → authoritative-table refusal, zero SETs.
	resp := createPortBasedVLAN(t, data, factoryDefaultVLANBlocks(t))
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create must refuse when the plan omits device VLANs")
	}

	if len(fake.calls) != 0 {
		t.Fatalf("SET calls = %v, want none (refusal happens before any SET)", fake.callStrings())
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{"VLANs [5]", "Add [5]", "No configuration was sent to the switch"} {
		if !strings.Contains(text, want) {
			t.Fatalf("unmanaged-VLAN refusal should mention %q, got: %q", want, text)
		}
	}
}

func TestPortBasedVLANCreateRefusesNonPortBasedEngineModes(t *testing.T) {
	t.Parallel()

	for _, mode := range []nsdp.VLANEngineMode{2, 3, 4} {
		fake := newFakeSwitch()
		fake.engineMode = mode // id-based / 802.1q port-based / 802.1q extended
		data := newPortConfigTestData(fake)

		plan := vlanBlocks(t, map[int][]int{
			1:  {1, 2, 3, 4, 5, 6, 7, 8},
			10: {1, 2},
		})

		resp := createPortBasedVLAN(t, data, plan)
		if !resp.Diagnostics.HasError() {
			t.Fatalf("Create must refuse when the engine mode is %d", byte(mode))
		}

		if len(fake.calls) != 0 {
			t.Fatalf("engine mode %d: SET calls = %v, want none (guard fires before any SET)", byte(mode), fake.callStrings())
		}

		text := diagnosticsDetailText(resp.Diagnostics)
		for _, want := range []string{
			fmt.Sprintf("VLAN engine mode is %d", byte(mode)),
			"netgear_plus_vlan_state",
			"sent no configuration",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("engine mode %d: guard should mention %q, got: %q", byte(mode), want, text)
			}
		}
	}
}

func TestPortBasedVLANCreateToleratesLostSetReply(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.DropSetReplies[1] = true // the SET's reply is lost; the write still applies
	data := newPortConfigTestData(fake)

	plan := vlanBlocks(t, map[int][]int{
		1:  {1, 2, 3, 4, 5, 6, 7, 8},
		10: {1, 2},
	})

	resp := createPortBasedVLAN(t, data, plan)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create must survive a lost SET reply: %v", resp.Diagnostics)
	}

	// Exactly the one planned SET — the lost reply must never trigger a
	// re-send (read is truth; a re-send risks lockout strikes).
	want := []string{"SetPortBasedVLAN(vlan=10, ports=[1 2])"}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want %v (no re-send after lost reply)", got, want)
	}
	if !hasWarningWithSummary(resp.Diagnostics, "SET reply lost") {
		t.Fatalf("Create should warn about the lost reply, diags: %v", resp.Diagnostics)
	}

	if got := fake.pbvlans[10]; !reflect.DeepEqual(got, []int{1, 2}) {
		t.Fatalf("the write applied despite the lost reply, VLAN 10 = %v", got)
	}
}

func TestPortBasedVLANCreateFailsAfterIgnoredSets(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.IgnoreSets = true // SETs are accepted but silently never apply
	data := newPortConfigTestData(fake)

	plan := vlanBlocks(t, map[int][]int{
		1:  {1, 2, 3, 4, 5, 6, 7, 8},
		10: {1, 2},
	})

	resp := createPortBasedVLAN(t, data, plan)
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create must fail when the device silently ignores SETs")
	}

	// Initial SET + exactly ONE corrective pass, then the drift error.
	want := []string{
		"SetPortBasedVLAN(vlan=10, ports=[1 2])",
		"SetPortBasedVLAN(vlan=10, ports=[1 2])",
	}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want initial + one corrective pass %v", got, want)
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{"vlan 10: missing (wanted ports [1, 2])"} {
		if !strings.Contains(text, want) {
			t.Fatalf("drift error should name %q, got: %q", want, text)
		}
	}
}

func TestPortBasedVLANCreateAuthFailureNamesLockout(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.AuthFailOnSet = true
	data := newPortConfigTestData(fake)

	plan := vlanBlocks(t, map[int][]int{
		1:  {1, 2, 3, 4, 5, 6, 7, 8},
		10: {1, 2},
	})

	resp := createPortBasedVLAN(t, data, plan)
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create must fail on persistent NSDP auth failures")
	}

	// withNSDPClient retries exactly once with a fresh client (one
	// re-login attempt per operation, never more).
	if got := fake.callStrings(); len(got) != 2 {
		t.Fatalf("SET calls = %v, want exactly 2 (initial + one retry)", got)
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{"password", "30-minute SET lockout", "re-apply"} {
		if !strings.Contains(text, want) {
			t.Fatalf("auth-failure diagnostic should mention %q, got: %q", want, text)
		}
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestPortBasedVLANReadReflectsDeviceDrift(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.pbvlans = map[int][]int{ // drifted table
		1:  {1, 2, 3, 4},
		10: {5, 6},
	}
	data := newPortConfigTestData(fake)

	r := &portBasedVLANResource{}
	r.data = data
	req := resource.ReadRequest{State: portBasedVLANTestState(t, portBasedVLANResourceModel{
		ID:    types.StringValue("nsdp@8c:3b:ad:25:1b:88"),
		VLANs: factoryDefaultVLANBlocks(t),
	})}
	resp := resource.ReadResponse{State: tfsdk.State{Schema: portBasedVLANSchema(t)}}
	r.Read(context.Background(), req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read failed: %v", resp.Diagnostics)
	}

	model := statePortBasedVLANModel(t, resp.State)
	if len(model.VLANs) != 2 {
		t.Fatalf("Read should surface the drifted 2-entry table, got %+v", model.VLANs)
	}
	if model.VLANs[0].VLANID.ValueInt64() != 1 || len(model.VLANs[0].Ports.Elements()) != 4 {
		t.Fatalf("Read should surface VLAN 1 ports [1 2 3 4], got %+v", model.VLANs[0])
	}
	if model.VLANs[1].VLANID.ValueInt64() != 10 || len(model.VLANs[1].Ports.Elements()) != 2 {
		t.Fatalf("Read should surface VLAN 10 ports [5 6], got %+v", model.VLANs[1])
	}
	if got, want := model.ID.ValueString(), "nsdp@8c:3b:ad:25:1b:88"; got != want {
		t.Fatalf("Read should preserve the state id, got %q want %q", got, want)
	}
}

func TestPortBasedVLANReadRefusesNonPortBasedEngineMode(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.engineMode = 3 // 802.1q port-based
	data := newPortConfigTestData(fake)

	r := &portBasedVLANResource{}
	r.data = data
	req := resource.ReadRequest{State: portBasedVLANTestState(t, portBasedVLANResourceModel{
		ID:    types.StringValue("nsdp@8c:3b:ad:25:1b:88"),
		VLANs: factoryDefaultVLANBlocks(t),
	})}
	resp := resource.ReadResponse{State: tfsdk.State{Schema: portBasedVLANSchema(t)}}
	r.Read(context.Background(), req, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("Read must refuse in non-port-based mode (never surface a stale table)")
	}

	if len(fake.calls) != 0 {
		t.Fatalf("SET calls = %v, want none", fake.callStrings())
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{"Refusing to manage the port-based VLAN table", "netgear_plus_vlan_state"} {
		if !strings.Contains(text, want) {
			t.Fatalf("Read guard should mention %q, got: %q", want, text)
		}
	}
}

func TestPortBasedVLANReadSurfacesGetFailure(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.GetBlockErr = errors.New("no valid response after 14 attempts")
	data := newPortConfigTestData(fake)

	r := &portBasedVLANResource{}
	r.data = data
	req := resource.ReadRequest{State: portBasedVLANTestState(t, portBasedVLANResourceModel{
		ID:    types.StringValue("nsdp@8c:3b:ad:25:1b:88"),
		VLANs: factoryDefaultVLANBlocks(t),
	})}
	resp := resource.ReadResponse{State: tfsdk.State{Schema: portBasedVLANSchema(t)}}
	r.Read(context.Background(), req, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("Read must fail when the block GETs fail")
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	if !strings.Contains(text, "VLAN engine mode guard failed") {
		t.Fatalf("Read error should name the failed guard read, got: %q", text)
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestPortBasedVLANUpdateSendsOnlyChangedVLANs(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)

	prior := portBasedVLANResourceModel{
		ID:    types.StringValue("nsdp@8c:3b:ad:25:1b:88"),
		VLANs: factoryDefaultVLANBlocks(t),
	}

	plan := vlanBlocks(t, map[int][]int{
		1:  {1, 2, 3, 4, 5, 6, 7, 8},
		10: {1, 2},
		20: {2, 3},
	})

	resp := updatePortBasedVLAN(t, data, plan, prior)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update failed: %v", resp.Diagnostics)
	}

	want := []string{
		"SetPortBasedVLAN(vlan=10, ports=[1 2])",
		"SetPortBasedVLAN(vlan=20, ports=[2 3])",
	}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want only the new VLANs %v", got, want)
	}
}

func TestPortBasedVLANUpdateIsAuthoritativeOverDeviceDrift(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.pbvlans = map[int][]int{ // device drifted: VLAN 1 lost ports
		1: {1, 2, 3, 4},
	}
	data := newPortConfigTestData(fake)

	prior := portBasedVLANResourceModel{
		ID:    types.StringValue("nsdp@8c:3b:ad:25:1b:88"),
		VLANs: factoryDefaultVLANBlocks(t),
	}

	resp := updatePortBasedVLAN(t, data, factoryDefaultVLANBlocks(t), prior)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update failed: %v", resp.Diagnostics)
	}

	// The plan's full VLAN 1 restores the drifted port set.
	want := []string{"SetPortBasedVLAN(vlan=1, ports=[1 2 3 4 5 6 7 8])"}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want the drift correction %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestPortBasedVLANDeleteIsStateOnly(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)

	r := &portBasedVLANResource{}
	r.data = data
	req := resource.DeleteRequest{State: portBasedVLANTestState(t, portBasedVLANResourceModel{
		ID:    types.StringValue("nsdp@8c:3b:ad:25:1b:88"),
		VLANs: factoryDefaultVLANBlocks(t),
	})}
	resp := resource.DeleteResponse{}
	r.Delete(context.Background(), req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete failed: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("Delete must not write to the switch, SET calls = %v", fake.callStrings())
	}
	if !hasWarningWithSummary(resp.Diagnostics, "Delete leaves the VLAN table unchanged") {
		t.Fatalf("Delete should warn that it is state-only, diags: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// TF_ACC-gated hardware acceptance skeleton.
//
// The repo has no terraform-plugin-testing dependency (no TF_ACC harness
// exists yet), so this drives the resource CRUD methods directly against
// real hardware, mirroring the unit-test direct-drive helpers. It is
// gated behind TF_ACC plus the NETGEAR_PLUS_AGENT_MAC / NETGEAR_PLUS_IFACE
// / NETGEAR_PLUS_PASSWORD environment variables AND an explicit
// NETGEAR_PLUS_ACC_PORT_BASED_VLAN=1 opt-in — writes to the VLAN table of
// a real switch are more intrusive than a per-port setting, so it runs
// only when asked for by name.
//
// The plan is the factory table (VLAN 1, all ports) plus VLAN 10 with a
// small port set, so a factory-fresh switch applies one mild SET.
// ---------------------------------------------------------------------------

func TestAccPortBasedVLANResource(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set: skipping NSDP hardware acceptance test")
	}
	if os.Getenv("NETGEAR_PLUS_ACC_PORT_BASED_VLAN") != "1" {
		t.Skip("NETGEAR_PLUS_ACC_PORT_BASED_VLAN != 1: port-based VLAN writes are opt-in")
	}
	agentMAC := normalizeAgentMAC(os.Getenv("NETGEAR_PLUS_AGENT_MAC"))
	password := os.Getenv("NETGEAR_PLUS_PASSWORD")
	ifaceName := os.Getenv("NETGEAR_PLUS_IFACE")
	if agentMAC == "" || password == "" {
		t.Skip("NETGEAR_PLUS_AGENT_MAC / NETGEAR_PLUS_PASSWORD not set: skipping NSDP hardware acceptance test")
	}

	data := &providerData{
		config: client.Config{
			Password:       password,
			RequestSpacing: defaultRequestSpacing,
		},
		agentMAC:  agentMAC,
		ifaceName: ifaceName,
		deviceKey: agentMAC,
	}

	plan := vlanBlocks(t, map[int][]int{
		1:  {1, 2, 3, 4, 5, 6, 7, 8},
		10: {1, 2},
	})

	// Create: apply the near-factory plan.
	createResp := createPortBasedVLAN(t, data, plan)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("acceptance Create failed: %v", createResp.Diagnostics)
	}

	// Convergence: a second apply of the identical plan must send no SETs.
	convergeResp := updatePortBasedVLAN(t, data, plan, statePortBasedVLANModel(t, createResp.State))
	if convergeResp.Diagnostics.HasError() {
		t.Fatalf("acceptance convergence apply failed: %v", convergeResp.Diagnostics)
	}
	if !hasWarningWithSummary(convergeResp.Diagnostics, "Port-based VLAN table already in sync") {
		t.Fatalf("second apply should be a no-op, diags: %v", convergeResp.Diagnostics)
	}

	// CheckDestroy equivalent: Delete is state-only — it must succeed
	// with the state-only warning and never write to the switch.
	r := &portBasedVLANResource{}
	r.data = data
	delResp := resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: createResp.State}, &delResp)
	if delResp.Diagnostics.HasError() {
		t.Fatalf("acceptance Delete failed: %v", delResp.Diagnostics)
	}
	if !hasWarningWithSummary(delResp.Diagnostics, "Delete leaves the VLAN table unchanged") {
		t.Fatalf("Delete should be state-only with a warning, diags: %v", delResp.Diagnostics)
	}
}
