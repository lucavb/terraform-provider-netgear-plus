package provider

import (
	"context"
	"errors"
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

func switchSettingsSchema(t *testing.T) rschema.Schema {
	t.Helper()

	var resp resource.SchemaResponse
	(&switchSettingsResource{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if diags := resp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatalf("schema validation returned errors: %v", diags)
	}
	return resp.Schema
}

func switchSettingsRawValue(t *testing.T, schema rschema.Schema, model switchSettingsResourceModel) tftypes.Value {
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

func switchSettingsTestPlan(t *testing.T, model switchSettingsResourceModel) tfsdk.Plan {
	t.Helper()

	schema := switchSettingsSchema(t)
	if model.ID.IsNull() {
		model.ID = types.StringNull()
	}
	return tfsdk.Plan{Raw: switchSettingsRawValue(t, schema, model), Schema: schema}
}

func switchSettingsTestState(t *testing.T, model switchSettingsResourceModel) tfsdk.State {
	t.Helper()

	schema := switchSettingsSchema(t)
	return tfsdk.State{Raw: switchSettingsRawValue(t, schema, model), Schema: schema}
}

func stateSwitchSettingsModel(t *testing.T, state tfsdk.State) switchSettingsResourceModel {
	t.Helper()

	var model switchSettingsResourceModel
	if diags := state.Get(context.Background(), &model); diags.HasError() {
		t.Fatalf("reading state into model failed: %v", diags)
	}
	return model
}

// factoryDefaultSwitchSettingsModel spells out the factory values, as
// Terraform would after applying schema defaults.
func factoryDefaultSwitchSettingsModel() switchSettingsResourceModel {
	return switchSettingsResourceModel{
		ID:                    types.StringNull(),
		QoSMode:               types.StringValue(defaultSwitchQoSMode),
		BlockUnknownMulticast: types.BoolValue(defaultSwitchBlockUnknownMulticast),
		MirrorDestinationPort: types.Int64Value(defaultMirrorDestinationPort),
		MirrorSourcePorts:     types.SetValueMust(types.Int64Type, []attr.Value{}),
	}
}

// mirrorSourcePorts builds the mirror_source_ports set attribute.
func mirrorSourcePorts(ports ...int64) types.Set {
	values := make([]attr.Value, 0, len(ports))
	for _, port := range ports {
		values = append(values, types.Int64Value(port))
	}
	return types.SetValueMust(types.Int64Type, values)
}

func createSwitchSettings(t *testing.T, data *providerData, model switchSettingsResourceModel) resource.CreateResponse {
	t.Helper()

	r := &switchSettingsResource{}
	r.data = data
	plan := switchSettingsTestPlan(t, model)
	req := resource.CreateRequest{Plan: plan}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: plan.Schema}}
	r.Create(context.Background(), req, &resp)
	return resp
}

func updateSwitchSettings(t *testing.T, data *providerData, model switchSettingsResourceModel, prior switchSettingsResourceModel) resource.UpdateResponse {
	t.Helper()

	r := &switchSettingsResource{}
	r.data = data
	plan := switchSettingsTestPlan(t, model)
	req := resource.UpdateRequest{
		Config: tfsdk.Config{Raw: plan.Raw, Schema: plan.Schema},
		Plan:   plan,
		State:  switchSettingsTestState(t, prior),
	}
	resp := resource.UpdateResponse{State: tfsdk.State{Schema: plan.Schema}}
	r.Update(context.Background(), req, &resp)
	return resp
}

// ---------------------------------------------------------------------------
// Schema and expand validation
// ---------------------------------------------------------------------------

func TestSwitchSettingsSchemaShape(t *testing.T) {
	t.Parallel()

	schema := switchSettingsSchema(t)

	if _, ok := schema.Attributes["id"]; !ok {
		t.Fatal("schema should expose computed id attribute")
	}

	qosMode := schema.Attributes["qos_mode"].(rschema.StringAttribute)
	if qosMode.Default == nil || len(qosMode.Validators) == 0 {
		t.Fatal("qos_mode must carry its factory default and the OneOf validator")
	}
	blocked := schema.Attributes["block_unknown_multicast"].(rschema.BoolAttribute)
	if blocked.Default == nil {
		t.Fatal("block_unknown_multicast must carry its factory default (false)")
	}
	dst := schema.Attributes["mirror_destination_port"].(rschema.Int64Attribute)
	if dst.Default == nil || len(dst.Validators) == 0 {
		t.Fatal("mirror_destination_port must carry its factory default and the 0-8 range validator")
	}
	srcs := schema.Attributes["mirror_source_ports"].(rschema.SetAttribute)
	if srcs.Default == nil || len(srcs.Validators) == 0 {
		t.Fatal("mirror_source_ports must carry its empty-set default and the 1-8 port validator")
	}
}

func TestExpandSwitchSettingsAppliesFactoryDefaults(t *testing.T) {
	t.Parallel()

	// A fully-null model (defaults not yet applied by Terraform) expands
	// to the factory settings, so a from-factory apply is a no-op.
	settings, err := expandSwitchSettings(context.Background(), switchSettingsResourceModel{
		ID:                    types.StringNull(),
		QoSMode:               types.StringNull(),
		BlockUnknownMulticast: types.BoolNull(),
		MirrorDestinationPort: types.Int64Null(),
		MirrorSourcePorts:     types.SetNull(types.Int64Type),
	})
	if err != nil {
		t.Fatalf("expandSwitchSettings(null model) failed: %v", err)
	}
	want := switchSettings{QoSMode: nsdp.QoSModePortBased, BlockUnknownMulticast: false, MirrorDst: 0}
	if settings.QoSMode != want.QoSMode || settings.BlockUnknownMulticast || settings.MirrorDst != 0 || len(settings.MirrorSrc) != 0 {
		t.Fatalf("expandSwitchSettings(null model) = %+v, want factory %+v", settings, want)
	}
}

func TestExpandSwitchSettingsRejectsInvalidMirrorRules(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	model := factoryDefaultSwitchSettingsModel()
	model.MirrorSourcePorts = mirrorSourcePorts(2, 3) // sources without destination
	if _, err := expandSwitchSettings(ctx, model); err == nil ||
		!strings.Contains(err.Error(), "mirror_source_ports` must be empty when `mirror_destination_port` is 0") {
		t.Fatalf("sources without destination error = %v, want the disabled-mirror rule", err)
	}

	model = factoryDefaultSwitchSettingsModel()
	model.MirrorDestinationPort = types.Int64Value(1) // destination without sources
	if _, err := expandSwitchSettings(ctx, model); err == nil ||
		!strings.Contains(err.Error(), "must name at least one source port") {
		t.Fatalf("destination without sources error = %v, want the empty-sources rule", err)
	}

	model = factoryDefaultSwitchSettingsModel()
	model.MirrorDestinationPort = types.Int64Value(1)
	model.MirrorSourcePorts = mirrorSourcePorts(1, 2) // destination also mirrored
	if _, err := expandSwitchSettings(ctx, model); err == nil ||
		!strings.Contains(err.Error(), "must not also appear in `mirror_source_ports`") {
		t.Fatalf("destination in sources error = %v, want the self-mirror rule", err)
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestSwitchSettingsCreateFromFactoryPlanSendsNoSets(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)

	resp := createSwitchSettings(t, data, factoryDefaultSwitchSettingsModel())
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create failed: %v", resp.Diagnostics)
	}

	if len(fake.calls) != 0 {
		t.Fatalf("SET calls = %v, want none (factory plan is a no-op)", fake.callStrings())
	}
	if !hasWarningWithSummary(resp.Diagnostics, "Switch settings already in sync") {
		t.Fatalf("Create should warn the settings are already in sync, diags: %v", resp.Diagnostics)
	}

	model := stateSwitchSettingsModel(t, resp.State)
	if got := model.ID.ValueString(); got != "nsdp@8c:3b:ad:25:1b:88" {
		t.Fatalf("state id = %q, want nsdp@<agent mac>", got)
	}
	if got := model.QoSMode.ValueString(); got != "port-based" {
		t.Fatalf("state qos_mode = %q, want port-based", got)
	}
	if model.BlockUnknownMulticast.ValueBool() {
		t.Fatal("state block_unknown_multicast should be false")
	}
	if model.MirrorDestinationPort.ValueInt64() != 0 || len(model.MirrorSourcePorts.Elements()) != 0 {
		t.Fatalf("state mirroring should be disabled, dst=%d srcs=%v",
			model.MirrorDestinationPort.ValueInt64(), model.MirrorSourcePorts)
	}
}

func TestSwitchSettingsCreateSendsOnlyChangedSets(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)

	model := factoryDefaultSwitchSettingsModel()
	model.QoSMode = types.StringValue("802.1p") // one changed field
	model.MirrorDestinationPort = types.Int64Value(1)
	model.MirrorSourcePorts = mirrorSourcePorts(2, 3)

	resp := createSwitchSettings(t, data, model)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create failed: %v", resp.Diagnostics)
	}

	// QoS, then multicast, then mirror (fixed apply order; one mirror SET
	// carries destination and sources together).
	want := []string{
		"SetQoSMode(mode=2)",
		"SetPortMirroring(dst=1, src=[2 3])",
	}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want %v", got, want)
	}

	verified := stateSwitchSettingsModel(t, resp.State)
	if got := verified.QoSMode.ValueString(); got != "802.1p" {
		t.Fatalf("state qos_mode = %q, want 802.1p", got)
	}
	if verified.MirrorDestinationPort.ValueInt64() != 1 {
		t.Fatalf("state mirror_destination_port = %d, want 1", verified.MirrorDestinationPort.ValueInt64())
	}
	if got := verified.MirrorSourcePorts.String(); !strings.Contains(got, "2") || !strings.Contains(got, "3") {
		t.Fatalf("state mirror_source_ports = %s, want ports 2 and 3", got)
	}
}

func TestSwitchSettingsCreateToleratesLostSetReply(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.DropSetReplies[1] = true // the SET's reply is lost; the write still applies
	data := newPortConfigTestData(fake)

	model := factoryDefaultSwitchSettingsModel()
	model.BlockUnknownMulticast = types.BoolValue(true) // the single change

	resp := createSwitchSettings(t, data, model)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create must survive a lost SET reply: %v", resp.Diagnostics)
	}

	// Exactly the one planned SET — the lost reply must never trigger a
	// re-send (read is truth; a re-send risks lockout strikes).
	want := []string{"SetBlockUnknownMulticast(blocked=true)"}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want %v (no re-send after lost reply)", got, want)
	}
	if !hasWarningWithSummary(resp.Diagnostics, "SET reply lost") {
		t.Fatalf("Create should warn about the lost reply, diags: %v", resp.Diagnostics)
	}

	if !fake.blockUnknownMulticast {
		t.Fatal("the write applied despite the lost reply")
	}
}

func TestSwitchSettingsCreateFailsAfterIgnoredSets(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.IgnoreSets = true // SETs are accepted but silently never apply
	data := newPortConfigTestData(fake)

	model := factoryDefaultSwitchSettingsModel()
	model.QoSMode = types.StringValue("802.1p")

	resp := createSwitchSettings(t, data, model)
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create must fail when the device silently ignores SETs")
	}

	// Initial SET + exactly ONE corrective pass, then the drift error.
	want := []string{
		"SetQoSMode(mode=2)",
		"SetQoSMode(mode=2)",
	}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want initial + one corrective pass %v", got, want)
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{"qos_mode=port-based (wanted 802.1p)"} {
		if !strings.Contains(text, want) {
			t.Fatalf("drift error should name %q, got: %q", want, text)
		}
	}
}

func TestSwitchSettingsCreateAuthFailureNamesLockout(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.AuthFailOnSet = true
	data := newPortConfigTestData(fake)

	model := factoryDefaultSwitchSettingsModel()
	model.BlockUnknownMulticast = types.BoolValue(true) // one change

	resp := createSwitchSettings(t, data, model)
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

func TestSwitchSettingsCreateRequiresAgentMAC(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)
	data.agentMAC = "" // provider configured without agent_mac
	data.deviceKey = canonicalHostKey("http://192.0.2.10")

	resp := createSwitchSettings(t, data, factoryDefaultSwitchSettingsModel())
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create must fail when the provider lacks agent_mac")
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	if !strings.Contains(text, "NSDP resources require the provider attribute agent_mac") {
		t.Fatalf("error should name the missing provider attribute, got: %q", text)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("SET calls = %v, want none", fake.callStrings())
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestSwitchSettingsReadReflectsDeviceDrift(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.qosMode = nsdp.QoSMode8021p  // drifted to 802.1p
	fake.blockUnknownMulticast = true // drifted to blocking
	fake.mirrorDst = 8                // mirroring drifted on
	fake.mirrorSrcPorts = []int{1, 2}
	data := newPortConfigTestData(fake)

	r := &switchSettingsResource{}
	r.data = data
	req := resource.ReadRequest{State: switchSettingsTestState(t, factoryDefaultSwitchSettingsModel())}
	resp := resource.ReadResponse{State: tfsdk.State{Schema: switchSettingsSchema(t)}}
	r.Read(context.Background(), req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read failed: %v", resp.Diagnostics)
	}

	model := stateSwitchSettingsModel(t, resp.State)
	if got := model.QoSMode.ValueString(); got != "802.1p" {
		t.Fatalf("Read should surface qos_mode drift, got %q", got)
	}
	if !model.BlockUnknownMulticast.ValueBool() {
		t.Fatal("Read should surface block_unknown_multicast=true drift")
	}
	if model.MirrorDestinationPort.ValueInt64() != 8 {
		t.Fatalf("Read should surface mirror_destination_port=8 drift, got %d", model.MirrorDestinationPort.ValueInt64())
	}
	if got := model.MirrorSourcePorts.String(); !strings.Contains(got, "1") || !strings.Contains(got, "2") {
		t.Fatalf("Read should surface mirror_source_ports {1,2} drift, got %s", got)
	}
}

func TestSwitchSettingsReadSurfacesGetFailure(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.GetBlockErr = errors.New("no valid response after 14 attempts")
	data := newPortConfigTestData(fake)

	r := &switchSettingsResource{}
	r.data = data
	req := resource.ReadRequest{State: switchSettingsTestState(t, factoryDefaultSwitchSettingsModel())}
	resp := resource.ReadResponse{State: tfsdk.State{Schema: switchSettingsSchema(t)}}
	r.Read(context.Background(), req, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("Read must fail when the block GETs fail")
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	if !strings.Contains(text, "Read switch settings failed") {
		t.Fatalf("Read error should be clear about the failed read, got: %q", text)
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestSwitchSettingsUpdateIsAuthoritativeOverDeviceDrift(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.blockUnknownMulticast = true // drifted away from the managed config
	data := newPortConfigTestData(fake)

	prior := factoryDefaultSwitchSettingsModel()
	prior.ID = types.StringValue("nsdp@8c:3b:ad:25:1b:88")

	plan := factoryDefaultSwitchSettingsModel()

	resp := updateSwitchSettings(t, data, plan, prior)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update failed: %v", resp.Diagnostics)
	}

	// The plan's defaults correct the out-of-band drift — nothing else.
	want := []string{"SetBlockUnknownMulticast(blocked=false)"}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want only the drift correction %v", got, want)
	}

	if fake.blockUnknownMulticast {
		t.Fatal("Update should have restored block_unknown_multicast=false")
	}
}

func TestSwitchSettingsUpdateSendsOnlyChangedFields(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)

	prior := factoryDefaultSwitchSettingsModel()
	prior.ID = types.StringValue("nsdp@8c:3b:ad:25:1b:88")

	plan := factoryDefaultSwitchSettingsModel()
	plan.MirrorDestinationPort = types.Int64Value(6)
	plan.MirrorSourcePorts = mirrorSourcePorts(1, 2)

	resp := updateSwitchSettings(t, data, plan, prior)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update failed: %v", resp.Diagnostics)
	}

	want := []string{"SetPortMirroring(dst=6, src=[1 2])"}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want only the changed mirroring %v", got, want)
	}

	verified := stateSwitchSettingsModel(t, resp.State)
	if verified.MirrorDestinationPort.ValueInt64() != 6 {
		t.Fatalf("state mirror_destination_port = %d, want 6", verified.MirrorDestinationPort.ValueInt64())
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestSwitchSettingsDeleteIsStateOnly(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)

	r := &switchSettingsResource{}
	r.data = data
	req := resource.DeleteRequest{State: switchSettingsTestState(t, factoryDefaultSwitchSettingsModel())}
	resp := resource.DeleteResponse{}
	r.Delete(context.Background(), req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete failed: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("Delete must not write to the switch, SET calls = %v", fake.callStrings())
	}
	if !hasWarningWithSummary(resp.Diagnostics, "Delete leaves switch configuration unchanged") {
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
// / NETGEAR_PLUS_PASSWORD environment variables and runs on a real switch
// only when those are set.
//
// The configuration is all factory defaults (a factory-fresh switch
// applies nothing), then block_unknown_multicast flipped on — a single
// mild, easily reversible SET.
// ---------------------------------------------------------------------------

func TestAccSwitchSettingsResource(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set: skipping NSDP hardware acceptance test")
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

	// Phase 1: all-defaults plan on a factory-fresh switch is a no-op.
	defaults := factoryDefaultSwitchSettingsModel()
	createResp := createSwitchSettings(t, data, defaults)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("acceptance Create (defaults) failed: %v", createResp.Diagnostics)
	}

	// Phase 2: one flipped setting — block unknown multicast.
	plan := factoryDefaultSwitchSettingsModel()
	plan.BlockUnknownMulticast = types.BoolValue(true)
	updateResp := updateSwitchSettings(t, data, plan, stateSwitchSettingsModel(t, createResp.State))
	if updateResp.Diagnostics.HasError() {
		t.Fatalf("acceptance Update (flip block_unknown_multicast) failed: %v", updateResp.Diagnostics)
	}

	// Convergence: re-applying the same plan must be a no-op.
	convergeResp := updateSwitchSettings(t, data, plan, stateSwitchSettingsModel(t, updateResp.State))
	if convergeResp.Diagnostics.HasError() {
		t.Fatalf("acceptance convergence apply failed: %v", convergeResp.Diagnostics)
	}
	if !hasWarningWithSummary(convergeResp.Diagnostics, "Switch settings already in sync") {
		t.Fatalf("convergence apply should be a no-op, diags: %v", convergeResp.Diagnostics)
	}

	// CheckDestroy equivalent: Delete is state-only.
	r := &switchSettingsResource{}
	r.data = data
	delResp := resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: updateResp.State}, &delResp)
	if delResp.Diagnostics.HasError() {
		t.Fatalf("acceptance Delete failed: %v", delResp.Diagnostics)
	}
	if !hasWarningWithSummary(delResp.Diagnostics, "Delete leaves switch configuration unchanged") {
		t.Fatalf("Delete should be state-only with a warning, diags: %v", delResp.Diagnostics)
	}
}
