package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client/gs108tv2"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// ---------------------------------------------------------------------------
// Milestone-3 F3b provider tests: port_config over the composite
// text-config transport, reboot_to_apply preflights, changes_pending.
// All socket-free (stub textcfgDriver; the endpoint sentinel tests
// mutate the package var the driver itself guards, with cleanup).
// ---------------------------------------------------------------------------
func tv2PortPlan(t *testing.T, mutate func([]portConfigPortModel)) portConfigResourceModel {
	t.Helper()

	ports := factoryDefaultPortModels()
	if mutate != nil {
		mutate(ports)
	}
	return portConfigResourceModel{
		ID:    types.StringNull(),
		Ports: ports,
	}
}

// tv2PortTestPlan builds a framework plan from the FULL model (incl.
// reboot_to_apply), unlike portConfigTestPlan which only serializes the
// ports block.
func tv2PortTestPlan(t *testing.T, model portConfigResourceModel) tfsdk.Plan {
	t.Helper()

	schema := portConfigSchema(t)
	raw := portConfigRawValue(t, schema, model)
	return tfsdk.Plan{Raw: raw, Schema: schema}
}

func tv2CreatePortConfig(t *testing.T, data *providerData, model portConfigResourceModel) resource.CreateResponse {
	t.Helper()

	r := &portConfigResource{}
	r.data = data
	plan := tv2PortTestPlan(t, model)
	req := resource.CreateRequest{Plan: plan}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: plan.Schema}}
	r.Create(context.Background(), req, &resp)
	return resp
}

// -------------------------------------------------------------------------
// port_config over the composite text-config transport.
// -------------------------------------------------------------------------

// TestPortConfigGS108Tv2RoutesToComposite: on model gs108tv2 the
// resource consults the composite's ReadPortSettings/ApplyPortSettings
// seams (NOT the NSDP blocks), writes the gs108tv2@host ID, and the
// factory-default no-op apply reports changes_pending=false.
func TestPortConfigGS108Tv2RoutesToComposite(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	transportBuilt := false
	driver := &stubTextcfgDriver{}
	plan := tv2PortPlan(t, nil) // all defaults → no-op apply
	data := newGS108Tv2TextcfgTestData(t, driver, struct {
		Host     string
		AgentMAC string
	}{Host: "http://192.0.2.20", AgentMAC: "8c:3b:ad:25:1b:88"})
	data.textcfgFactory = func(textcfgDriverRequest) (textcfgDriver, error) {
		transportBuilt = true
		return driver, nil
	}

	resp := createPortConfig(t, data, plan.Ports)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create over the composite failed: %v", resp.Diagnostics)
	}
	if !transportBuilt {
		t.Fatal("Create must build the composite text-config transport")
	}
	if driver.readPortCalls < 1 {
		t.Fatal("ReadPortSettings must be consulted (current + verify)")
	}
	if driver.applyPortCalls != 1 {
		t.Fatalf("ApplyPortSettings calls = %d, want 1", driver.applyPortCalls)
	}
	if driver.applyCalls != 0 || driver.rebootCalls != 0 {
		t.Fatalf("VLAN/reboot seams must stay untouched: %d/%d", driver.applyCalls, driver.rebootCalls)
	}

	state := statePortConfigModel(t, resp.State)
	if got, want := state.ID.ValueString(), "gs108tv2@192.0.2.20"; got != want {
		t.Fatalf("state ID = %q, want the text-config convention %q", got, want)
	}
	if state.ChangesPending.ValueBool() {
		t.Fatal("a no-op apply must leave changes_pending=false")
	}
	if state.ChangesPending.IsNull() {
		t.Fatal("changes_pending must be set on the written state")
	}
}

// TestPortConfigGS108Tv2StagesPortAndWarns: a flow-control change on
// port 3 stages (one restore), the state carries changes_pending=true,
// and the staged-for-next-reboot warning surfaces.
func TestPortConfigGS108Tv2StagesPortAndWarns(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	current := gs108tv2.DefaultPortSettingsMap()
	var gotDesired map[int]gs108tv2.PortSettings
	driver := &stubTextcfgDriver{
		readPortSettings: func(context.Context) (map[int]gs108tv2.PortSettings, error) {
			return current, nil
		},
		applyPortSettings: func(_ context.Context, desired map[int]gs108tv2.PortSettings) (gs108tv2.ApplyOutcome, error) {
			gotDesired = desired
			// Converge: the next verify read sees the staged state.
			after := make(map[int]gs108tv2.PortSettings, len(desired))
			for p, ps := range desired {
				after[p] = ps
			}
			current = after
			return gs108tv2.ApplyOutcome{Staged: true}, nil
		},
	}
	data := newGS108Tv2TextcfgTestData(t, driver, struct {
		Host     string
		AgentMAC string
	}{Host: "http://192.0.2.20", AgentMAC: "8c:3b:ad:25:1b:88"})

	plan := tv2PortPlan(t, func(ports []portConfigPortModel) {
		ports[2].FlowControl = types.BoolValue(true) // port 3
	})
	resp := createPortConfig(t, data, plan.Ports)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create over the composite failed: %v", resp.Diagnostics)
	}

	if !gotDesired[3].FlowControl || gotDesired[3].Enabled != true || gotDesired[3].QoSPriority != "low" {
		t.Fatalf("desired map lost the plan's port 3 override: %+v", gotDesired[3])
	}

	state := statePortConfigModel(t, resp.State)
	if !state.ChangesPending.ValueBool() {
		t.Fatal("a staged (not rebooted) apply must set changes_pending=true")
	}
	if !hasWarningWithSummary(resp.Diagnostics, "gs108tv2: Port configuration changes are staged for the next reboot") {
		t.Fatalf("apply must warn about the staged semantics, diags = %v", resp.Diagnostics)
	}
	if hasWarningWithSummary(resp.Diagnostics, "gs108tv2: the switch rewrote the staged configuration") {
		t.Fatal("canonical divergence warning must stay absent on a clean re-serialize")
	}
}

// TestPortConfigGS108Tv2CapabilityRefusal: qos_priority "high" on port 2
// produces a typed per-port diagnostic BEFORE any staging — zero reads,
// zero applies, zero transport construction.
func TestPortConfigGS108Tv2CapabilityRefusal(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	driver := &stubTextcfgDriver{
		readPortSettings: func(context.Context) (map[int]gs108tv2.PortSettings, error) {
			t.Error("ReadPortSettings must not be reached through a refused capability plan")
			return nil, nil
		},
		applyPortSettings: func(context.Context, map[int]gs108tv2.PortSettings) (gs108tv2.ApplyOutcome, error) {
			t.Error("ApplyPortSettings must never stage a refused capability plan")
			return gs108tv2.ApplyOutcome{}, nil
		},
	}
	data := newGS108Tv2TextcfgTestData(t, driver, struct {
		Host     string
		AgentMAC string
	}{Host: "http://192.0.2.20", AgentMAC: "8c:3b:ad:25:1b:88"})
	transportBuilt := false
	data.textcfgFactory = func(textcfgDriverRequest) (textcfgDriver, error) {
		transportBuilt = true
		return driver, nil
	}

	plan := tv2PortPlan(t, func(ports []portConfigPortModel) {
		ports[1].QoSPriority = types.StringValue("high") // port 2
	})
	resp := createPortConfig(t, data, plan.Ports)
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create must refuse a non-default Unsupported attribute")
	}
	if transportBuilt {
		t.Fatal("the capability refusal must happen BEFORE any transport construction")
	}
	if driver.readPortCalls != 0 || driver.applyPortCalls != 0 {
		t.Fatalf("refused plan reached the driver (reads=%d applies=%d)", driver.readPortCalls, driver.applyPortCalls)
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{"port 2", "qos_priority", `"high"`, "no FASTPATH 5.4.2.36 text-config grammar"} {
		if !strings.Contains(text, want) {
			t.Fatalf("capability refusal should mention %q, got: %q", want, text)
		}
	}
}

// TestPortConfigGS108Tv2SerialPinRefusal: the same fail-closed rail as
// vlan_state — without agent_mac nothing reaches the switch.
func TestPortConfigGS108Tv2SerialPinRefusal(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	driver := &stubTextcfgDriver{
		applyPortSettings: func(context.Context, map[int]gs108tv2.PortSettings) (gs108tv2.ApplyOutcome, error) {
			t.Error("ApplyPortSettings must never run on an unpinned serial")
			return gs108tv2.ApplyOutcome{}, nil
		},
	}
	data := newGS108Tv2TextcfgTestData(t, driver, struct {
		Host     string
		AgentMAC string
	}{Host: "http://192.0.2.20"})
	transportBuilt := false
	data.textcfgFactory = func(textcfgDriverRequest) (textcfgDriver, error) {
		transportBuilt = true
		return driver, nil
	}

	resp := createPortConfig(t, data, tv2PortPlan(t, nil).Ports)
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create without agent_mac must refuse on gs108tv2")
	}
	if transportBuilt {
		t.Fatal("the serial-pin refusal must happen BEFORE any transport construction")
	}
	if driver.readPortCalls != 0 || driver.applyPortCalls != 0 {
		t.Fatalf("unpinned plan reached the driver (reads=%d applies=%d)", driver.readPortCalls, driver.applyPortCalls)
	}
	if text := diagnosticsDetailText(resp.Diagnostics); !strings.Contains(text, "Model gs108tv2 requires agent_mac") {
		t.Fatalf("serial-pin refusal summary missing, got: %q", text)
	}
}

// TestPortConfigGS108Tv2ReadFlattens: Read decodes the startup config's
// port bodies into the state and passes changes_pending/reboot_to_apply
// through unchanged (running state unobservable between applies).
func TestPortConfigGS108Tv2ReadFlattens(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	current := gs108tv2.DefaultPortSettingsMap()
	p3 := current[3]
	p3.FlowControl = true
	p5 := current[5]
	p5.Enabled = false
	current[3] = p3
	current[5] = p5

	driver := &stubTextcfgDriver{
		readPortSettings: func(context.Context) (map[int]gs108tv2.PortSettings, error) {
			return current, nil
		},
	}
	data := newGS108Tv2TextcfgTestData(t, driver, struct {
		Host     string
		AgentMAC string
	}{Host: "http://192.0.2.20", AgentMAC: "8c:3b:ad:25:1b:88"})

	r := &portConfigResource{}
	r.data = data
	req := resource.ReadRequest{State: portConfigTestState(t, portConfigResourceModel{
		ID:             types.StringValue("gs108tv2@192.0.2.20"),
		Ports:          factoryDefaultPortModels(),
		RebootToApply:  types.BoolValue(false),
		ChangesPending: types.BoolValue(true),
	})}
	resp := resource.ReadResponse{State: tfsdk.State{Schema: portConfigSchema(t)}}
	r.Read(context.Background(), req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read over the composite failed: %v", resp.Diagnostics)
	}

	state := statePortConfigModel(t, resp.State)
	if !state.Ports[2].FlowControl.ValueBool() {
		t.Fatal("Read should surface port 3 flow_control=true from the startup config")
	}
	if state.Ports[4].Enabled.ValueBool() {
		t.Fatal("Read should surface port 5 enabled=false from the startup config (shutdown line)")
	}
	if got, want := state.ID.ValueString(), "gs108tv2@192.0.2.20"; got != want {
		t.Fatalf("Read should preserve the state id, got %q want %q", got, want)
	}
	// Unobservability: both flags pass through on Read (value kept,
	// NOT re-computed from the switch).
	if state.ChangesPending.IsNull() || !state.ChangesPending.ValueBool() {
		t.Fatal("Read must pass changes_pending through unchanged (no reboot detection between applies)")
	}
	if state.RebootToApply.IsNull() || state.RebootToApply.ValueBool() {
		t.Fatal("Read must pass reboot_to_apply through unchanged")
	}
}

// -------------------------------------------------------------------------
// reboot_to_apply.
// -------------------------------------------------------------------------

// TestVLANStateRebootPreflightRefusal: with the endpoint sentinel still
// unpinned (the DEFAULT until phase 0b), reboot_to_apply=true refuses
// typed and actionable BEFORE any staging — zero apply calls.
func TestVLANStateRebootPreflightRefusal(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})
	if gs108tv2.RebootEndpoint != "" {
		t.Fatal("precondition: RebootEndpoint must be empty by default (phase 0b)")
	}

	driver := &stubTextcfgDriver{
		applyVLANState: func(context.Context, model.VLANState) (gs108tv2.ApplyOutcome, error) {
			t.Error("staging must never happen when the reboot cannot be honored")
			return gs108tv2.ApplyOutcome{}, nil
		},
	}
	data := newGS108Tv2TextcfgTestData(t, driver, struct {
		Host     string
		AgentMAC string
	}{Host: "http://192.0.2.20", AgentMAC: "8c:3b:ad:25:1b:88"})

	plan := nsdpVLANStatePlan()
	plan.RebootToApply = types.BoolValue(true)
	resp := createVLANState(t, data, plan)
	if !resp.Diagnostics.HasError() {
		t.Fatal("reboot_to_apply with an unpinned endpoint must refuse")
	}
	if driver.applyCalls != 0 || driver.rebootCalls != 0 {
		t.Fatalf("preflight refusal leaked work to the driver (applies=%d reboots=%d)", driver.applyCalls, driver.rebootCalls)
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{"reboot endpoint is not pinned", "phase 0b", "reboot_to_apply"} {
		if !strings.Contains(text, want) {
			t.Fatalf("sentinel refusal should mention %q, got: %q", want, text)
		}
	}
}

// TestPortConfigRebootPreflightRefusal: the same gate on the port
// resource (still zero transport work).
func TestPortConfigRebootPreflightRefusal(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})
	if gs108tv2.RebootEndpoint != "" {
		t.Fatal("precondition: RebootEndpoint must be empty by default (phase 0b)")
	}

	driver := &stubTextcfgDriver{}
	data := newGS108Tv2TextcfgTestData(t, driver, struct {
		Host     string
		AgentMAC string
	}{Host: "http://192.0.2.20", AgentMAC: "8c:3b:ad:25:1b:88"})
	transportBuilt := false
	data.textcfgFactory = func(textcfgDriverRequest) (textcfgDriver, error) {
		transportBuilt = true
		return driver, nil
	}

	plan := tv2PortPlan(t, nil)
	plan.RebootToApply = types.BoolValue(true)
	resp := tv2CreatePortConfig(t, data, plan)
	if !resp.Diagnostics.HasError() {
		t.Fatal("reboot_to_apply with an unpinned endpoint must refuse")
	}
	if transportBuilt || driver.readPortCalls != 0 || driver.applyPortCalls != 0 {
		t.Fatal("the reboot preflight must run before ANY transport work")
	}
	if text := diagnosticsDetailText(resp.Diagnostics); !strings.Contains(text, "reboot endpoint is not pinned") {
		t.Fatalf("sentinel refusal text missing, got: %q", text)
	}
}

// TestVLANStateRebootingApplyHappyPath: with a PINNED endpoint, a
// changed apply stages, reboots, and reports changes_pending=false with
// NO pending-staged warning (the change is active).
func TestVLANStateRebootingApplyHappyPath(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
		gs108tv2.RebootEndpoint = ""
	})
	gs108tv2.RebootEndpoint = "/base/system/reboot.html" // phase-0b pinned shape

	desired := (model.VLANState{PortCount: 8, VLANs: map[int]model.Vlan{}, PVIDs: map[int]int{}}).Normalize()
	var staged model.VLANState
	driver := &stubTextcfgDriver{
		readVLANState: func(context.Context) (model.VLANState, error) {
			if staged.VLANs != nil {
				return staged, nil
			}
			return desired, nil // empty pre-apply startup state
		},
		applyVLANState: func(_ context.Context, want model.VLANState) (gs108tv2.ApplyOutcome, error) {
			staged = want
			return gs108tv2.ApplyOutcome{Staged: true}, nil
		},
		rebootAndWait: func(context.Context) (gs108tv2.RebootOutcome, error) {
			return gs108tv2.RebootOutcome{Rebooted: true, UptimeReset: true, Fingerprint: "fp"}, nil
		},
	}
	data := newGS108Tv2TextcfgTestData(t, driver, struct {
		Host     string
		AgentMAC string
	}{Host: "http://192.0.2.20", AgentMAC: "8c:3b:ad:25:1b:88"})

	plan := nsdpVLANStatePlan()
	plan.RebootToApply = types.BoolValue(true)
	resp := createVLANState(t, data, plan)
	if resp.Diagnostics.HasError() {
		t.Fatalf("rebooting apply failed: %v", resp.Diagnostics)
	}

	if driver.applyCalls != 1 {
		t.Fatalf("apply calls = %d, want 1 (stage happened before the reboot)", driver.applyCalls)
	}
	if driver.rebootCalls != 1 {
		t.Fatalf("reboot calls = %d, want 1", driver.rebootCalls)
	}
	state := stateVLANStateModel(t, resp.State)
	if state.ChangesPending.ValueBool() {
		t.Fatal("a rebooting apply must leave changes_pending=false (the change is active)")
	}
	if hasWarningWithSummary(resp.Diagnostics, "gs108tv2: VLAN changes are staged for the next reboot") {
		t.Fatal("a rebooting apply must not warn about pending staged changes")
	}
}

// TestRebootToApplyRefusedOnGS108Ev3: the option exists only for the
// text-config channel; the ev3 NSDP path refuses typed before any
// transport work.
func TestRebootToApplyRefusedOnGS108Ev3(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	data := newHTTPSelectedTestData() // model implicitly gs108ev3, HTTP stub driver

	plan := nsdpVLANStatePlan()
	plan.RebootToApply = types.BoolValue(true)
	resp := createVLANState(t, data, plan)
	if !resp.Diagnostics.HasError() {
		t.Fatal("reboot_to_apply must refuse on gs108ev3")
	}
	if text := diagnosticsDetailText(resp.Diagnostics); !strings.Contains(text, "reboot_to_apply is a gs108tv2 option") {
		t.Fatalf("ev3 refusal text missing, got: %q", text)
	}
}

// TestPortConfigGS108Tv2VerifiesDrift: the fake stages something OTHER
// than the desired map — the verify re-read must produce the typed
// post-apply verification failure.
func TestPortConfigGS108Tv2VerifiesDrift(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	current := gs108tv2.DefaultPortSettingsMap()
	driver := &stubTextcfgDriver{
		readPortSettings: func(context.Context) (map[int]gs108tv2.PortSettings, error) {
			return current, nil // never converges
		},
		applyPortSettings: func(context.Context, map[int]gs108tv2.PortSettings) (gs108tv2.ApplyOutcome, error) {
			return gs108tv2.ApplyOutcome{Staged: true}, nil
		},
	}
	data := newGS108Tv2TextcfgTestData(t, driver, struct {
		Host     string
		AgentMAC string
	}{Host: "http://192.0.2.20", AgentMAC: "8c:3b:ad:25:1b:88"})

	plan := tv2PortPlan(t, func(ports []portConfigPortModel) {
		ports[2].FlowControl = types.BoolValue(true) // port 3
	})
	resp := createPortConfig(t, data, plan.Ports)
	if !resp.Diagnostics.HasError() {
		t.Fatal("a non-converging_read must fail post-apply verification")
	}
	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{"Post-apply verification failed", "port 3"} {
		if !strings.Contains(text, want) {
			t.Fatalf("verification failure should mention %q, got: %q", want, text)
		}
	}
}

// -------------------------------------------------------------------------
// Composite seams (widened surface smoke tests).
// -------------------------------------------------------------------------

func TestTextcfgSwitchTransportPortAndRebootSeams(t *testing.T) {
	t.Parallel()

	desired := gs108tv2.DefaultPortSettingsMap()
	var gotDesired map[int]gs108tv2.PortSettings
	driver := &stubTextcfgDriver{
		readPortSettings: func(context.Context) (map[int]gs108tv2.PortSettings, error) {
			return gs108tv2.DefaultPortSettingsMap(), nil
		},
		applyPortSettings: func(_ context.Context, want map[int]gs108tv2.PortSettings) (gs108tv2.ApplyOutcome, error) {
			gotDesired = want
			return gs108tv2.ApplyOutcome{Staged: true, CanonicalDiverged: true}, nil
		},
		rebootAndWait: func(context.Context) (gs108tv2.RebootOutcome, error) {
			return gs108tv2.RebootOutcome{Rebooted: true, UptimeReset: true, Fingerprint: "fp"}, nil
		},
	}
	var transportImpl switchTransport = textcfgSwitchTransport{driver: driver}

	if _, ok := transportImpl.(portSettingsTransport); !ok {
		t.Fatal("the composite must satisfy the port read seam")
	}
	if _, ok := transportImpl.(detailedPortSettingsApplier); !ok {
		t.Fatal("the composite must satisfy the detailed port apply seam")
	}
	if _, ok := transportImpl.(textcfgRebooter); !ok {
		t.Fatal("the composite must satisfy the reboot seam")
	}

	outcome, err := transportImpl.(detailedPortSettingsApplier).ApplyPortSettingsDetailed(context.Background(), desired)
	if err != nil {
		t.Fatalf("ApplyPortSettingsDetailed() error = %v", err)
	}
	if !outcome.Staged || !outcome.CanonicalDiverged {
		t.Fatalf("outcome = %+v, want staged + diverged passthrough", outcome)
	}
	if len(gotDesired) != 8 || gotDesired[3] != gs108tv2.DefaultPortSettings() {
		t.Fatalf("desired map passthrough broken: %+v", gotDesired[3])
	}

	rebooted, err := transportImpl.(textcfgRebooter).Reboot(context.Background())
	if err != nil {
		t.Fatalf("Reboot() error = %v", err)
	}
	if !rebooted.Rebooted || rebooted.Fingerprint != "fp" {
		t.Fatalf("reboot outcome passthrough broken: %+v", rebooted)
	}

	// The plain port seam discards the outcome but still applies once.
	if _, err := transportImpl.(detailedPortSettingsApplier).ApplyPortSettingsDetailed(context.Background(), desired); err != nil {
		t.Fatalf("second apply error = %v", err)
	}
	if driver.applyPortCalls != 2 {
		t.Fatalf("apply count = %d, want 2", driver.applyPortCalls)
	}
}
