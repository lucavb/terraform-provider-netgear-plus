package provider

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/client/gs108tv2"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// ---------------------------------------------------------------------------
// stubTextcfgDriver: method-level fake of the gs108tv2 text-config
// driver surface (textcfgDriver), socket-free.
// ---------------------------------------------------------------------------

type stubTextcfgDriver struct {
	login             func(context.Context) error
	logout            func(context.Context) error
	readSwitchFacts   func(context.Context) (model.SwitchFacts, error)
	readVLANState     func(context.Context) (model.VLANState, error)
	applyVLANState    func(context.Context, model.VLANState) (gs108tv2.ApplyOutcome, error)
	readPortSettings  func(context.Context) (map[int]gs108tv2.PortSettings, error)
	applyPortSettings func(context.Context, map[int]gs108tv2.PortSettings) (gs108tv2.ApplyOutcome, error)
	rebootAndWait     func(context.Context) (gs108tv2.RebootOutcome, error)
	fingerprint       func(context.Context) (string, error)

	applyCalls     int
	applyPortCalls int
	rebootCalls    int
	readPortCalls  int
}

func (d *stubTextcfgDriver) Login(ctx context.Context) error {
	if d.login != nil {
		return d.login(ctx)
	}
	return nil
}

func (d *stubTextcfgDriver) Logout(ctx context.Context) error {
	if d.logout != nil {
		return d.logout(ctx)
	}
	return nil
}

func (d *stubTextcfgDriver) ReadSwitchFacts(ctx context.Context) (model.SwitchFacts, error) {
	if d.readSwitchFacts != nil {
		return d.readSwitchFacts(ctx)
	}
	return model.SwitchFacts{Model: "gs108tv2", FirmwareVersion: "5.4.2.36", MACAddress: "8c:3b:ad:2c:e9:7d"}, nil
}

func (d *stubTextcfgDriver) ReadVLANState(ctx context.Context) (model.VLANState, error) {
	if d.readVLANState != nil {
		return d.readVLANState(ctx)
	}
	return (model.VLANState{PortCount: 8, VLANs: map[int]model.Vlan{}, PVIDs: map[int]int{}}).Normalize(), nil
}

func (d *stubTextcfgDriver) ApplyVLANState(ctx context.Context, desired model.VLANState) (gs108tv2.ApplyOutcome, error) {
	d.applyCalls++
	if d.applyVLANState != nil {
		return d.applyVLANState(ctx, desired)
	}
	return gs108tv2.ApplyOutcome{Staged: true}, nil
}

func (d *stubTextcfgDriver) ReadPortSettings(ctx context.Context) (map[int]gs108tv2.PortSettings, error) {
	d.readPortCalls++
	if d.readPortSettings != nil {
		return d.readPortSettings(ctx)
	}
	return gs108tv2.DefaultPortSettingsMap(), nil
}

func (d *stubTextcfgDriver) ApplyPortSettings(ctx context.Context, desired map[int]gs108tv2.PortSettings) (gs108tv2.ApplyOutcome, error) {
	d.applyPortCalls++
	if d.applyPortSettings != nil {
		return d.applyPortSettings(ctx, desired)
	}
	return gs108tv2.ApplyOutcome{Staged: true}, nil
}

func (d *stubTextcfgDriver) RebootAndWait(ctx context.Context) (gs108tv2.RebootOutcome, error) {
	d.rebootCalls++
	if d.rebootAndWait != nil {
		return d.rebootAndWait(ctx)
	}
	return gs108tv2.RebootOutcome{Rebooted: true, UptimeReset: true}, nil
}

func (d *stubTextcfgDriver) Fingerprint(ctx context.Context) (string, error) {
	if d.fingerprint != nil {
		return d.fingerprint(ctx)
	}
	return "", nil
}

// ---------------------------------------------------------------------------
// providerData builders.
// ---------------------------------------------------------------------------

// syncReset returns a fresh zero sync.Map for the global per-device
// lock tables (the existing-test reset convention).
func syncReset() sync.Map {
	return sync.Map{}
}

// newGS108Tv2TextcfgTestData builds providerData bound to model
// gs108tv2 with a stub text-config driver behind the test factory.
func newGS108Tv2TextcfgTestData(t *testing.T, driver *stubTextcfgDriver, opts struct {
	Host     string
	AgentMAC string
}) *providerData {
	t.Helper()

	data := &providerData{
		config: client.Config{
			Host:           opts.Host,
			Password:       "sekrit",
			Model:          client.ModelGS108Tv2,
			RequestTimeout: 15,
			InsecureHTTP:   true,
			RequestSpacing: time.Millisecond,
		},
		ifaceName: "en0",
		agentMAC:  strings.ToLower(opts.AgentMAC),
	}
	data.deviceKey = data.agentMAC
	if data.deviceKey == "" {
		data.deviceKey = canonicalHostKey(opts.Host)
	}
	data.textcfgFactory = func(textcfgDriverRequest) (textcfgDriver, error) {
		return driver, nil
	}
	if data.agentMAC != "" {
		fake := newFakeSwitch()
		data.nsdpFactory = func(nsdp.Options) (nsdpClient, error) {
			return fake, nil
		}
	}
	return data
}

// ---------------------------------------------------------------------------
// Composite transport unit tests (stub driver).
// ---------------------------------------------------------------------------

func TestTextcfgSwitchTransportFactsFallBackToFastpath(t *testing.T) {
	t.Parallel()

	driver := &stubTextcfgDriver{}
	transport := textcfgSwitchTransport{driver: driver, resourceID: "gs108tv2@192.0.2.20"}

	facts, err := transport.ReadSwitchFacts(context.Background())
	if err != nil {
		t.Fatalf("ReadSwitchFacts() error = %v", err)
	}
	if got, want := facts.Model, "gs108tv2"; got != want {
		t.Fatalf("facts.Model = %q, want the fastpath read %q", got, want)
	}
	// Channel limit: the fastpath/config-file facts carry no serial.
	if facts.SerialNumber != "" {
		t.Fatalf("facts.SerialNumber = %q, want empty (text-config channel cannot read the serial)", facts.SerialNumber)
	}
	if got, want := transport.ResourceID(), "gs108tv2@192.0.2.20"; got != want {
		t.Fatalf("ResourceID() = %q, want %q", got, want)
	}
}

func TestTextcfgSwitchTransportFactsPreferNSDPIdentity(t *testing.T) {
	t.Parallel()

	// With agent_mac configured, the composite's identity adapter (an
	// nsdpSwitchTransport over the shared NSDP client) owns the facts:
	// that is the only path carrying the serial the pin compares.
	fake := newFakeSwitch()
	transport := textcfgSwitchTransport{
		driver:     &stubTextcfgDriver{},
		resourceID: "gs108tv2@192.0.2.20",
		identity:   nsdpSwitchTransport{client: fake, agentMAC: "8c:3b:ad:25:1b:88"},
	}

	facts, err := transport.ReadSwitchFacts(context.Background())
	if err != nil {
		t.Fatalf("ReadSwitchFacts() error = %v", err)
	}
	if got, want := facts.SerialNumber, "UH77B5R033EE"; got != want {
		t.Fatalf("facts.SerialNumber = %q, want the NSDP v1 identity %q", got, want)
	}
	if got, want := facts.MACAddress, "8c:3b:ad:25:1b:88"; got != want {
		t.Fatalf("facts.MACAddress = %q, want the configured agent_mac %q", got, want)
	}
}

func TestTextcfgSwitchTransportApplySurfacesOutcome(t *testing.T) {
	t.Parallel()

	desired := (model.VLANState{PortCount: 8, VLANs: map[int]model.Vlan{}, PVIDs: map[int]int{}}).Normalize()
	driver := &stubTextcfgDriver{
		applyVLANState: func(_ context.Context, state model.VLANState) (gs108tv2.ApplyOutcome, error) {
			if !state.Equal(desired) {
				t.Fatalf("ApplyVLANState got %v, want the passed-through desired state", state)
			}
			return gs108tv2.ApplyOutcome{Staged: true, CanonicalDiverged: true}, nil
		},
	}
	transport := textcfgSwitchTransport{driver: driver}

	if err := transport.ApplyVLANState(context.Background(), desired); err != nil {
		t.Fatalf("ApplyVLANState(interface shape) error = %v", err)
	}
	if driver.applyCalls != 1 {
		t.Fatalf("apply count = %d, want 1 (the interface method must not double-apply)", driver.applyCalls)
	}

	outcome, err := transport.ApplyVLANStateDetailed(context.Background(), desired)
	if err != nil {
		t.Fatalf("ApplyVLANStateDetailed() error = %v", err)
	}
	if !outcome.Staged || !outcome.CanonicalDiverged {
		t.Fatalf("outcome = %+v, want staged + canonical-diverged pass-through", outcome)
	}
	if driver.applyCalls != 2 {
		t.Fatalf("apply count = %d, want 2", driver.applyCalls)
	}
}

// ---------------------------------------------------------------------------
// Routing (withSwitchTransport / withSwitchIdentityTransport).
// ---------------------------------------------------------------------------

func TestSwitchTransportSelectionGS108Tv2UsesComposite(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	driver := &stubTextcfgDriver{}
	data := &providerData{
		config: client.Config{
			Host:           "http://192.0.2.20",
			Model:          client.ModelGS108Tv2,
			RequestSpacing: time.Millisecond,
		},
		textcfgFactory: func(textcfgDriverRequest) (textcfgDriver, error) {
			return driver, nil
		},
	}

	err := withSwitchTransport(context.Background(), data, func(transport switchTransport) error {
		if _, ok := transport.(textcfgSwitchTransport); !ok {
			t.Fatalf("gs108tv2 selection must yield textcfgSwitchTransport, got %T", transport)
		}
		if got, want := transport.ResourceID(), "gs108tv2@192.0.2.20"; got != want {
			t.Fatalf("resource ID = %q, want facts-based %q", got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withSwitchTransport(gs108tv2) error = %v", err)
	}
}

func TestSwitchTransportSelectionGS108Tv2IgnoresAgentMAC(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	// agent_mac presence must NOT change the VLAN-seam routing: NSDP v1
	// has no VLAN datatypes, so the composite stays in charge even when
	// the identity seam shares the NSDP client.
	driver := &stubTextcfgDriver{}
	data := &providerData{
		config: client.Config{
			Host:           "http://192.0.2.20",
			Model:          client.ModelGS108Tv2,
			RequestSpacing: time.Millisecond,
		},
		agentMAC:  "8c:3b:ad:25:1b:88",
		deviceKey: "8c:3b:ad:25:1b:88",
		nsdpFactory: func(nsdp.Options) (nsdpClient, error) {
			return newFakeSwitch(), nil
		},
		textcfgFactory: func(textcfgDriverRequest) (textcfgDriver, error) {
			return driver, nil
		},
	}

	err := withSwitchTransport(context.Background(), data, func(transport switchTransport) error {
		if _, ok := transport.(textcfgSwitchTransport); !ok {
			t.Fatalf("agent_mac must not switch the VLAN seam off the composite, got %T", transport)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withSwitchTransport(gs108tv2 + agent_mac) error = %v", err)
	}
}

func TestSwitchIdentityTransportGS108Tv2WithoutAgentMACRefuses(t *testing.T) {
	t.Parallel()

	data := &providerData{
		config: client.Config{
			Host:  "http://192.0.2.20",
			Model: client.ModelGS108Tv2,
		},
	}

	err := withSwitchIdentityTransport(context.Background(), data, func(switchTransport) error {
		t.Fatal("identity seam must refuse before any transport call")
		return nil
	})
	var opErr *providerOperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("identity seam refusal error = %v (%T), want a typed providerOperationError", err, err)
	}
	for _, want := range []string{"agent_mac", "gs108tv2", "identity"} {
		if !strings.Contains(strings.Join([]string{opErr.summary, opErr.detail}, " "), want) {
			t.Fatalf("refusal should mention %q, got: %q / %q", want, opErr.summary, opErr.detail)
		}
	}
	// The remedy must stay honest: config-channel operations still
	// work with host only.
	if !strings.Contains(opErr.detail, "text-config") {
		t.Fatalf("refusal should say config-channel operations still work, got: %q", opErr.detail)
	}
}

func TestSwitchIdentityTransportGS108Tv2WithAgentMACKeepsNSDP(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	// Identity facts are NSDP v1's job on this model: the identity seam
	// keeps today's NSDP branch (agent_mac is sufficient; no host).
	fake := newFakeSwitch()
	data := &providerData{
		config: client.Config{
			Password:       "sekrit",
			Model:          client.ModelGS108Tv2,
			RequestSpacing: time.Millisecond,
		},
		agentMAC:  "8c:3b:ad:25:1b:88",
		deviceKey: "8c:3b:ad:25:1b:88",
		nsdpFactory: func(nsdp.Options) (nsdpClient, error) {
			return fake, nil
		},
	}

	err := withSwitchIdentityTransport(context.Background(), data, func(transport switchTransport) error {
		if _, ok := transport.(nsdpSwitchTransport); !ok {
			t.Fatalf("identity seam with agent_mac must stay nsdpSwitchTransport, got %T", transport)
		}
		if got, want := transport.ResourceID(), "nsdp@8c:3b:ad:25:1b:88"; got != want {
			t.Fatalf("resource ID = %q, want the NSDP convention %q", got, want)
		}
		facts, err := transport.ReadSwitchFacts(context.Background())
		if err != nil {
			t.Fatalf("ReadSwitchFacts over the identity seam: %v", err)
		}
		if got, want := facts.SerialNumber, "UH77B5R033EE"; got != want {
			t.Fatalf("serial = %q, want the NSDP v1 identity %q", got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withSwitchIdentityTransport(gs108tv2 + agent_mac) error = %v", err)
	}
}

func TestSwitchIdentityTransportGS108Ev3RoutesThroughWithSwitchTransport(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	data := newHTTPSelectedTestData()
	err := withSwitchIdentityTransport(context.Background(), data, func(transport switchTransport) error {
		if _, ok := transport.(httpSwitchTransport); !ok {
			t.Fatalf("non-gs108tv2 identity seam must route through withSwitchTransport, got %T", transport)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withSwitchIdentityTransport(ev3) error = %v", err)
	}
}

func TestSwitchTransportGS108Tv2RequiresHost(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	data := &providerData{
		config: client.Config{
			Password:       "sekrit",
			Model:          client.ModelGS108Tv2,
			RequestSpacing: time.Millisecond,
		},
		agentMAC:  "8c:3b:ad:25:1b:88",
		deviceKey: "8c:3b:ad:25:1b:88",
	}

	err := withSwitchTransport(context.Background(), data, func(switchTransport) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "require the provider attribute host") {
		t.Fatalf("host-less gs108tv2 VLAN seam error = %v, want the host requirement", err)
	}
}

// ---------------------------------------------------------------------------
// Resource layer: serial-pin refusal + staged-semantics diagnostics.
// ---------------------------------------------------------------------------

func TestVLANStateGS108Tv2SerialPinRefusal(t *testing.T) {
	t.Parallel()

	asserted := false
	driver := &stubTextcfgDriver{
		applyVLANState: func(context.Context, model.VLANState) (gs108tv2.ApplyOutcome, error) {
			t.Error("ApplyVLANState must never be reached without the serial pin")
			return gs108tv2.ApplyOutcome{}, nil
		},
	}
	data := newGS108Tv2TextcfgTestData(t, driver, struct {
		Host     string
		AgentMAC string
	}{Host: "http://192.0.2.20"})

	// Capture that the factory was NOT consulted either: without
	// agent_mac the refusal happens before the transport is even built.
	data.textcfgFactory = func(textcfgDriverRequest) (textcfgDriver, error) {
		asserted = true
		return driver, nil
	}

	plan := nsdpVLANStatePlan()
	resp := createVLANState(t, data, plan)
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create without agent_mac must refuse on gs108tv2")
	}
	if asserted {
		t.Fatal("the refusal must happen BEFORE any transport construction")
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{
		"Model gs108tv2 requires agent_mac",
		"expected_serial_number",
		"agent_mac",
		"spanning-tree configuration name",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("serial-pin refusal should mention %q, got: %q", want, text)
		}
	}
}

func TestVLANStateGS108Tv2StagedWarning(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	// The stub replays the classic staged flow: pre-apply reads see the
	// (empty) current state; the apply stores the desired state; the
	// post-apply startup-config re-read then verifies clean.
	var staged model.VLANState
	driver := &stubTextcfgDriver{
		readVLANState: func(context.Context) (model.VLANState, error) {
			if staged.VLANs != nil {
				return staged, nil
			}
			return (model.VLANState{PortCount: 8, VLANs: map[int]model.Vlan{}, PVIDs: map[int]int{}}).Normalize(), nil
		},
		applyVLANState: func(_ context.Context, desired model.VLANState) (gs108tv2.ApplyOutcome, error) {
			staged = desired
			return gs108tv2.ApplyOutcome{Staged: true, CanonicalDiverged: false}, nil
		},
	}
	data := newGS108Tv2TextcfgTestData(t, driver, struct {
		Host     string
		AgentMAC string
	}{Host: "http://192.0.2.20", AgentMAC: "8c:3b:ad:25:1b:88"})

	resp := createVLANState(t, data, nsdpVLANStatePlan())
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create over the composite failed: %v", resp.Diagnostics)
	}
	if !hasWarningWithSummary(resp.Diagnostics, "gs108tv2: VLAN changes are staged for the next reboot") {
		t.Fatalf("apply must warn about the staged semantics, diags = %v", resp.Diagnostics)
	}
	// Canonical divergence was false: no normalizer warning.
	if hasWarningWithSummary(resp.Diagnostics, "gs108tv2: the switch rewrote the staged configuration") {
		t.Fatal("canonical divergence warning must stay absent on a clean re-serialize")
	}
	// Stage-without-reboot is exactly what changes_pending covers.
	state := stateVLANStateModel(t, resp.State)
	if !state.ChangesPending.ValueBool() {
		t.Fatal("a staged (not rebooted) apply must set changes_pending=true")
	}
	if state.RebootToApply.ValueBool() {
		t.Fatal("reboot_to_apply must default to false in the written state")
	}
}

func TestVLANStateGS108Tv2CanonicalDivergenceWarning(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = syncReset()
		hostOperationPacers = syncReset()
	})

	// The stub replays the classic staged flow with a switch-side
	// normalizer rewrite (canonical divergence = re-fetched bytes are
	// not the uploaded bytes).
	var staged model.VLANState
	driver := &stubTextcfgDriver{
		readVLANState: func(context.Context) (model.VLANState, error) {
			if staged.VLANs != nil {
				return staged, nil
			}
			return (model.VLANState{PortCount: 8, VLANs: map[int]model.Vlan{}, PVIDs: map[int]int{}}).Normalize(), nil
		},
		applyVLANState: func(_ context.Context, desired model.VLANState) (gs108tv2.ApplyOutcome, error) {
			staged = desired
			return gs108tv2.ApplyOutcome{Staged: true, CanonicalDiverged: true}, nil
		},
	}
	data := newGS108Tv2TextcfgTestData(t, driver, struct {
		Host     string
		AgentMAC string
	}{Host: "http://192.0.2.20", AgentMAC: "8c:3b:ad:25:1b:88"})

	resp := createVLANState(t, data, nsdpVLANStatePlan())
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create over the composite failed: %v", resp.Diagnostics)
	}
	if !hasWarningWithSummary(resp.Diagnostics, "gs108tv2: the switch rewrote the staged configuration") {
		t.Fatalf("canonical divergence must add its own warning, diags = %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// nsdpV1Guard wording (post-milestone-3 truth).
// ---------------------------------------------------------------------------

type v1GuardStub struct{ *stubNSDPClient }

func (c v1GuardStub) IsV1() bool { return true }

func TestNSDPV1GuardWordingNamesTheTextConfigChannel(t *testing.T) {
	t.Parallel()

	err := nsdpV1Guard(v1GuardStub{&stubNSDPClient{}}, "Global switch settings (QoS mode, multicast blocking, mirroring)")
	if err == nil {
		t.Fatal("v1 clients must refuse guarded families")
	}
	var opErr *providerOperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("guard error = %v, want a typed providerOperationError", err)
	}
	detail := opErr.summary + " " + opErr.detail
	// Post-milestone-3 truth: VLAN management goes through the
	// text-config channel now.
	for _, want := range []string{
		"text-config channel",
		"netgear_plus_vlan_state",
		"is not supported on this switch over NSDP",
	} {
		if !strings.Contains(detail, want) {
			t.Fatalf("guard wording should contain %q, got: %q", want, detail)
		}
	}
	for _, stale := range []string{
		"will arrive through the switch's text-config transport",
	} {
		if strings.Contains(detail, stale) {
			t.Fatalf("guard wording still carries the stale pre-milestone promise %q: %s", stale, detail)
		}
	}
}

// ---------------------------------------------------------------------------
// netgear_plus_switch_config: canonical attribute.
// ---------------------------------------------------------------------------

func TestSwitchConfigDataSourceExposesCanonicalAttribute(t *testing.T) {
	t.Parallel()

	d := &switchConfigDataSource{}
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	if diags := schemaResp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatalf("schema validation returned errors: %v", diags)
	}

	canonical, ok := schemaResp.Schema.Attributes["canonical"]
	if !ok {
		t.Fatal("schema should expose the canonical attribute")
	}
	if !canonical.IsComputed() {
		t.Fatal("canonical must be computed")
	}
	if schemaResp.Schema.Attributes["content"] == nil {
		t.Fatal("schema should still expose content")
	}

	// The description must explain why content always changes between
	// reads (uptime line) while canonical is the stable comparand.
	description := canonical.(dschema.StringAttribute).Description
	if !strings.Contains(description, "Up Time") || !strings.Contains(description, "canonical") {
		t.Fatalf("canonical description should document the uptime-line discard, got: %q", description)
	}
}
