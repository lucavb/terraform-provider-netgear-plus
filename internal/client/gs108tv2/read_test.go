package gs108tv2

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/fastpath"
)

// ---------------------------------------------------------------------------
// ReadVLANState / ReadPortSettings: socket-gated (fake emweb switch, skip
// convention as the other fake tests) driver-side read tests.
// ---------------------------------------------------------------------------

// TestDriverReadVLANStateReflectsStagedStage: the startup-config read
// mirrors what the previous apply staged (running state is unreadable
// on this firmware); factory fixture reads back as the factory state.
func TestDriverReadVLANStateReflectsStagedState(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	// Factory fixture → factory state.
	state, err := d.ReadVLANState(ctx)
	if err != nil {
		t.Fatalf("ReadVLANState(factory): %v", err)
	}
	if !state.Equal(defaultState()) {
		t.Fatalf("factory read = %s, want %s", summariseVLANState(state), summariseVLANState(defaultState()))
	}

	// Stage vlan 42 → the NEXT fresh read must see it (no caching).
	if _, err := d.ApplyVLANState(ctx, stagedVlan42State()); err != nil {
		t.Fatalf("ApplyVLANState: %v", err)
	}
	state, err = d.ReadVLANState(ctx)
	if err != nil {
		t.Fatalf("ReadVLANState(staged): %v", err)
	}
	if !state.Equal(stagedVlan42State()) {
		t.Fatalf("staged read = %s, want %s", summariseVLANState(state), summariseVLANState(stagedVlan42State()))
	}
}

// TestDriverReadVLANStateFreshSave: back-to-back reads with an uptime
// restamp must not hit any byte cache — the up-time stamp moves and
// each read carries its own stamp.
func TestDriverReadVLANStateFreshSave(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	fake.restampUptime = true
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	// Reads carry no session requirement beyond the driver's;
	// SaveStartupConfig self-heals with fresh logins.
	first, err := d.ReadVLANState(ctx)
	if err != nil {
		t.Fatalf("ReadVLANState #1: %v", err)
	}
	if serr := d.Login(ctx); serr != nil {
		t.Fatalf("Login (session drop): %v", serr)
	}
	d.mu.Lock()
	d.session = nil // simulate a dead session between reads
	d.mu.Unlock()

	second, err := d.ReadVLANState(ctx)
	if err != nil {
		t.Fatalf("ReadVLANState #2: %v", err)
	}
	if !first.Equal(second) {
		t.Fatalf("reads disagree structurally: %s vs %s", summariseVLANState(first), summariseVLANState(second))
	}
}

// TestDriverReadVLANStateFailsClosedOnForeignGrammar: a config whose
// vlan database carries an unpinned `vlan` line fails the read with a
// typed grammar error — never a guess.
func TestDriverReadVLANStateFailsClosedOnForeignGrammar(t *testing.T) {
	raw := loadFactoryFixture(t)
	poisoned := strings.Replace(string(raw),
		"vlan database\n\nexit", "vlan database\n\nvlan 99 hybrid core\n\nexit", 1)
	fake := newFakeSwitch(t, "sekrit", []byte(poisoned))
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	_, err := d.ReadVLANState(ctx)
	if err == nil || !errors.As(err, new(*ErrGrammarLine)) {
		t.Fatalf("ReadVLANState(foreign grammar) error = %v, want a typed ErrGrammarLine", err)
	}
}

// TestDriverReadPortSettingsDefaultsAndFlowControl: factory config reads
// defaults; a staged flow-control port reads back enabled.
func TestDriverReadPortSettings(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	ports, err := d.ReadPortSettings(ctx)
	if err != nil {
		t.Fatalf("ReadPortSettings(factory): %v", err)
	}
	if want := DefaultPortSettingsMap(); !equalPortSettings(ports, want) {
		t.Fatalf("factory port read = %s, want defaults", describePortsDelta(want, ports))
	}

	desired := DefaultPortSettingsMap()
	p3 := desired[3]
	p3.FlowControl = true
	desired[3] = p3
	if _, err := d.ApplyPortSettings(ctx, desired); err != nil {
		t.Fatalf("ApplyPortSettings: %v", err)
	}
	ports, err = d.ReadPortSettings(ctx)
	if err != nil {
		t.Fatalf("ReadPortSettings(staged): %v", err)
	}
	if !equalPortSettings(ports, desired) {
		t.Fatalf("staged port read = %s, want %s", describePortsDelta(desired, ports), describePortsDelta(desired, desired))
	}
}

// TestDriverReadPortSettingsPassthrough: a foreign (non-port-grammar)
// line inside an interface body must not fail the port READ — foreign
// lines are preserved state, not managed grammar.
func TestDriverReadPortSettingsPassthrough(t *testing.T) {
	raw := loadFactoryFixture(t)
	seeded := withForeignLine(raw)
	fake := newFakeSwitch(t, "sekrit", seeded)
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	ports, err := d.ReadPortSettings(ctx)
	if err != nil {
		t.Fatalf("ReadPortSettings(foreign seed): %v", err)
	}
	if want := DefaultPortSettingsMap(); !equalPortSettings(ports, want) {
		t.Fatalf("port read = %s, want defaults (foreign line must not disturb)", describePortsDelta(want, ports))
	}
}

// TestDriverReadVLANStateAfterPortApply: the namespace symmetry — a
// port apply must not disturb the VLAN read (and vice versa).
func TestDriverReadVLANStateAfterPortApply(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	vlanWant := stagedVlan42State()
	if _, err := d.ApplyVLANState(ctx, vlanWant); err != nil {
		t.Fatalf("ApplyVLANState: %v", err)
	}
	ports := DefaultPortSettingsMap()
	p2 := ports[2]
	p2.FlowControl = true
	ports[2] = p2
	if _, err := d.ApplyPortSettings(ctx, ports); err != nil {
		t.Fatalf("ApplyPortSettings: %v", err)
	}

	state, err := d.ReadVLANState(ctx)
	if err != nil {
		t.Fatalf("ReadVLANState: %v", err)
	}
	if !state.Equal(vlanWant) {
		t.Fatalf("VLAN read after port apply = %s, want %s (namespace leak)", summariseVLANState(state), summariseVLANState(vlanWant))
	}
	readPorts, err := d.ReadPortSettings(ctx)
	if err != nil {
		t.Fatalf("ReadPortSettings: %v", err)
	}
	if !equalPortSettings(readPorts, ports) {
		t.Fatalf("port read drifted: %s", describePortsDelta(ports, readPorts))
	}
}

// TestDecodeOnceReadsAgree pins the "decode once, expose twice"
// invariant: one decodeTextConfig pass feeds both reads; they must
// never disagree on a healthy config.
func TestDecodeOnceReadsAgree(t *testing.T) {
	raw := loadFactoryFixture(t)
	staged := strings.Replace(string(raw),
		"vlan database\n\nexit", "vlan database\n\nvlan 42\n\nvlan 42 port 0/8 untagged\n\nexit", 1)
	staged = strings.Replace(staged, "interface 0/8\n\nexit", "interface 0/8\n\nvlan pvid 42\n\nexit", 1)

	tc, err := fastpath.ParseTextConfig([]byte(staged))
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}
	dec, err := decodeTextConfig(tc)
	if err != nil {
		t.Fatalf("decodeTextConfig: %v", err)
	}
	if !dec.State.Equal(stagedVlan42State()) {
		t.Fatalf("decode state = %s, want vlan-42 stage", summariseVLANState(dec.State))
	}
	if want := DefaultPortSettingsMap(); !equalPortSettings(dec.Ports, want) {
		t.Fatalf("decode ports = %s, want defaults", describePortsDelta(want, dec.Ports))
	}
}
