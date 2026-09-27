package gs108tv2

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/fastpath"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// The socket-gated tests below use the stateful fake emweb switch
// (fakeserver_test.go) and skip, with the same convention as
// internal/fastpath/web_test.go, when the sandbox denies loopback TCP
// — they remain meaningful on the casalta runner.

func newFakeDriver(t *testing.T, srvURL string, tweak func(*Config)) *Driver {
	t.Helper()
	cfg := fastDriverConfig(t, srvURL)
	if tweak != nil {
		tweak(&cfg)
	}
	return New(cfg)
}

// withForeignLine seeds the fake's stored config with a foreign body
// line inside interface 0/3 (the no-caching test's marker).
func withForeignLine(raw []byte) []byte {
	return []byte(strings.Replace(string(raw),
		"interface 0/3\n\nexit", "interface 0/3\n\nno snmp trap link-status\n\nexit", 1))
}

// TestDriverSaveFingerprintFacts: fresh-save semantics, canonical
// fingerprint stability across uptime restamps and facts extraction.
func TestDriverSaveFingerprintFacts(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	// Restamp OFF for the first save: its subject is byte-identity
	// with the fixture; the up-time line sits BEFORE the vlan
	// database label, so a restamp is a legitimate byte difference
	// (the fake historically zeroed the stamp on every fetch).
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	if err := d.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	got, err := d.SaveStartupConfig(ctx)
	if err != nil {
		t.Fatalf("SaveStartupConfig: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("first save is not the fixture bytes")
	}
	// Second save, with the wall-clock stamping on: the bytes differ
	// in the up-time stamp alone, canonically they are identical.
	fake.setRestamp(true)
	got2, err := d.SaveStartupConfig(ctx)
	if err != nil {
		t.Fatalf("SaveStartupConfig #2: %v", err)
	}
	if bytes.Equal(got, got2) {
		t.Fatal("fake did not restamp the uptime line")
	}
	tc1, _ := fastpath.ParseTextConfig(got)
	tc2, _ := fastpath.ParseTextConfig(got2)
	if tc1.Fingerprint() != tc2.Fingerprint() {
		t.Fatal("fingerprints differ across an uptime-only restamp")
	}

	facts, err := d.ReadSwitchFacts(ctx)
	if err != nil {
		t.Fatalf("ReadSwitchFacts: %v", err)
	}
	if facts.Model != "gs108tv2" {
		t.Errorf("Model = %q", facts.Model)
	}
	if facts.FirmwareVersion != "5.4.2.36" {
		t.Errorf("FirmwareVersion = %q", facts.FirmwareVersion)
	}
	if facts.MACAddress != "8c:3b:ad:2c:e9:7d" {
		t.Errorf("MACAddress = %q", facts.MACAddress)
	}
	if facts.SerialNumber != "" || facts.BootloaderVersion != "" || facts.SwitchName != "" {
		t.Errorf("channel-limited facts must stay empty: %+v", facts)
	}
}

// TestApplyVLANStateStagesAndVerifies: desired states stage, converge,
// and the fake's stored config parses back to the desired state,
// with the fingerprint moving.
func TestApplyVLANStateStagesAndVerifies(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	fake.restampUptime = true
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	preFp, err := d.Fingerprint(ctx)
	if err != nil {
		t.Fatalf("Fingerprint(pre): %v", err)
	}

	desired := stagedVlan42State()
	outcome, err := d.ApplyVLANState(ctx, desired)
	if err != nil {
		t.Fatalf("ApplyVLANState: %v", err)
	}
	if !outcome.Staged {
		t.Fatal("apply did not converge to staged")
	}
	if outcome.CanonicalDiverged {
		t.Fatal("canonical diverged on a clean fake (restamp only affects the excluded line)")
	}

	stored := fake.storedConfig()
	tc, err := fastpath.ParseTextConfig(stored)
	if err != nil {
		t.Fatalf("ParseTextConfig(stored): %v", err)
	}
	dec, err := decodeTextConfig(tc)
	if err != nil {
		t.Fatalf("decodeTextConfig(stored): %v", err)
	}
	if !dec.State.Equal(desired) {
		t.Fatalf("stored config state = %s, want %s", summariseVLANState(dec.State), summariseVLANState(desired))
	}
	postFp, err := d.Fingerprint(ctx)
	if err != nil {
		t.Fatalf("Fingerprint(post): %v", err)
	}
	if postFp == preFp {
		t.Fatal("fingerprint did not change after staging vlan 42")
	}
	// Uptime restamps never move the fingerprint.
	fake2Fp := tc.Fingerprint()
	if postFp != fake2Fp {
		t.Fatalf("fingerprint(%s) != stored fingerprint(%s)", postFp, fake2Fp)
	}
}

// TestApplyNoOpShortCircuits: applying the already-satisfied state
// returns Staged WITHOUT a restore POST (idempotence: reboot-retry
// friendliness and cheap no-ops — the byte-identity of the would-be
// upload is pinned pure in TestRenderDefaultStateByteIdentical).
func TestApplyNoOpShortCircuits(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	// No restamping needed: nothing must hit the wire at all.
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	outcome, err := d.ApplyVLANState(ctx, defaultState())
	if err != nil {
		t.Fatalf("ApplyVLANState(default): %v", err)
	}
	if !outcome.Staged || outcome.CanonicalDiverged {
		t.Fatalf("outcome = %+v, want Staged with no divergence", outcome)
	}
	_, _, _, restores := fake.counters()
	if restores != 0 {
		t.Fatalf("no-op apply performed %d restore POSTs, want 0 (short-circuit)", restores)
	}
	if uploads := fake.recordedUploads(); len(uploads) != 0 {
		t.Fatalf("no-op apply uploaded %d times, want 0", len(uploads))
	}
	if !bytes.Equal(fake.storedConfig(), raw) {
		t.Fatal("stored config changed during a no-op apply")
	}
}

// TestApplyByteConfinement: the upload differs from the pre-apply
// bytes ONLY inside vlan database / interface 0/x bodies — the
// configure preamble and interface 3/x are byte-identical.
func TestApplyByteConfinement(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	if _, err := d.ApplyVLANState(ctx, stagedVlan42State()); err != nil {
		t.Fatalf("ApplyVLANState: %v", err)
	}
	uploads := fake.recordedUploads()
	if len(uploads) == 0 {
		t.Fatal("no upload recorded")
	}
	upload := uploads[len(uploads)-1]

	// Region helpers over raw bytes.
	lineOffset := func(needle string) int {
		lines := strings.Split(string(raw), "\n")
		off := 0
		for _, l := range lines {
			if strings.TrimRight(l, "\r") == needle {
				return off
			}
			off += len(l) + 1
		}
		return -1
	}
	mainStart := lineOffset("vlan database")
	mainEnd := lineOffset("interface 3/1")
	if mainStart < 0 || mainEnd < 0 {
		t.Fatalf("fixture anchors missing: %d %d", mainStart, mainEnd)
	}
	if !bytes.Equal(raw[:mainStart], upload[:mainStart]) {
		t.Fatal("bytes before vlan database changed")
	}
	if !bytes.Equal(raw[mainEnd:], upload[len(upload)-(len(raw)-mainEnd):]) {
		t.Fatal("bytes from interface 3/1 onward changed")
	}
	middle := upload[mainStart : len(upload)-(len(raw)-mainEnd)]
	if !strings.Contains(string(middle), "\nvlan 42\n") || !strings.Contains(string(middle), "vlan 42 port 0/8 untagged") || !strings.Contains(string(middle), "vlan pvid 42") {
		t.Fatalf("managed region did not carry the staged content:\n%s", string(middle))
	}
}

// TestApplyRidesOutTransientWindow: refused logins and a mangled
// mid-ingest fetch never surface as errors, and the loop converges.
func TestApplyRidesOutTransientWindow(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	fake.restampUptime = true
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	if _, err := d.ApplyVLANState(ctx, defaultState()); err != nil {
		t.Fatalf("baseline apply: %v", err)
	}

	// Arm the window for the next apply: 2 refused logins + 1 mangled
	// fetch (the fake only arms after a restore landed).
	fake.armWindow(2, 1)
	outcome, err := d.ApplyVLANState(ctx, stagedVlan42State())
	if err != nil {
		t.Fatalf("ApplyVLANState through transient window: %v", err)
	}
	if !outcome.Staged {
		t.Fatal("did not converge after the window")
	}
	logins, refuses, mangles, restores := fake.counters()
	if refuses != 2 || mangles != 1 {
		t.Fatalf("window not exercised: refuses=%d mangles=%d (logins=%d restores=%d)", refuses, mangles, logins, restores)
	}
}

// TestApplyDeadlineExhausted: a window that never clears ends in the
// typed deadline error naming the last failure class.
func TestApplyDeadlineExhausted(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	srv := fake.start(t)
	ctx := context.Background()
	// The baseline applies first so the window arming gate passes;
	// then a huge refusal budget outlasts the deadline.
	d := newFakeDriver(t, srv.URL, func(c *Config) {
		c.RestoreWaitTimeout = 200 * time.Millisecond
	})
	if _, err := d.ApplyVLANState(ctx, defaultState()); err != nil {
		t.Fatalf("baseline apply: %v", err)
	}

	fake.armWindow(1000, 0)
	_, err := d.ApplyVLANState(ctx, stagedVlan42State())
	if err == nil {
		t.Fatal("apply converged despite a permanently refused window")
	}
	var deadlineErr *ErrRestoreDeadline
	if !errors.As(err, &deadlineErr) {
		t.Fatalf("error = %T (%v), want *ErrRestoreDeadline", err, err)
	}
	if deadlineErr.LastClass != "login" {
		t.Fatalf("LastClass = %q, want login", deadlineErr.LastClass)
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("deadline error lost the whole-window note: %v", err)
	}
}

// TestApplyInterleavedFreshSave: two applies back to back with flat
// driver config — B's upload builds on A's staged bytes (fresh
// SaveConfig, no caching).
func TestApplyInterleavedFreshSave(t *testing.T) {
	raw := loadFactoryFixture(t)
	foreign := withForeignLine(raw)
	fake := newFakeSwitch(t, "sekrit", foreign)
	// No restamping: the test compares preamble bytes across applies
	// (up-time difference would undermine the byte comparisons).
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	if _, err := d.ApplyVLANState(ctx, stagedVlan42State()); err != nil {
		t.Fatalf("apply A: %v", err)
	}
	aStored := fake.storedConfig()

	// B: vlan 30 added on top of A's staging (port 5 moves to VLAN 30:
	// its VLAN 1 membership follows the PVID to ignored).
	desiredB := stagedVlan42State()
	desiredB.VLANs[30] = model.Vlan{ID: 30, Ports: map[int]model.PortMembership{
		5: model.PortMembershipUntagged,
	}}
	desiredB.VLANs[1].Ports[5] = model.PortMembershipIgnored
	desiredB.PVIDs[5] = 30
	_, err := d.ApplyVLANState(ctx, desiredB)
	if err != nil {
		t.Fatalf("apply B: %v", err)
	}

	uploads := fake.recordedUploads()
	if len(uploads) < 2 {
		t.Fatalf("expected at least 2 uploads, got %d", len(uploads))
	}
	bUpload := uploads[len(uploads)-1]
	// Fresh-save proof: the foreign line only exists in the switch's
	// storage (put there before A applied); a cached factory parse as
	// base would drop it.
	if !strings.Contains(string(bUpload), "no snmp trap link-status") {
		t.Fatal("B's upload lost the foreign line — driver cached or used factory bytes as base")
	}
	// A's staged content survives into B's upload base.
	if !strings.Contains(string(bUpload), "vlan 42 port 0/8 untagged") {
		t.Fatal("B's upload lost A's staging (vlan 42)")
	}
	// The final stored state is exactly B's desired.
	stored := fake.storedConfig()
	tc, err := fastpath.ParseTextConfig(stored)
	if err != nil {
		t.Fatalf("ParseTextConfig(stored): %v", err)
	}
	dec, err := decodeTextConfig(tc)
	if err != nil {
		t.Fatalf("decodeTextConfig(stored): %v", err)
	}
	if !dec.State.Equal(desiredB) {
		t.Fatalf("final state = %s, want B desired", summariseVLANState(dec.State))
	}
	// The base of B's apply was A's storage (prefix identity).
	baseLimit := strings.Index(string(aStored), "vlan database")
	if baseLimit < 0 || string(bUpload[:baseLimit]) != string(aStored[:baseLimit]) {
		t.Fatal("B's upload does not extend A's staged bytes")
	}
}

// TestApplyDetectsStructuralDrift: the fake accepts the upload but
// keeps serving its old (already-valid) config — that parses cleanly
// to the WRONG state, which is drift, distinct from transient errors.
func TestApplyDetectsStructuralDrift(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	fake.restampUptime = true
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, func(c *Config) {
		c.RestoreWaitTimeout = 500 * time.Millisecond
	})

	ignoreUpload := func(_ []byte) []byte { return raw }
	fake.mutateOnStore = ignoreUpload

	_, err := d.ApplyVLANState(ctx, stagedVlan42State())
	if err == nil {
		t.Fatal("apply did not notice the drift")
	}
	var drift *ErrDriftDetected
	if !errors.As(err, &drift) {
		t.Fatalf("error = %T (%v), want *ErrDriftDetected", err, err)
	}
	var deadline *ErrRestoreDeadline
	if errors.As(err, &deadline) {
		t.Fatal("drift misclassified as deadline/transient")
	}
	if !strings.Contains(err.Error(), "vlan") {
		t.Fatalf("drift detail lost the state digest: %v", err)
	}
}

// TestApplyCanonicalDivergenceWarning: a switch-side normalizer
// rewrite (fake drops a byte from the stored config body) must not
// fail the apply — Staged stays true with the divergence surfaced.
func TestApplyCanonicalDivergenceWarning(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	// Rewrite the stored file ever so slightly (extra annotation line
	// at EOF), simulating a switch-side normalization: state equal,
	// canonical bytes different.
	normalized := func(in []byte) []byte {
		if !bytes.HasSuffix(in, []byte("\n")) {
			in = append(in, '\n')
		}
		return append(in, []byte("!\n")...)
	}
	fake.mutateOnStore = normalized

	outcome, err := d.ApplyVLANState(ctx, stagedVlan42State())
	if err != nil {
		t.Fatalf("ApplyVLANState: %v", err)
	}
	if !outcome.Staged {
		t.Fatal("normalized config should still stage")
	}
	if !outcome.CanonicalDiverged {
		t.Fatal("canonical divergence not surfaced")
	}
}

// stagedVlan42State: VLAN 42 untagged on port 8 (PVID 42 there),
// everything else factory defaults.
func stagedVlan42State() model.VLANState {
	pvids := map[int]int{1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 42}
	vlans := map[int]map[int]model.PortMembership{
		1:  untagged(1, 2, 3, 4, 5, 6, 7),
		42: untagged(8),
	}
	return mkState(vlans, pvids)
}

// ---------------------------------------------------------------------------
// F2b additions: port settings + reboot
// ---------------------------------------------------------------------------

// seedIfaceBodies splices one interface body via the fastpath editor
// (used to seed the fake with pre-existing vlan pvid / foreign lines).
func seedIfaceBodies(t *testing.T, raw []byte, bodies map[string][]string) []byte {
	t.Helper()
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		t.Fatalf("ParseTextConfig(seed): %v", err)
	}
	editor, err := fastpath.NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor(seed): %v", err)
	}
	for label, body := range bodies {
		if err := editor.ReplaceSectionBody(label, body); err != nil {
			t.Fatalf("seed %s: %v", label, err)
		}
	}
	out, err := editor.Render()
	if err != nil {
		t.Fatalf("seed render: %v", err)
	}
	return out
}

// TestApplyPortSettingsStagesAndPreserves: flow control on port 3,
// shutdown on port 5 — PVID lines and foreign lines survive with the
// VLAN state untouched, and the region discipline holds (configure
// preamble and interface 3/x byte-identical).
func TestApplyPortSettingsStagesAndPreserves(t *testing.T) {
	raw := loadFactoryFixture(t)
	seeded := seedIfaceBodies(t, raw, map[string][]string{
		"interface 0/8": {"vlan pvid 42"},
		"interface 0/3": {"no snmp trap link-status"},
	})
	fake := newFakeSwitch(t, "sekrit", seeded)
	// NO restamp: the byte-confinement assertions compare preamble
	// bytes against the seeded fixture, and the up-time annotation
	// lives in that preamble (test-bug from the first socket run).
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	// Reference VLAN state of the seeded config (pvid 42 on port 8
	// moves VLAN 1's membership there to ignored by inference).
	seedTC, err := fastpath.ParseTextConfig(seeded)
	if err != nil {
		t.Fatalf("ParseTextConfig(seeded): %v", err)
	}
	seedDec, err := decodeTextConfig(seedTC)
	if err != nil {
		t.Fatalf("decodeTextConfig(seeded): %v", err)
	}

	desired := DefaultPortSettingsMap()
	p3 := desired[3]
	p3.FlowControl = true
	desired[3] = p3
	p5 := desired[5]
	p5.Enabled = false
	desired[5] = p5

	outcome, err := d.ApplyPortSettings(ctx, desired)
	if err != nil {
		t.Fatalf("ApplyPortSettings: %v", err)
	}
	if !outcome.Staged {
		t.Fatal("port apply did not stage")
	}

	stored := fake.storedConfig()
	if !strings.Contains(string(stored), "interface 0/5\n\nshutdown\n\nexit") {
		t.Fatalf("port 5 not shut down:\n%s", sectionSnippet(t, stored, "interface 0/5"))
	}
	if !strings.Contains(string(stored), "interface 0/3\n\nno snmp trap link-status\n\nflow control\n\nexit") {
		t.Fatalf("port 3 body wrong (foreign line must precede flow control):\n%s", sectionSnippet(t, stored, "interface 0/3"))
	}
	if !strings.Contains(string(stored), "interface 0/8\n\nvlan pvid 42\n\nexit") {
		t.Fatalf("vlan pvid line not preserved:\n%s", sectionSnippet(t, stored, "interface 0/8"))
	}
	if !strings.Contains(string(stored), "interface 0/1\n\nexit") {
		t.Fatalf("default port 1 mutated:\n%s", sectionSnippet(t, stored, "interface 0/1"))
	}

	storedTC, err := fastpath.ParseTextConfig(stored)
	if err != nil {
		t.Fatalf("ParseTextConfig(stored): %v", err)
	}
	storedDec, err := decodeTextConfig(storedTC)
	if err != nil {
		t.Fatalf("decodeTextConfig(stored): %v", err)
	}
	if !storedDec.State.Equal(seedDec.State) {
		t.Fatalf("VLAN state changed across a port apply: %s vs %s",
			summariseVLANState(storedDec.State), summariseVLANState(seedDec.State))
	}
	if !equalPortSettings(storedDec.Ports, desired) {
		t.Fatalf("port settings drifted: want desired, got delta %s", describePortsDelta(desired, storedDec.Ports))
	}

	// Virtual preamble + interface 3/x untouched, and the VLAN
	// database body untouched (the port codec does not own it).
	lineOffset := func(needle string) int {
		lines := strings.Split(string(seeded), "\n")
		off := 0
		for _, l := range lines {
			if strings.TrimRight(l, "\r") == needle {
				return off
			}
			off += len(l) + 1
		}
		return -1
	}
	mainStart := lineOffset("vlan database")
	mainEnd := lineOffset("interface 3/1")
	if !bytes.Equal(stored[:mainStart], seeded[:mainStart]) {
		t.Fatal("preamble bytes changed across a port apply")
	}
	if !bytes.Equal(stored[len(stored)-(len(seeded)-mainEnd):], seeded[mainEnd:]) {
		t.Fatal("interface 3/x bytes changed across a port apply")
	}
	// The vlan database + configure region must be untouched by the
	// port codec: nothing before interface 0/1's body changes, so the
	// byte span between anchors (in each file's own coordinates) is
	// byte-identical.
	storedIface1 := lineOffsetIn(stored, "interface 0/1")
	seededIface1 := lineOffset("interface 0/1")
	if !bytes.Equal(stored[mainStart:storedIface1], seeded[mainStart:seededIface1]) {
		t.Fatal("vlan database / configure region changed across a port apply")
	}
}

func lineOffsetIn(raw []byte, needle string) int {
	lines := strings.Split(string(raw), "\n")
	off := 0
	for _, l := range lines {
		if strings.TrimRight(l, "\r") == needle {
			return off
		}
		off += len(l) + 1
	}
	return -1
}

// TestApplyNamespaceInterleaving: VLAN→port→VLAN→port — each codec
// must pass the other's lines through untouched.
func TestApplyNamespaceInterleaving(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	// 1. VLAN: stage vlan 42 (untagged port 8, PVID 42 there).
	vlanA := stagedVlan42State()
	if _, err := d.ApplyVLANState(ctx, vlanA); err != nil {
		t.Fatalf("vlan apply A: %v", err)
	}

	// 2. Port: flow control on port 2 — vlan 42 must survive.
	portsA := DefaultPortSettingsMap()
	p2 := portsA[2]
	p2.FlowControl = true
	portsA[2] = p2
	if _, err := d.ApplyPortSettings(ctx, portsA); err != nil {
		t.Fatalf("port apply A: %v", err)
	}
	mid := fake.storedConfig()
	if !strings.Contains(string(mid), "vlan 42 port 0/8 untagged") || !strings.Contains(string(mid), "vlan pvid 42") {
		t.Fatal("vlan lines lost across a port apply")
	}
	if !strings.Contains(string(mid), "interface 0/2\n\nflow control\n\nexit") {
		t.Fatalf("port line missing:\n%s", sectionSnippet(t, mid, "interface 0/2"))
	}

	// 3. VLAN: add vlan 30 untagged port 7 (PVID 7 → 30) — the flow
	// control line must survive the VLAN render.
	vlanB := vlanA.Clone()
	vlanB.VLANs[30] = model.Vlan{ID: 30, Ports: map[int]model.PortMembership{
		1: model.PortMembershipIgnored, 2: model.PortMembershipIgnored, 3: model.PortMembershipIgnored,
		4: model.PortMembershipIgnored, 5: model.PortMembershipIgnored, 6: model.PortMembershipIgnored,
		7: model.PortMembershipUntagged, 8: model.PortMembershipIgnored,
	}}
	vlanB.VLANs[1].Ports[7] = model.PortMembershipIgnored
	vlanB.PVIDs[7] = 30
	if _, err := d.ApplyVLANState(ctx, vlanB); err != nil {
		t.Fatalf("vlan apply B: %v", err)
	}
	after := fake.storedConfig()
	if !strings.Contains(string(after), "interface 0/2\n\nflow control\n\nexit") {
		t.Fatalf("port line lost across a VLAN apply:\n%s", sectionSnippet(t, after, "interface 0/2"))
	}
	if !strings.Contains(string(after), "vlan pvid 30") || strings.Contains(string(after), "vlan pvid 7") {
		t.Fatal("pvid rerender wrong")
	}

	// 4. Port: back to factory defaults — vlan lines survive again.
	if _, err := d.ApplyPortSettings(ctx, DefaultPortSettingsMap()); err != nil {
		t.Fatalf("port apply B: %v", err)
	}
	final := fake.storedConfig()
	if strings.Contains(string(final), "flow control") {
		t.Fatal("flow control line survived the default port apply")
	}
	if !strings.Contains(string(final), "vlan 42 port 0/8 untagged") || !strings.Contains(string(final), "vlan 30 port 0/7 untagged") {
		t.Fatal("vlan lines lost across the default port apply")
	}
	storedTC, err := fastpath.ParseTextConfig(final)
	if err != nil {
		t.Fatalf("ParseTextConfig(final): %v", err)
	}
	dec, err := decodeTextConfig(storedTC)
	if err != nil {
		t.Fatalf("decodeTextConfig(final): %v", err)
	}
	portsWant := DefaultPortSettingsMap()
	if !equalPortSettings(dec.Ports, portsWant) {
		t.Fatalf("final ports = %s", describePortsDelta(portsWant, dec.Ports))
	}
	if !dec.State.Equal(vlanB) {
		t.Fatalf("final vlan state = %s, want B", summariseVLANState(dec.State))
	}
}

// TestApplyPortSettingsShortCircuits: re-applying the same port map
// (and an already-staged vlan state) must not hit the wire.
func TestApplyPortSettingsShortCircuits(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	outcome, err := d.ApplyPortSettings(ctx, DefaultPortSettingsMap())
	if err != nil {
		t.Fatalf("ApplyPortSettings(default): %v", err)
	}
	if !outcome.Staged {
		t.Fatal("port apply did not stage")
	}
	_, _, _, restores := fake.counters()
	if restores != 0 {
		t.Fatalf("no-op port apply performed %d restore POSTs", restores)
	}
}

// TestApplyPortSettingsCapabilityRefusal: non-default values for
// unsupported attributes are refused before any upload; the default
// value is accepted (absence render → short-circuit, no wire traffic).
func TestApplyPortSettingsCapabilityRefusal(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	desired := DefaultPortSettingsMap()
	p2 := desired[2]
	p2.QoSPriority = "high"
	desired[2] = p2
	_, err := d.ApplyPortSettings(ctx, desired)
	if err == nil {
		t.Fatal("qos_priority high accepted despite Unsupported capability")
	}
	var refused *ErrUnsupportedAttribute
	if !errors.As(err, &refused) {
		t.Fatalf("error = %T (%v), want *ErrUnsupportedAttribute", err, err)
	}
	if refused.Attribute != "qos_priority" || refused.Value != "high" || refused.Port != 2 {
		t.Fatalf("refusal details = %+v", refused)
	}
	if _, _, _, restores := fake.counters(); restores != 0 {
		t.Fatal("refused apply still posted a restore")
	}

	// Default value passes: accepted (short-circuits as no upload).
	p2 = DefaultPortSettings()
	desired[2] = p2
	outcome, err := d.ApplyPortSettings(ctx, desired)
	if err != nil {
		t.Fatalf("default-value apply: %v", err)
	}
	if !outcome.Staged {
		t.Fatal("default-value apply did not stage")
	}
	if _, _, _, restores := fake.counters(); restores != 0 {
		t.Fatal("default-value apply posted a restore")
	}
}

// TestRebootAndWaitHappyPath: reboot POST, down-window refusals ride
// out, up-time resets, the staged file survives with its fingerprint.
func TestRebootAndWaitHappyPath(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, func(c *Config) {
		c.RebootWaitTimeout = 2 * time.Second
		c.RebootPollInterval = 5 * time.Millisecond
	})

	RebootEndpoint = "/base/system/reboot.html"
	t.Cleanup(func() { RebootEndpoint = "" })

	// Stage something first: the reboot must preserve IT.
	if _, err := d.ApplyVLANState(ctx, stagedVlan42State()); err != nil {
		t.Fatalf("stage before reboot: %v", err)
	}
	stagedFp, err := d.Fingerprint(ctx)
	if err != nil {
		t.Fatalf("Fingerprint(pre-reboot): %v", err)
	}

	fake.armReboot(2, true, nil)
	outcome, err := d.RebootAndWait(ctx)
	if err != nil {
		t.Fatalf("RebootAndWait: %v", err)
	}
	if !outcome.Rebooted || !outcome.UptimeReset {
		t.Fatalf("outcome = %+v", outcome)
	}
	if outcome.Fingerprint != stagedFp {
		t.Fatalf("fingerprint = %s, want staged %s", outcome.Fingerprint, stagedFp)
	}
	rebootCount, _ := fake.rebootStats()
	if rebootCount != 1 {
		t.Fatalf("reboot POSTs = %d, want 1", rebootCount)
	}
}

// TestRebootSentinelRefusals: no endpoint pinned → typed refusal and
// zero HTTP traffic.
func TestRebootSentinelRefusals(t *testing.T) {
	if RebootEndpoint != "" {
		t.Fatal("precondition: RebootEndpoint must be empty by default")
	}
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, nil)

	outcome, err := d.RebootAndWait(ctx)
	if err == nil {
		t.Fatal("RebootAndWait proceeded without a pinned endpoint")
	}
	var refused *ErrRebootUnavailable
	if !errors.As(err, &refused) {
		t.Fatalf("error = %T (%v), want *ErrRebootUnavailable", err, err)
	}
	if !strings.Contains(err.Error(), "phase 0b") {
		t.Fatalf("sentinel error lost the actionable text: %v", err)
	}
	_ = outcome
	logins, _, _, restores := fake.counters()
	if logins != 0 || restores != 0 {
		t.Fatalf("sentinel refusal still produced HTTP traffic (logins=%d restores=%d)", logins, restores)
	}
}

// TestRebootDeadline: a reboot window that never clears ends in the
// typed deadline error.
func TestRebootDeadline(t *testing.T) {
	raw := loadFactoryFixture(t)
	fake := newFakeSwitch(t, "sekrit", raw)
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, func(c *Config) {
		c.RebootWaitTimeout = 150 * time.Millisecond
		c.RebootPollInterval = 5 * time.Millisecond
	})
	RebootEndpoint = "/base/system/reboot.html"
	t.Cleanup(func() { RebootEndpoint = "" })

	fake.armReboot(1000, false, nil)
	_, err := d.RebootAndWait(ctx)
	if err == nil {
		t.Fatal("reboot converged despite the endless refuse budget")
	}
	var deadlineErr *ErrRebootDeadline
	if !errors.As(err, &deadlineErr) {
		t.Fatalf("error = %T (%v), want *ErrRebootDeadline", err, err)
	}
	if deadlineErr.LastClass != "conn" {
		t.Fatalf("LastClass = %q, want conn (refused connections)", deadlineErr.LastClass)
	}
}

// TestRebootFileDrift: the stored config swap across the reboot is a
// typed error — staged content must survive.
func TestRebootFileDrift(t *testing.T) {
	raw := loadFactoryFixture(t)
	seeded := withForeignLine(raw)
	fake := newFakeSwitch(t, "sekrit", seeded)
	srv := fake.start(t)
	ctx := context.Background()
	d := newFakeDriver(t, srv.URL, func(c *Config) {
		c.RebootWaitTimeout = 2 * time.Second
		c.RebootPollInterval = 5 * time.Millisecond
	})
	RebootEndpoint = "/base/system/reboot.html"
	t.Cleanup(func() { RebootEndpoint = "" })

	fake.armReboot(0, true, raw)
	_, err := d.RebootAndWait(ctx)
	if err == nil {
		t.Fatal("config drift across reboot not detected")
	}
	var drift *ErrRebootConfigDrift
	if !errors.As(err, &drift) {
		t.Fatalf("error = %T (%v), want *ErrRebootConfigDrift", err, err)
	}
}
