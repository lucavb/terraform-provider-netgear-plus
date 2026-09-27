package gs108tv2

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/fastpath"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// loadFactoryFixture reads the ground-truth factory export (the same
// mirror the fastpath package tests use).
func loadFactoryFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../../startup-config-gs108t")
	if err != nil {
		t.Skipf("startup-config-gs108t not present: %v", err)
	}
	return data
}

// mkState builds a normalized-shape state: missing memberships are
// ignored, missing PVIDs error at encode time.
func mkState(vlans map[int]map[int]model.PortMembership, pvids map[int]int) model.VLANState {
	s := model.VLANState{PortCount: defaultPortCount, VLANs: map[int]model.Vlan{}, PVIDs: map[int]int{}}
	for vid, ports := range vlans {
		pm := map[int]model.PortMembership{}
		for p := 1; p <= defaultPortCount; p++ {
			if m, ok := ports[p]; ok {
				pm[p] = m
			} else {
				pm[p] = model.PortMembershipIgnored
			}
		}
		s.VLANs[vid] = model.Vlan{ID: vid, Ports: pm}
	}
	for p := 1; p <= defaultPortCount; p++ {
		s.PVIDs[p] = pvids[p]
	}
	return s
}

func untagged(ps ...int) map[int]model.PortMembership {
	out := map[int]model.PortMembership{}
	for _, p := range ps {
		out[p] = model.PortMembershipUntagged
	}
	return out
}

// defaultState is the normalized factory state: VLAN 1 untagged
// everywhere, PVID 1 everywhere.
func defaultState() model.VLANState {
	vlans := map[int]map[int]model.PortMembership{}
	v1 := map[int]model.PortMembership{}
	for p := 1; p <= defaultPortCount; p++ {
		v1[p] = model.PortMembershipUntagged
	}
	vlans[1] = v1
	pvids := map[int]int{}
	for p := 1; p <= defaultPortCount; p++ {
		pvids[p] = defaultPVID
	}
	return mkState(vlans, pvids)
}

// --- pure codec tests (no sockets) ---

// TestDecodeFactoryDefaultState: the factory file's defaults are
// implicit by absence — empty vlan database and empty interface bodies
// decode to VLAN 1 all-untagged with PVID 1s.
func TestDecodeFactoryDefaultState(t *testing.T) {
	raw := loadFactoryFixture(t)
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}
	dec, err := decodeTextConfig(tc)
	if err != nil {
		t.Fatalf("decodeTextConfig: %v", err)
	}
	want := defaultState()
	if !dec.State.Equal(want) {
		t.Fatalf("decoded state = %s, want default %s", summariseVLANState(dec.State), summariseVLANState(want))
	}
	if len(dec.Foreign["vlan database"]) != 0 && len(dec.Foreign[fmt.Sprintf("interface 0/%d", defaultPortCount)]) != 0 {
		t.Fatalf("factory file unexpectedly carries foreign lines: %v", dec.Foreign)
	}
}

// TestRenderDefaultStateByteIdentical: rendering the default state over
// the factory file reproduces the factory bytes exactly (no-op apply
// friendliness) and never touches interface 3/x.
func TestRenderDefaultStateByteIdentical(t *testing.T) {
	raw := loadFactoryFixture(t)
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}
	editor, err := fastpath.NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	upload, err := renderVLANState(editor, defaultState().Normalize(), captureForeign(tc))
	if err != nil {
		t.Fatalf("renderVLANState: %v", err)
	}
	if string(upload) != string(raw) {
		t.Fatal("default-state render is not byte-identical to the factory file")
	}
	if !strings.Contains(string(upload), "voip oui 00:1B:4F desc AVAYA2") {
		t.Fatal("configure preamble lost")
	}
}

// TestCodecRoundTripStagedConfig: declare vlan 42 (untagged member on
// port 8, PVID 42 there) and round-trip decode→render→decode.
func TestCodecRoundTripStagedConfig(t *testing.T) {
	raw := loadFactoryFixture(t)
	pvids := map[int]int{1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 42}
	desired := mkState(
		map[int]map[int]model.PortMembership{
			1:  untagged(1, 2, 3, 4, 5, 6, 7),
			42: untagged(8),
		},
		pvids,
	)
	roundTripState(t, raw, desired)

	// Interleaved-apply shape: B adds vlan 30 on port 5 while keeping
	// A's vlan 42 (port 5's VLAN 1 membership follows the PVID).
	bState := mkState(
		map[int]map[int]model.PortMembership{
			1:  untagged(1, 2, 3, 4, 6, 7),
			42: untagged(8),
			30: untagged(5),
		},
		map[int]int{1: 1, 2: 1, 3: 1, 4: 1, 5: 30, 6: 1, 7: 1, 8: 42},
	)
	roundTripState(t, []byte(string(raw)), bState)
}

func roundTripState(t *testing.T, raw []byte, desired model.VLANState) {
	t.Helper()
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}
	editor, err := fastpath.NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	upload, err := renderVLANState(editor, desired.Normalize(), captureForeign(tc))
	if err != nil {
		t.Fatalf("renderVLANState: %v", err)
	}
	tc2, err := fastpath.ParseTextConfig(upload)
	if err != nil {
		t.Fatalf("ParseTextConfig(rendered): %v", err)
	}
	dec2, err := decodeTextConfig(tc2)
	if err != nil {
		t.Fatalf("decodeTextConfig(rendered): %v", err)
	}
	if !dec2.State.Equal(desired) {
		t.Fatalf("round trip lost state: got %s, want %s", summariseVLANState(dec2.State), summariseVLANState(desired))
	}
}

// TestCodecFailClosedUnknownVLANLine: a `vlan `-prefixed line that
// matches no template is a typed ErrGrammarLine quoting the line.
func TestCodecFailClosedUnknownVLANLine(t *testing.T) {
	raw := loadFactoryFixture(t)
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}
	editor, err := fastpath.NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	if err := editor.ReplaceSectionBody("vlan database", []string{"vlan bogus 7"}); err != nil {
		t.Fatalf("ReplaceSectionBody: %v", err)
	}
	mutated, err := editor.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	tc2, err := fastpath.ParseTextConfig(mutated)
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}
	_, derr := decodeTextConfig(tc2)
	if derr == nil {
		t.Fatal("decode accepted an unpinned vlan line")
	}
	var grammarErr *ErrGrammarLine
	if !errors.As(derr, &grammarErr) {
		t.Fatalf("error = %T (%v), want *ErrGrammarLine", err, err)
	}
	if grammarErr.Line != "vlan bogus 7" {
		t.Fatalf("error line = %q, want the offending line", grammarErr.Line)
	}
	if grammarErr.Section != "vlan database" {
		t.Fatalf("error section = %q", grammarErr.Section)
	}
}

// TestCodecForeignLinesPreserved: a foreign body line in interface 0/3
// plus a PVID change both survive the render in the right order, with
// the editor holding the double-spaced style.
func TestCodecForeignLinesPreserved(t *testing.T) {
	raw := loadFactoryFixture(t)
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}
	// Seed the fetched config with a foreign line in interface 0/3.
	editor, err := fastpath.NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	if err := editor.ReplaceSectionBody("interface 0/3", []string{"no snmp trap link-status", "vlan pvid 7"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	seeded, err := editor.Render()
	if err != nil {
		t.Fatalf("seed render: %v", err)
	}
	tc2, err := fastpath.ParseTextConfig(seeded)
	if err != nil {
		t.Fatalf("ParseTextConfig(seeded): %v", err)
	}

	desired := mkState(
		map[int]map[int]model.PortMembership{
			// Port 3 moved to VLAN 7 (PVID 7): VLAN 1 is ignored there.
			1: {1: model.PortMembershipUntagged, 2: model.PortMembershipUntagged, 4: model.PortMembershipUntagged, 5: model.PortMembershipUntagged, 6: model.PortMembershipUntagged, 7: model.PortMembershipUntagged, 8: model.PortMembershipUntagged},
			7: untagged(3),
		},
		map[int]int{1: 1, 2: 1, 3: 7, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1},
	)
	editor2, err := fastpath.NewTextConfigEditor(tc2)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	upload, err := renderVLANState(editor2, desired.Normalize(), captureForeign(tc2))
	if err != nil {
		t.Fatalf("renderVLANState: %v", err)
	}
	if !strings.Contains(string(upload), "interface 0/3\n\nno snmp trap link-status\n\nvlan pvid 7\n\nexit") {
		t.Fatalf("foreign line or PVID line did not survive in order:\n%s", sectionSnippet(t, upload, "interface 0/3"))
	}
	if !strings.Contains(string(upload), "interface 0/4\n\nexit") {
		t.Fatalf("untouched port mutated:\n%s", sectionSnippet(t, upload, "interface 0/4"))
	}
	roundTripState(t, seeded, desired)
}

// TestApplyRejectsTwoUntaggedPorts: fail-closed on a semantically
// impossible desired state before any network traffic.
func TestApplyRejectsTwoUntaggedPorts(t *testing.T) {
	bad := mkState(
		map[int]map[int]model.PortMembership{
			1:  untagged(1, 2),
			42: untagged(1),
		},
		map[int]int{1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1},
	)
	if err := validateRenderable(bad.Normalize()); err == nil {
		t.Fatal("two untagged VLANs on one port accepted")
	}
	var typed *ErrInvalidDesiredState
	if err := validateRenderable(bad.Normalize()); !errors.As(err, &typed) {
		t.Fatalf("error = %T (%v), want *ErrInvalidDesiredState", err, err)
	}
}

// TestSwitchMACFromConfigPure: the STP identity annotation normalizes
// to colon-separated lowercase.
func TestSwitchMACFromConfigPure(t *testing.T) {
	raw := loadFactoryFixture(t)
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}
	if got := switchMACFromConfig(tc); got != "8c:3b:ad:2c:e9:7d" {
		t.Fatalf("MAC = %q, want 8c:3b:ad:2c:e9:7d", got)
	}
}

// sectionSnippet extracts one section's block from rendered bytes for
// failure messages.
func sectionSnippet(t *testing.T, raw []byte, label string) string {
	t.Helper()
	lines := strings.Split(string(raw), "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimRight(l, "\r") == label {
			start = i
			break
		}
	}
	if start < 0 {
		return "<missing " + label + ">"
	}
	end := start + 6
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "|")
}

// ---------------------------------------------------------------------------
// F2b pure tests: uptime parser, capability table, port codec round
// trips and cross-namespace interleaving (no sockets required).
// ---------------------------------------------------------------------------

func TestParseUptimeSeconds(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"0 days 0 hrs 5 mins 36 secs", 336, true},
		{"0 days 0 hrs 0 mins 3 secs", 3, true},
		{"2 days 3 hrs 41 mins 12 secs", 2*86400 + 3*3600 + 41*60 + 12, true},
		{"1 hr 5 secs", 3605, true},
		{"", 0, false},
		{"garbage", 0, false},
		{"5 mins", 300, true},
		{"5 parsecs", 0, false},
		{"1 day 2 hrs", 86400 + 7200, true},
	}
	for _, c := range cases {
		got, ok := parseUptimeSeconds(c.in)
		if ok != c.ok {
			t.Errorf("parseUptimeSeconds(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("parseUptimeSeconds(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestUptimeSecondsFromConfig(t *testing.T) {
	raw := loadFactoryFixture(t)
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}
	got, ok := uptimeSecondsFromConfig(tc)
	if !ok || got != 336 {
		t.Fatalf("uptimeSecondsFromConfig(factory) = %d/%v, want 336/true", got, ok)
	}
}

func TestPortSettingCapabilitiesIntegrity(t *testing.T) {
	wantKeys := []string{"enabled", "flow_control", "qos_priority", "ingress_rate", "egress_rate"}
	if len(PortSettingCapabilities) != len(wantKeys) {
		t.Fatalf("capability table keys = %d, want %d", len(PortSettingCapabilities), len(wantKeys))
	}
	for _, key := range wantKeys {
		st, ok := PortSettingCapabilities[key]
		if !ok {
			t.Fatalf("capability key %q missing", key)
		}
		switch st.Status {
		case AttributeProvisional, AttributeUnsupported, AttributeSupported:
		default:
			t.Fatalf("capability %q has odd status %q", key, st.Status)
		}
	}
	for _, key := range []string{"qos_priority", "ingress_rate", "egress_rate"} {
		st := PortSettingCapabilities[key]
		if st.Status != AttributeUnsupported {
			t.Fatalf("%q marked %q, want unsupported until the grammar is pinned", key, st.Status)
		}
		if !strings.Contains(st.Reason, "no FASTPATH 5.4.2.36 text-config grammar pinned") {
			t.Fatalf("%q reason = %q", key, st.Reason)
		}
	}
}

// TestPortCodecRoundTrips: factory-in, all-defaults → byte-identical
// render; shutdown/flow-control edits decode back; vlan pvid lines and
// foreign lines pass through the port codec untouched.
func TestPortCodecRoundTrips(t *testing.T) {
	raw := loadFactoryFixture(t)
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}

	// All defaults render byte-identically to the factory file.
	editor, err := fastpath.NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	dec, err := decodeTextConfig(tc)
	if err != nil {
		t.Fatalf("decodeTextConfig: %v", err)
	}
	identical, err := renderPortSettings(editor, tc, dec.Ports, dec.PortPass)
	if err != nil {
		t.Fatalf("renderPortSettings(defaults): %v", err)
	}
	if string(identical) != string(raw) {
		t.Fatal("all-default port render is not byte-identical to the factory file")
	}

	// Seed bodies: shutdown on port 5, flow control on port 3, plus a
	// vlan pvid line and a foreign line crossing namespaces.
	editor2, err := fastpath.NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	if err := editor2.ReplaceSectionBody("interface 0/5", []string{"shutdown"}); err != nil {
		t.Fatalf("seed 0/5: %v", err)
	}
	if err := editor2.ReplaceSectionBody("interface 0/3", []string{"no snmp trap link-status", "flow control"}); err != nil {
		t.Fatalf("seed 0/3: %v", err)
	}
	if err := editor2.ReplaceSectionBody("interface 0/8", []string{"vlan pvid 42", "shutdown"}); err != nil {
		t.Fatalf("seed 0/8: %v", err)
	}
	seeded, err := editor2.Render()
	if err != nil {
		t.Fatalf("seed render: %v", err)
	}
	seedTC, err := fastpath.ParseTextConfig(seeded)
	if err != nil {
		t.Fatalf("ParseTextConfig(seeded): %v", err)
	}
	seedDec, err := decodeTextConfig(seedTC)
	if err != nil {
		t.Fatalf("decodeTextConfig(seeded): %v", err)
	}
	if seedDec.Ports[5].Enabled || !seedDec.Ports[5].FlowControl == false {
		t.Fatalf("port5 decoded = %+v", seedDec.Ports[5])
	}
	if !seedDec.Ports[3].FlowControl {
		t.Fatalf("port3 decoded = %+v", seedDec.Ports[3])
	}
	if seedDec.Ports[8].Enabled {
		t.Fatal("port 8 must decode disabled")
	}

	// Re-render the same settings back: byte-identical (style holds).
	editor3, err := fastpath.NewTextConfigEditor(seedTC)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	round, err := renderPortSettings(editor3, seedTC, seedDec.Ports, seedDec.PortPass)
	if err != nil {
		t.Fatalf("renderPortSettings(staged): %v", err)
	}
	if string(round) != string(seeded) {
		t.Fatal("staged-config port render is not a byte fixpoint")
	}

	// Flip port 5 back on: only that body changes; the vlan pvid line
	// and the foreign line stay put.
	wantOn := DefaultPortSettingsMap()
	editor4, err := fastpath.NewTextConfigEditor(seedTC)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	flipped, err := renderPortSettings(editor4, seedTC, wantOn, seedDec.PortPass)
	if err != nil {
		t.Fatalf("renderPortSettings(defaults over seeded): %v", err)
	}
	if strings.Contains(string(flipped), "shutdown") {
		t.Fatal("default port render left a shutdown line behind")
	}
	if !strings.Contains(string(flipped), "interface 0/8\n\nvlan pvid 42\n\nexit") {
		t.Fatalf("vlan pvid line dropped on port render:\n%s", sectionSnippet(t, flipped, "interface 0/8"))
	}
	if !strings.Contains(string(flipped), "interface 0/3\n\nno snmp trap link-status\n\nexit") {
		t.Fatalf("foreign line dropped on port render:\n%s", sectionSnippet(t, flipped, "interface 0/3"))
	}
}

// TestCrossNamespaceCodecInterleaving (pure): VLAN render then port
// render then VLAN render on synthetic configs — both namespaces
// survive each other, mirroring the socket-level interleaving test.
func TestCrossNamespaceCodecInterleaving(t *testing.T) {
	raw := loadFactoryFixture(t)

	// Stage 1: VLAN 42 (untagged 8, PVID 42) + port settings
	// (flow control 2, shutdown 5) — via the REAL apply sequence:
	// vlan render first.
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}
	vlanState := stagedVlan42State()
	vEditor, err := fastpath.NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	afterVlan, err := renderVLANState(vEditor, vlanState.Normalize(), captureForeign(tc))
	if err != nil {
		t.Fatalf("renderVLANState: %v", err)
	}

	// Stage 2: port apply over that.
	tc2, err := fastpath.ParseTextConfig(afterVlan)
	if err != nil {
		t.Fatalf("ParseTextConfig(vlan-staged): %v", err)
	}
	dec2, err := decodeTextConfig(tc2)
	if err != nil {
		t.Fatalf("decodeTextConfig(vlan-staged): %v", err)
	}
	ports := DefaultPortSettingsMap()
	p2 := ports[2]
	p2.FlowControl = true
	ports[2] = p2
	p5 := ports[5]
	p5.Enabled = false
	ports[5] = p5
	pEditor, err := fastpath.NewTextConfigEditor(tc2)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	afterPorts, err := renderPortSettings(pEditor, tc2, ports, dec2.PortPass)
	if err != nil {
		t.Fatalf("renderPortSettings: %v", err)
	}
	if !strings.Contains(string(afterPorts), "vlan 42 port 0/8 untagged") || !strings.Contains(string(afterPorts), "vlan pvid 42") {
		t.Fatal("vlan lines lost across a port render")
	}
	if !strings.Contains(string(afterPorts), "interface 0/2\n\nflow control\n\nexit") {
		t.Fatalf("port line wrong:\n%s", sectionSnippet(t, afterPorts, "interface 0/2"))
	}

	// Stage 3: another VLAN change — flow control must survive.
	tc3, err := fastpath.ParseTextConfig(afterPorts)
	if err != nil {
		t.Fatalf("ParseTextConfig(ports-staged): %v", err)
	}
	vEditor2, err := fastpath.NewTextConfigEditor(tc3)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	bState := vlanState.Clone()
	bState.VLANs[30] = model.Vlan{ID: 30, Ports: map[int]model.PortMembership{
		1: model.PortMembershipIgnored, 2: model.PortMembershipIgnored, 3: model.PortMembershipIgnored,
		4: model.PortMembershipIgnored, 5: model.PortMembershipIgnored, 6: model.PortMembershipIgnored,
		7: model.PortMembershipUntagged, 8: model.PortMembershipIgnored,
	}}
	bState.VLANs[1].Ports[7] = model.PortMembershipIgnored
	bState.PVIDs[7] = 30
	afterVlan2, err := renderVLANState(vEditor2, bState.Normalize(), captureForeign(tc3))
	if err != nil {
		t.Fatalf("renderVLANState(2nd): %v", err)
	}
	if !strings.Contains(string(afterVlan2), "flow control") {
		t.Fatal("port line lost across a VLAN apply")
	}
	if !strings.Contains(string(afterVlan2), "interface 0/5\n\nshutdown\n\nexit") {
		t.Fatalf("shutdown lost across a VLAN apply:\n%s", sectionSnippet(t, afterVlan2, "interface 0/5"))
	}
	if !strings.Contains(string(afterVlan2), "vlan pvid 30") {
		t.Fatal("stage 3 vlan body wrong")
	}

	// And the state stays coherent: decode the final bytes.
	tc4, err := fastpath.ParseTextConfig(afterVlan2)
	if err != nil {
		t.Fatalf("ParseTextConfig(final): %v", err)
	}
	dec4, err := decodeTextConfig(tc4)
	if err != nil {
		t.Fatalf("decodeTextConfig(final): %v", err)
	}
	if !dec4.State.Equal(bState) {
		t.Fatalf("final vlan state = %s, want B", summariseVLANState(dec4.State))
	}
	if !equalPortSettings(dec4.Ports, ports) {
		t.Fatalf("final ports drifted: %s", describePortsDelta(ports, dec4.Ports))
	}
}

// TestValidatePortSettingsRefusal (pure): typed per-attribute refusal
// and normalization semantics.
func TestValidatePortSettingsRefusal(t *testing.T) {
	// Normalization fills missing ports with defaults.
	norm := normalizePortSettings(nil)
	if !equalPortSettings(norm, DefaultPortSettingsMap()) {
		t.Fatal("normalize(nil) != defaults")
	}

	bad := DefaultPortSettingsMap()
	p4 := bad[4]
	p4.QoSPriority = "high"
	bad[4] = p4
	err := validatePortSettings(bad)
	var refused *ErrUnsupportedAttribute
	if !errors.As(err, &refused) {
		t.Fatalf("error = %T (%v), want *ErrUnsupportedAttribute", err, err)
	}
	if refused.Attribute != "qos_priority" || refused.Value != "high" || refused.Port != 4 {
		t.Fatalf("refusal = %+v", refused)
	}

	// Default values are accepted.
	if err := validatePortSettings(DefaultPortSettingsMap()); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}

	// Missing ports in the desired map are refused (must cover 1..8).
	short := DefaultPortSettingsMap()
	delete(short, 6)
	if err := validatePortSettings(short); err == nil {
		t.Fatal("map missing port 6 accepted")
	}
}

// ---------------------------------------------------------------------------
// Phase 0a pinning tests against REAL bench captures.
// Fixtures: internal/testfixtures/gs108tv2 (see the README there for
// provenance: GS108Tv2 @ 10.0.2.8, 2026-09-16, emweb HTTP channel).
// ---------------------------------------------------------------------------

func loadLiveFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testfixtures/gs108tv2/" + name)
	if err != nil {
		t.Fatalf("live fixture %s missing: %v", name, err)
	}
	return data
}

// TestDecodeLiveFactoryDefaultState: the LIVE factory capture decodes
// to the default state — its configure-level foreign lines (the
// `snmp-server sysname " "` and `ip dhcp filtering` annotations the
// repo fixture lacks) must not break the VLAN decode, and the
// default render is byte-identical over the live bytes (their full
// passthrough, configure preamble included, pinned by byte identity).
func TestDecodeLiveFactoryDefaultState(t *testing.T) {
	for _, name := range []string{"factory-live.txt", "factory-reverted.txt"} {
		raw := loadLiveFixture(t, name)
		tc, err := fastpath.ParseTextConfig(raw)
		if err != nil {
			t.Fatalf("%s: ParseTextConfig: %v", name, err)
		}
		dec, err := decodeTextConfig(tc)
		if err != nil {
			t.Fatalf("%s: decodeTextConfig: %v", name, err)
		}
		if !dec.State.Equal(defaultState()) {
			t.Fatalf("%s: state = %s, want default", name, summariseVLANState(dec.State))
		}

		// Configure-level foreign passthrough, verbatim: the codec
		// never owns configure, and a default-state render must
		// reproduce the live bytes exactly (which keeps the sysname
		// and dhcp-filtering lines byte-for-byte).
		body, ok := tc.SectionBody("configure")
		if !ok {
			t.Fatalf("%s: configure section missing", name)
		}
		joined := strings.Join(body, "\n")
		if !strings.Contains(joined, `snmp-server sysname " "`) {
			t.Fatalf("%s: sysname line lost in configure body: %q", name, joined)
		}

		editor, err := fastpath.NewTextConfigEditor(tc)
		if err != nil {
			t.Fatalf("%s: NewTextConfigEditor: %v", name, err)
		}
		upload, err := renderVLANState(editor, defaultState().Normalize(), captureForeign(tc))
		if err != nil {
			t.Fatalf("%s: renderVLANState(default): %v", name, err)
		}
		if string(upload) != string(raw) {
			t.Fatalf("%s: default-state render is not byte-identical to the live capture", name)
		}
	}
	// Explicit passthrough pin for the sysname line across a VLAN
	// staging render (non-default): the line must survive untouched.
	raw := loadLiveFixture(t, "factory-live.txt")
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}
	editor, err := fastpath.NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	upload, err := renderVLANState(editor, stagedVlan42State().Normalize(), captureForeign(tc))
	if err != nil {
		t.Fatalf("renderVLANState(vlan42 over live factory): %v", err)
	}
	if !strings.Contains(string(upload), `snmp-server sysname " "`) || !strings.Contains(string(upload), "ip dhcp filtering") {
		t.Fatal("configure-level foreign lines lost across a VLAN staging render")
	}
}

// TestDecodeLiveVlan42Reserved: the live-pinned phase-0a evidence — a
// bare `vlan 42` declaration survives restore and re-serve; decode
// yields VLAN 42 (no memberships yet) alongside the implicit VLAN 1
// and the PVID-1 defaults.
func TestDecodeLiveVlan42Reserved(t *testing.T) {
	reserved := loadLiveFixture(t, "vlan42-reserved.txt")
	upload := loadLiveFixture(t, "vlan42-upload.txt")

	// The pinned capture shape: double-spaced, in the switch's own
	// re-serialized style.
	if !strings.Contains(string(reserved), "vlan database\n\nvlan 42\n\nexit") {
		t.Fatal("reserved capture lost the double-spaced declaration block")
	}

	reservedTC, err := fastpath.ParseTextConfig(reserved)
	if err != nil {
		t.Fatalf("ParseTextConfig(reserved): %v", err)
	}
	dec, err := decodeTextConfig(reservedTC)
	if err != nil {
		t.Fatalf("decodeTextConfig(reserved): %v", err)
	}
	norm := dec.State.Normalize()
	v42, ok := norm.VLANs[42]
	if !ok {
		t.Fatalf("vlan 42 absent from the decoded state: %s", summariseVLANState(dec.State))
	}
	for port := 1; port <= defaultPortCount; port++ {
		if m := v42.Ports[port]; m != model.PortMembershipIgnored {
			t.Fatalf("vlan 42 port %d membership = %q, want ignored (declaration only)", port, m)
		}
	}
	v1 := norm.VLANs[defaultPVID]
	for port := 1; port <= defaultPortCount; port++ {
		if v1.Ports[port] != model.PortMembershipUntagged {
			t.Fatalf("implicit vlan 1 port %d = %q, want untagged", port, v1.Ports[port])
		}
		if norm.PVIDs[port] != defaultPVID {
			t.Fatalf("pvid for port %d = %d, want default", port, norm.PVIDs[port])
		}
	}

	// The COMPACT upload decodes to the SAME state: whitespace shape
	// is not part of the grammar's meaning (that is what the switch's
	// double-spacing normalization proves).
	uploadTC, err := fastpath.ParseTextConfig(upload)
	if err != nil {
		t.Fatalf("ParseTextConfig(upload): %v", err)
	}
	uploadDec, err := decodeTextConfig(uploadTC)
	if err != nil {
		t.Fatalf("decodeTextConfig(upload): %v", err)
	}
	if !uploadDec.State.Equal(dec.State) {
		t.Fatalf("compact upload decoded differently from the re-served capture: %s vs %s",
			summariseVLANState(uploadDec.State), summariseVLANState(dec.State))
	}
}
