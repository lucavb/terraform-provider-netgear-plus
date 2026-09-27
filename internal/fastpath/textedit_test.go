package fastpath

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// factoryRaw loads the ground-truth factory export. Skips when the
// repo-root fixture is absent (out-of-tree checkouts).
func factoryRaw(t *testing.T) []byte {
	t.Helper()
	s := mirrorFactoryFile(t)
	if s == "" {
		t.Skip("startup-config-gs108t not present in repo root")
	}
	return []byte(s)
}

// lineIndexOf returns the 0-based index of the first line equal to
// want (ignoring a trailing "\r").
func lineIndexOf(raw []byte, want string) int {
	for i, l := range strings.Split(string(raw), "\n") {
		if strings.TrimRight(l, "\r") == want {
			return i
		}
	}
	return -1
}

// firstExitAfter returns the 0-based index of the first standalone
// "exit" line strictly after from (its own line), or -1.
func firstExitAfter(raw []byte, from int) int {
	lines := strings.Split(string(raw), "\n")
	for j := from + 1; j < len(lines); j++ {
		if strings.TrimSpace(strings.TrimRight(lines[j], "\r")) == "exit" {
			return j
		}
	}
	return -1
}

// offsetOfLine returns the byte offset of the given 0-based line index.
func offsetOfLine(raw []byte, idx int) int {
	lines := strings.Split(string(raw), "\n")
	off := 0
	for i := 0; i < idx && i < len(lines); i++ {
		off += len(lines[i]) + 1
	}
	return off
}

func mustParse(t *testing.T, raw []byte) TextConfig {
	t.Helper()
	tc, err := ParseTextConfig(raw)
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}
	return tc
}

func mustSection(t *testing.T, tc TextConfig, label string) TextConfigSection {
	t.Helper()
	s, ok := tc.Section(label)
	if !ok {
		t.Fatalf("missing section %q in %+v", label, tc.Sections)
	}
	return s
}

// TestParseTextConfigSectionSpans pins the span fields against the
// factory fixture layout (ground truth, see repo-root
// startup-config-gs108t; every content line is 0-based even, blank
// lines odd).
func TestParseTextConfigSectionSpans(t *testing.T) {
	raw := factoryRaw(t)
	tc := mustParse(t, raw)

	// vlan database: label at its real line index, empty body.
	vlanIdx := lineIndexOf(raw, "vlan database")
	if vlanIdx != 20 {
		t.Fatalf("fixture drift: vlan database at line %d, want 20", vlanIdx)
	}
	vlan := mustSection(t, tc, "vlan database")
	if vlan.LabelLine != vlanIdx {
		t.Fatalf("vlan database LabelLine = %d, want %d", vlan.LabelLine, vlanIdx)
	}
	if vlan.LineCount != 0 {
		t.Fatalf("vlan database LineCount = %d, want 0", vlan.LineCount)
	}
	// The region is just the label's trailing blank line (the file is
	// double-spaced): BodyStart..BodyEnd = [21..21] for the factory file.
	wantVlanEnd := firstExitAfter(raw, vlanIdx) - 1
	if vlan.BodyStart != vlanIdx+1 || vlan.BodyEnd != wantVlanEnd {
		t.Fatalf("vlan database body span [%d, %d], want [%d, %d]",
			vlan.BodyStart, vlan.BodyEnd, vlanIdx+1, wantVlanEnd)
	}

	// interface 0/1..0/8: empty bodies bounded by their own exit.
	for n := 1; n <= 8; n++ {
		label := fmt.Sprintf("interface 0/%d", n)
		idx := lineIndexOf(raw, label)
		if idx < 0 {
			t.Fatalf("fixture lost %q", label)
		}
		s := mustSection(t, tc, label)
		wantBodyEnd := firstExitAfter(raw, idx) - 1
		if s.LabelLine != idx || s.BodyStart != idx+1 || s.BodyEnd != wantBodyEnd {
			t.Fatalf("%s span = [%d..%d] label %d, want label %d span [%d..%d]",
				label, s.BodyStart, s.BodyEnd, s.LabelLine, idx, idx+1, wantBodyEnd)
		}
		if body, _ := tc.SectionBody(label); len(body) != 0 {
			t.Fatalf("%s body = %q, want empty", label, body)
		}
	}

	// interface 3/1: two content lines.
	s31 := mustSection(t, tc, "interface 3/1")
	idx31 := lineIndexOf(raw, "interface 3/1")
	if s31.LabelLine != idx31 {
		t.Fatalf("interface 3/1 LabelLine = %d, want %d", s31.LabelLine, idx31)
	}
	if s31.LineCount != 2 {
		t.Fatalf("interface 3/1 LineCount = %d, want 2", s31.LineCount)
	}
	body31, ok := tc.SectionBody("interface 3/1")
	if !ok {
		t.Fatal("SectionBody(interface 3/1) reported missing")
	}
	want31 := []string{"no snmp trap link-status", "lacp collector max-delay 0"}
	if len(body31) != 2 || body31[0] != want31[0] || body31[1] != want31[1] {
		t.Fatalf("interface 3/1 body = %q, want %q", body31, want31)
	}
	if s31.BodyStart != idx31+1 || s31.BodyEnd != firstExitAfter(raw, idx31)-1 {
		t.Fatalf("interface 3/1 span = [%d..%d], want [%d..%d]",
			s31.BodyStart, s31.BodyEnd, idx31+1, firstExitAfter(raw, idx31)-1)
	}

	// configure: the body bound stops before the first nested
	// interface 0/1 label (its own exit is the final "exit" of the
	// file, far behind the nested splice blocks).
	cfg := mustSection(t, tc, "configure")
	wantCfgEnd := lineIndexOf(raw, "interface 0/1") - 1
	if cfg.BodyEnd != wantCfgEnd {
		t.Fatalf("configure BodyEnd = %d, want %d (before first nested interface 0/1)",
			cfg.BodyEnd, wantCfgEnd)
	}
	if cfg.BodyStart != cfg.LabelLine+1 {
		t.Fatalf("configure BodyStart = %d, want label+1 (%d)", cfg.BodyStart, cfg.LabelLine)
	}
	if cfg.LabelLine != lineIndexOf(raw, "configure") {
		t.Fatalf("configure LabelLine = %d, want %d", cfg.LabelLine, lineIndexOf(raw, "configure"))
	}
}

// TestConfigSectionLookup covers the Section/SectionBody helpers,
// including the miss path.
func TestConfigSectionLookup(t *testing.T) {
	raw := factoryRaw(t)
	tc := mustParse(t, raw)

	if _, ok := tc.Section("does not exist"); ok {
		t.Fatal("Section(missing) = ok, want !ok")
	}
	if _, ok := tc.SectionBody("does not exist"); ok {
		t.Fatal("SectionBody(missing) = ok, want !ok")
	}
	body, ok := tc.SectionBody("vlan database")
	if !ok || len(body) != 0 {
		t.Fatalf("vlan database body = %q (ok=%v), want empty", body, ok)
	}
}

// TestEditorNoOpRoundTrip pins the core invariant: an editor that
// changed nothing renders Raw byte-for-byte.
func TestEditorNoOpRoundTrip(t *testing.T) {
	raw := factoryRaw(t)
	ed, err := NewTextConfigEditor(mustParse(t, raw))
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	if ed.Dirty() {
		t.Fatal("fresh editor reports dirty")
	}
	out, err := ed.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !bytes.Equal(out, raw) {
		i := 0
		for j := 0; j < len(out) && j < len(raw); j++ {
			if out[j] != raw[j] {
				i = j
				break
			}
		}
		t.Fatalf("no-op round trip diverges at byte %d: got %q, want %q", i, out[i:i+16], raw[i:i+16])
	}
	if err := ValidateTextConfigHeader(out, "GS108Tv2", "5.4.2.36"); err != nil {
		t.Fatalf("ValidateTextConfigHeader(rendered): %v", err)
	}
}

// TestEditorReplaceVlanDatabase replaces the vlan database body with a
// synthetic VLAN line and proves the diff is confined to that section:
// bytes before the label and after the exit are identical to Raw.
func TestEditorReplaceVlanDatabase(t *testing.T) {
	raw := factoryRaw(t)
	tc := mustParse(t, raw)
	ed, err := NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}

	if _, known := tc.Section("vlan 42"); known {
		t.Fatal("precondition: fixture already contains vlan 42")
	}
	// Synthetic body on a copy of the raw config.
	body := []string{"vlan 42"}
	if err := ed.ReplaceSectionBody("vlan database", body); err != nil {
		t.Fatalf("ReplaceSectionBody: %v", err)
	}
	out, err := ed.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Surroundings: everything before the label line and after the
	// section's exit line is byte-identical to Raw.
	vlanIdx := lineIndexOf(raw, "vlan database")
	exitIdx := firstExitAfter(raw, vlanIdx)
	prefixLen := offsetOfLine(raw, vlanIdx)
	if !bytes.Equal(out[:prefixLen], raw[:prefixLen]) {
		t.Fatalf("bytes before section label changed:\n%x\nvs\n%x", out[:prefixLen], raw[:prefixLen])
	}
	suffixRaw := raw[offsetOfLine(raw, exitIdx):]
	if !bytes.Equal(out[len(out)-len(suffixRaw):], suffixRaw) {
		t.Fatalf("bytes after section exit changed:\n%x\nvs\n%x",
			out[len(out)-len(suffixRaw):], suffixRaw)
	}

	// The new section content survived, double-spaced, exit intact.
	outTC := mustParse(t, out)
	if got, ok := outTC.SectionBody("vlan database"); !ok || len(got) != 1 || got[0] != "vlan 42" {
		t.Fatalf("re-parsed vlan database body = %q, want [vlan 42]", got)
	}
	if !strings.Contains(string(out), "vlan database\n\nvlan 42\n\nexit\n\n") {
		t.Fatalf("double-spaced block not reproduced:\n%s", strings.Join(strings.Split(string(out), "\n")[19:27], "|"))
	}
	if err := ValidateTextConfigHeader(out, "GS108Tv2", "5.4.2.36"); err != nil {
		t.Fatalf("ValidateTextConfigHeader: %v", err)
	}
	assertNoDoubleBlanks(t, out)
}

// TestEditorReplaceInterface01 replaces one interface body and proves
// every other section is untouched.
func TestEditorReplaceInterface01(t *testing.T) {
	raw := factoryRaw(t)
	tc := mustParse(t, raw)
	ed, err := NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}

	body := []string{"no spanning-tree", "description synth"}
	if err := ed.ReplaceSectionBody("interface 0/1", body); err != nil {
		t.Fatalf("ReplaceSectionBody: %v", err)
	}
	out, err := ed.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	idx := lineIndexOf(raw, "interface 0/1")
	prefixLen := offsetOfLine(raw, idx)
	if !bytes.Equal(out[:prefixLen], raw[:prefixLen]) {
		t.Fatal("bytes before interface 0/1 label changed")
	}
	suffixRaw := raw[offsetOfLine(raw, firstExitAfter(raw, idx)):]
	if !bytes.Equal(out[len(out)-len(suffixRaw):], suffixRaw) {
		t.Fatal("bytes after interface 0/1 exit changed")
	}

	outTC := mustParse(t, out)
	if got, _ := outTC.SectionBody("interface 0/1"); len(got) != 2 || got[0] != body[0] || got[1] != body[1] {
		t.Fatalf("interface 0/1 body = %q, want %q", got, body)
	}
	// All other sections byte-untouched: bodies identical, labels in
	// the same order, nested configure labels preserved.
	if !sameSectionsExcept(tc, outTC, "interface 0/1") {
		t.Fatalf("unrelated sections changed: labels before=%v after=%v",
			sectionLabels(tc), sectionLabels(outTC))
	}
	for _, label := range []string{"interface 0/2", "interface 0/3", "interface 0/4",
		"interface 0/5", "interface 0/6", "interface 0/7", "interface 0/8",
		"interface 3/1", "interface 3/2", "interface 3/3", "interface 3/4",
		"vlan database", "configure", "lineconfig"} {
		want, _ := tc.SectionBody(label)
		got, _ := outTC.SectionBody(label)
		if len(want) != len(got) || !equalStrings(want, got) {
			t.Fatalf("section %q body changed: %q -> %q", label, want, got)
		}
	}
	assertNoDoubleBlanks(t, out)
	if err := ValidateTextConfigHeader(out, "GS108Tv2", "5.4.2.36"); err != nil {
		t.Fatalf("ValidateTextConfigHeader: %v", err)
	}
}

// TestEditorInsertSection pins the block shape and byte-surroundings
// of InsertSection, for both a block-section anchor (interface 0/8)
// and the vlan database anchor.
func TestEditorInsertSection(t *testing.T) {
	raw := factoryRaw(t)
	tc := mustParse(t, raw)

	// After interface 0/8: a new interface 0/9 splices in before
	// interface 3/1, well-formed and with byte-identical surroundings.
	ed, err := NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	anchor := mustSection(t, tc, "interface 0/8")
	anchorExit := anchor.BodyEnd + 1
	insertOff := offsetOfLine(raw, anchorExit+1)
	if err := ed.InsertSection("interface 0/8", "interface 0/9", []string{"description uplink"}); err != nil {
		t.Fatalf("InsertSection: %v", err)
	}
	out, err := ed.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !bytes.Equal(out[:insertOff], raw[:insertOff]) {
		t.Fatalf("bytes before insertion point changed:\n%q\nvs\n%q", out[:insertOff], raw[:insertOff])
	}
	after := raw[insertOff:]
	if !bytes.Equal(out[len(out)-len(after):], after) {
		t.Fatalf("bytes after insertion point changed:\n%q", out[len(out)-len(after):])
	}
	if !strings.Contains(string(out), "\ninterface 0/9\n\ndescription uplink\n\nexit\n\ninterface 3/1\n") {
		t.Fatalf("inserted block shape wrong: %q", outStringWindow(out, insertOff, 72))
	}
	outTC := mustParse(t, out)
	s9 := mustSection(t, outTC, "interface 0/9")
	if got, _ := outTC.SectionBody("interface 0/9"); len(got) != 1 || got[0] != "description uplink" {
		t.Fatalf("interface 0/9 body = %q", got)
	}
	if s9.LabelLine >= mustSection(t, outTC, "interface 3/1").LabelLine {
		t.Fatal("interface 0/9 must land before interface 3/1")
	}
	assertNoDoubleBlanks(t, out)

	// After vlan database: block lands between its exit and configure.
	ed2, err := NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	if err := ed2.InsertSection("vlan database", "snmp-server community private", []string{"hostname gs108t-synth"}); err != nil {
		t.Fatalf("InsertSection(after vlan database): %v", err)
	}
	out2, err := ed2.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(out2), "\nexit\n\nsnmp-server community private\n\nhostname gs108t-synth\n\nexit\n\nconfigure\n") {
		t.Fatalf("block after vlan database malformed")
	}
	outTC2 := mustParse(t, out2)
	if got, _ := outTC2.SectionBody("snmp-server community private"); len(got) != 1 || got[0] != "hostname gs108t-synth" {
		t.Fatalf("snmp body = %q", got)
	}
	vlan := mustSection(t, outTC2, "vlan database")
	sn := mustSection(t, outTC2, "configure")
	ins := mustSection(t, outTC2, "snmp-server community private")
	if ins.LabelLine <= vlan.LabelLine || ins.LabelLine >= sn.LabelLine {
		t.Fatalf("inserted snmp block not between vlan database (%d) and configure (%d): label at %d",
			vlan.LabelLine, sn.LabelLine, ins.LabelLine)
	}
	assertNoDoubleBlanks(t, out2)

	// Duplicates and missing anchors are refused.
	if err := ed2.InsertSection("vlan database", "configure", nil); err == nil {
		t.Fatal("InsertSection with existing label must fail")
	}
	if err := ed2.InsertSection("nope", "x", nil); err == nil {
		t.Fatal("InsertSection with missing afterLabel must fail")
	}
}

// TestEditorDeleteSection covers block removal, synthetic round trip
// and the protected-label denylist.
func TestEditorDeleteSection(t *testing.T) {
	raw := factoryRaw(t)
	tc := mustParse(t, raw)

	// Insert then delete the same synthetic block: byte-identical.
	ed, err := NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	if err := ed.InsertSection("interface 0/8", "interface 0/9", []string{"description uplink"}); err != nil {
		t.Fatalf("InsertSection: %v", err)
	}
	if err := ed.DeleteSection("interface 0/9"); err != nil {
		t.Fatalf("DeleteSection: %v", err)
	}
	out, err := ed.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !bytes.Equal(out, raw) {
		t.Fatal("insert+delete round trip is not byte-identical")
	}

	// Deleting a real section keeps neighbors clean.
	ed2, err := NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	if err := ed2.DeleteSection("interface 0/3"); err != nil {
		t.Fatalf("DeleteSection(interface 0/3): %v", err)
	}
	out2, err := ed2.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(out2), "\nexit\n\ninterface 0/4\n") {
		t.Fatalf("junction after deleting interface 0/3 wrong")
	}
	outTC2 := mustParse(t, out2)
	if _, ok := outTC2.Section("interface 0/3"); ok {
		t.Fatal("interface 0/3 still present after delete")
	}
	for _, label := range []string{"interface 0/2", "interface 0/4", "interface 3/1"} {
		if _, ok := outTC2.Section(label); !ok {
			t.Fatalf("%s lost by delete of interface 0/3", label)
		}
	}
	assertNoDoubleBlanks(t, out2)

	// Denylist and unknown labels.
	for _, label := range []string{"vlan database", "configure"} {
		if err := ed2.DeleteSection(label); err == nil {
			t.Fatalf("DeleteSection(%q) must be refused", label)
		}
	}
	if err := ed2.DeleteSection("not-a-section"); err == nil {
		t.Fatal("DeleteSection of unknown label must fail")
	}
	// ReplaceSectionBody on an unknown label fails too.
	if err := ed.ReplaceSectionBody("not-a-section", nil); err == nil {
		t.Fatal("ReplaceSectionBody of unknown label must fail")
	}
}

// TestCanonicalBytesFingerprint pins the up-time exclusion: two reads
// differing only in !System Up Time share a fingerprint; one changed
// config byte makes them differ.
func TestCanonicalBytesFingerprint(t *testing.T) {
	raw := factoryRaw(t)
	reRead := []byte(strings.Replace(string(raw),
		"0 days 0 hrs 5 mins 36 secs", "2 days 3 hrs 41 mins 12 secs", 1))
	if string(reRead) == string(raw) {
		t.Fatal("precondition: up-time substitution did not apply")
	}

	a := mustParse(t, raw)
	b := mustParse(t, reRead)
	if !bytes.Equal(a.CanonicalBytes(), b.CanonicalBytes()) {
		t.Fatal("canonical bytes differ across an up-time-only change")
	}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatalf("fingerprints differ across an up-time-only change: %s vs %s",
			a.Fingerprint(), b.Fingerprint())
	}
	if len(a.CanonicalBytes()) >= len(raw) {
		t.Fatal("canonical bytes must drop the up-time line")
	}

	// Any other byte change must move the fingerprint.
	other := []byte(strings.Replace(string(raw),
		"sntp client mode unicast", "sntp client mode broadcast", 1))
	if other := mustParse(t, other); other.Fingerprint() == a.Fingerprint() {
		t.Fatal("fingerprint unchanged by a config byte change")
	}

	// The up-time line is the ONLY structural change: the header and
	// all other lines survive verbatim.
	canon := string(a.CanonicalBytes())
	if !strings.HasPrefix(canon, string(raw[:offsetOfLine(raw, lineIndexOf(raw, "!System Up Time"))])) {
		t.Fatal("canonical bytes damaged before the up-time line")
	}
	if !strings.Contains(string(raw), UptimeLineExcluded) {
		t.Fatal("fixture lost the up-time annotation")
	}
}

// TestEditorDoubleSpacingFidelity exercises the style contract over a
// mutation sequence: exactly one blank between consecutive content
// lines, no double-blank runs, EOF newline preserved.
func TestEditorDoubleSpacingFidelity(t *testing.T) {
	raw := factoryRaw(t)
	tc := mustParse(t, raw)
	ed, err := NewTextConfigEditor(tc)
	if err != nil {
		t.Fatalf("NewTextConfigEditor: %v", err)
	}
	if err := ed.InsertSection("interface 0/8", "interface 0/9", []string{"description uplink"}); err != nil {
		t.Fatalf("InsertSection: %v", err)
	}
	if err := ed.ReplaceSectionBody("interface 3/2", []string{"no cdp"}); err != nil {
		t.Fatalf("ReplaceSectionBody: %v", err)
	}
	if err := ed.ReplaceSectionBody("interface 0/4", nil); err != nil {
		t.Fatalf("ReplaceSectionBody(empty): %v", err)
	}
	if err := ed.DeleteSection("interface 0/9"); err != nil {
		t.Fatalf("DeleteSection: %v", err)
	}
	out, err := ed.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	assertNoDoubleBlanks(t, out)

	// EOF: the factory file ends with "exit\n\n" — a terminating
	// content line and the final structural blank; the editor must
	// reproduce the same tail for non-append operations.
	if !strings.HasSuffix(string(out), "exit\n\n") {
		t.Fatalf("EOF newline lost: ends %q", out[len(out)-8:])
	}
	// Replaced interface body keeps the double-spaced shape: label,
	// blank, content, blank, exit.
	if !strings.Contains(string(out), "interface 3/2\n\nno cdp\n\nexit\n\n") {
		t.Fatalf("replaced body section shape wrong")
	}
	// Empty body collapses to the factory vlan database shape.
	if !strings.Contains(string(out), "interface 0/4\n\nexit\n\n") {
		t.Fatalf("empty-body section shape wrong")
	}
	// Header line byte-identical.
	if !strings.HasPrefix(string(out), string(raw[:offsetOfLine(raw, lineIndexOf(raw, "!Current Configuration:"))])) {
		t.Fatal("header block damaged")
	}
}

// --- test helpers -----------------------------------------------------

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sectionLabels(tc TextConfig) []string {
	out := make([]string, 0, len(tc.Sections))
	for _, s := range tc.Sections {
		out = append(out, s.Label)
	}
	return out
}

// sameSectionsExcept compares two parses: identical section label
// sequence (bodies are compared separately by the callers).
func sameSectionsExcept(before, after TextConfig, except string) bool {
	bb, ab := sectionLabels(before), sectionLabels(after)
	return equalStrings(bb, ab)
}

// assertNoDoubleBlanks fails on a rendered config containing three
// consecutive "\n" (a double blank line).
func assertNoDoubleBlanks(t *testing.T, raw []byte) {
	t.Helper()
	s := string(raw)
	if strings.Contains(s, "\n\n\n") {
		idx := strings.Index(s, "\n\n\n")
		lo := idx - 24
		if lo < 0 {
			lo = 0
		}
		hi := minInt2(idx+16, len(raw))
		t.Fatalf("double blank line run at byte %d: %q", idx, s[lo:hi])
	}
}

func outStringWindow(raw []byte, off, n int) string {
	if off > len(raw) {
		return ""
	}
	end := off + n
	if n <= 0 || end > len(raw) {
		end = len(raw)
	}
	return string(raw[off:end])
}
