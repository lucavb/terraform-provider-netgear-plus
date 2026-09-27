package fastpath

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// FASTPATH text configuration (the "startup-config" file of the
// GS108Tv2/GS110TPv2-class firmware, e.g. v5.4.2.36).
//
// Format (live factory-default export):
//
//	0x4e47 4e47 0100 GS108Tv2            5.4.2.36   0x00000000 0x00000000000000
//
//	! The line above is the NSDP Text Configuration header. DO NOT EDIT THIS HEADER
//
//	!System Description "GS108Tv2"
//
//	!System Software Version "5.4.2.36"
//	...
//	vlan database
//	exit
//	configure
//	...
//
// The binary-looking first line is the NSDP text-config magic header
// the firmware VALIDATES on restore ("Invalid text config header!",
// "Incompatible text config Firmware revision!",
// nsdpConfigHeaderBufferValidate: NSDP_STATUS_CONFIG_REVISION_NOT_COMPATIBLE
// in switchdrvr.bin). byte 0..1 = 0x4e47 = "NG" (NetGear); the
// following words carry the firmware string the upload validation
// compares. For GS108Tv2 v5.4.2.36 the leading bytes are the literal
// po "NGNG" pairs.
//
// This file exposes:
//   - ParseTextConfig: a structural read (header + sections) used by
//     read-only surfaces (config backup data source, drift diagnostics).
//   - ValidateTextConfigHeader: the same guards the firmware runs
//     on restore, used BEFORE uploading so callers get a local error
//     instead of a switch-side rejection mystery.
//
// Scope note (v0.1 of this transport): the authoritative VLAN/PVID
// channel for this family IS this file, but its VLAN-database grammar
// beyond the factory defaults will be pinned live (a config with real
// VLANs observed on real hardware) before the apply-side rewriter
// ships — ParseTextConfig therefore reports the section inventory it
// knows and validates the header contract.
// ---------------------------------------------------------------------------

// TextConfig is the structural read of a FASTPATH startup-config file.
type TextConfig struct {
	// Header is the verbatim magic first line (the firmware-validated
	// NSDP text-config header, binary bytes included).
	Header string

	// The NSDP magic prefix bytes the firmware checks (0x4e47 "NG"
	// pairs on GS108Tv2 5.4.2.36 factory export); kept for round-trip
	// fidelity and validation.
	HeaderBytes []byte

	// SystemDescription and SystemSoftwareVersion come from the
	// !System comment block right behind the header.
	SystemDescription     string
	SystemSoftwareVersion string

	// Raw is the untouched file bytes; callers doing a verbatim
	// round-trip restore (dump→upload) must use this.
	Raw []byte

	// Sections: the CLI block labels (vlan database, configure,
	// interface, ...) exactly as appearing at line level, in order,
	// with the count of body lines per section.
	Sections []TextConfigSection
}

// TextConfigSection is one structural block of the text config.
//
// Line-span fields (LabelLine / BodyStart / BodyEnd) are filled by
// ParseTextConfig; the zero value of TextConfigSection is not
// meaningful for them.
//
// Nested-overlap semantics: FASTPATH sections physically nest — the
// `configure` block spans (at label/exit level) the flat command
// sections around it such that `interface 0/x` label lines sit inside
// configure's line reach. The structured Sections list is FLAT (the
// walk emits every sectionStarts-recognized label in file order), and
// the clickable body region of a section stops BEFORE the first nested
// section's label line so a splice of the configure body can never
// swallow the nested `interface ...` blocks — see BodyEnd.
type TextConfigSection struct {
	Label     string // e.g. "vlan database", "configure", "interface 0/1"
	LineCount int    // body lines between the section label and its exit/next label

	// LabelLine is the 0-based index of the section's label line in the
	// line array of Raw (strings.Split(Raw, "\n")). Blank and "!"
	// comment lines are never labels, so index math with the raw line
	// array is exact.
	LabelLine int

	// BodyStart is the 0-based index of the first line of the section's
	// editable body region (the line right after the label line). The
	// region INCLUDES blank lines: the file is double-spaced, so the
	// label's trailing blank belongs to the region.
	BodyStart int

	// BodyEnd is the 0-based index (inclusive) of the last line of the
	// editable body region: the line before the section's own `exit`
	// line. For sections whose closing exit lies beyond nested labels
	// (configure: its exit is the final "exit" of the file), BodyEnd
	// stops BEFORE the first nested `interface ` label line instead,
	// keeping nested interface splice units out of the parent's
	// editable body. Flat command labels the walk recognizes
	// ("voip oui ...", "sntp client mode ...") never receive an exit of
	// their own; for those the region runs to just before the next
	// section's label line.
	BodyEnd int
}

// ParseTextConfig reads a startup-config file into structural facts.
// It is tolerant about content (the whole file is user-writable config
// state) but strict about the magic header: an empty input or one
// missing the NSDP header line is an error, because every consumer of
// a parsed handle is heading for an upload that the firmware will
// reject in exactly that case.
func ParseTextConfig(raw []byte) (TextConfig, error) {
	var tc TextConfig
	if len(raw) == 0 {
		return tc, fmt.Errorf("fastpath: empty text config")
	}
	tc.Raw = append([]byte(nil), raw...)

	text := string(raw)
	lines := strings.Split(text, "\n")

	// The magic header is line 1 in the factory export: ASCII with hex-escape
	// words — literal text "0x4e470x010x00GS108Tv2 ... 0x00000000
	// 0x00000000000000" (raw bytes verified 2026-09-15). Interpret it as
	// plain line-0 text; the "NG" (0x4e47) prefix escapes are part of it.
	tc.Header = strings.TrimRight(lines[0], "\r")
	tc.HeaderBytes = []byte(tc.Header)

	// "!System Description" / "!System Software Version" comments.
	for i := 0; i < len(lines) && i < 40; i++ {
		l := strings.TrimRight(lines[i], "\r")
		if v, ok := commentValue(l, "!System Description"); ok {
			tc.SystemDescription = v
		}
		if v, ok := commentValue(l, "!System Software Version"); ok {
			tc.SystemSoftwareVersion = v
		}
	}

	// Section-level structure walk.
	cur := -1
	for i, l := range lines {
		line := strings.TrimRight(l, "\r")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "!"):
			continue // comment annotation
		}
		if sectionStarts(trimmed) {
			tc.Sections = append(tc.Sections, TextConfigSection{Label: trimmed, LabelLine: i})
			cur = len(tc.Sections) - 1
			continue
		}
		if trimmed == "exit" && cur >= 0 {
			cur = -1
			continue
		}
		if cur >= 0 {
			tc.Sections[cur].LineCount++
		}
	}

	computeSectionSpans(&tc, lines)

	return tc, nil
}

// blockSectionLabel reports whether the given trimmed line opens a
// section block the FASTPATH emitter later closes with its own "exit".
// Flat command lines that sectionStarts also recognizes
// ("sntp client mode unicast", "voip oui ...", "users passwd ...")
// never receive an exit; treating them as blocks would let them
// swallow a later block's closing exit in the LIFO exit matching.
func blockSectionLabel(line string) bool {
	switch line {
	case "vlan database", "configure", "lineconfig":
		return true
	}
	return strings.HasPrefix(line, "interface ")
}

// pairSectionExits LIFO-matches block-section label lines (see
// blockSectionLabel) to their closing "exit" lines. A trailing "exit"
// with no open block on the stack is ignored — the same tolerance the
// structural walk has. Returns a map from label line index to exit
// line index.
func pairSectionExits(lines []string) map[int]int {
	pairs := make(map[int]int)
	var stack []int
	for i, l := range lines {
		t := strings.TrimSpace(strings.TrimRight(l, "\r"))
		if t == "" || strings.HasPrefix(t, "!") {
			continue
		}
		if t == "exit" {
			if len(stack) > 0 {
				pairs[stack[len(stack)-1]] = i
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if blockSectionLabel(t) {
			stack = append(stack, i)
		}
	}
	return pairs
}

// computeSectionSpans fills LabelLine / BodyStart / BodyEnd for every
// parsed section. See TextConfigSection for the nested-overlap
// semantics and pairSectionExits for the exit matching this relies on.
func computeSectionSpans(tc *TextConfig, lines []string) {
	exits := pairSectionExits(lines)
	for i := range tc.Sections {
		s := &tc.Sections[i]
		s.BodyStart = s.LabelLine + 1
		if e, ok := exits[s.LabelLine]; ok {
			// Block with its own exit: the body bound is the line
			// before it, pulled up in front of the first nested
			// interface label when one exists inside the span.
			s.BodyEnd = e - 1
			if n := firstNestedInterface(lines, s.LabelLine+1, e); n >= 0 {
				s.BodyEnd = n - 1
			}
			continue
		}
		// Flat/open section (never exit-matched): the body runs to
		// just before the next section's label line.
		s.BodyEnd = len(lines) - 1
		if i+1 < len(tc.Sections) {
			s.BodyEnd = tc.Sections[i+1].LabelLine - 1
		}
	}
}

// firstNestedInterface returns the line index of the first
// "interface " label line in [from, to), or -1.
func firstNestedInterface(lines []string, from, to int) int {
	for j := from; j < to && j < len(lines); j++ {
		t := strings.TrimSpace(strings.TrimRight(lines[j], "\r"))
		if strings.HasPrefix(t, "interface ") {
			return j
		}
	}
	return -1
}

// Section returns the first structural section with the given label
// (exact match, e.g. "vlan database", "interface 0/1").
func (tc TextConfig) Section(label string) (TextConfigSection, bool) {
	for _, s := range tc.Sections {
		if s.Label == label {
			return s, true
		}
	}
	return TextConfigSection{}, false
}

// SectionBody returns the section's content lines verbatim, without
// the blank/comment scaffolding of the double-spaced file: blank
// lines, "!" comment annotations and the section's structural "exit"
// lines are dropped, and any "\r" bytes at line ends survive (the
// file is "\n"-separated but tolerant of "\r" leftovers). For the
// factory file, SectionBody("interface 3/1") yields
// ["no snmp trap link-status", "lacp collector max-delay 0"] and all
// other sections yield empty bodies.
func (tc TextConfig) SectionBody(label string) ([]string, bool) {
	s, ok := tc.Section(label)
	if !ok {
		return nil, false
	}
	lines := strings.Split(string(tc.Raw), "\n")
	var body []string
	for j := s.BodyStart; j <= s.BodyEnd && j < len(lines); j++ {
		t := strings.TrimSpace(strings.TrimRight(lines[j], "\r"))
		if t == "" || strings.HasPrefix(t, "!") || t == "exit" {
			continue
		}
		body = append(body, lines[j])
	}
	return body, true
}

// UptimeLineExcluded is the single annotation excluded from
// CanonicalBytes/Fingerprint: the "!System Up Time ..." line. The
// switch re-stamps that annotation with its wall clock on every fetch
// (live-measured emweb contract, see web.go), so byte comparisons
// across reads — save → mutate → restore → read-back drift checks —
// must ignore exactly that line and nothing else. Everything outside
// it, including the NSDP magic header and the double-spaced blank
// lines, must stay byte-identical between reads.
const UptimeLineExcluded = "!System Up Time"

// CanonicalBytes returns Raw minus the single "!System Up Time"
// annotation line (see UptimeLineExcluded for why). Every other byte
// — the magic first line, all blank lines, the trailing newline — is
// byte-identical to Raw.
func (tc TextConfig) CanonicalBytes() []byte {
	lines := strings.Split(string(tc.Raw), "\n")
	kept := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), UptimeLineExcluded) {
			continue
		}
		kept = append(kept, l)
	}
	return []byte(strings.Join(kept, "\n"))
}

// Fingerprint is the SHA-256 hex digest of CanonicalBytes: a stable
// identity of the on-switch config across reads that differ only in
// the live up-time annotation.
func (tc TextConfig) Fingerprint() string {
	sum := sha256.Sum256(tc.CanonicalBytes())
	return hex.EncodeToString(sum[:])
}

// sectionStarts recognizes the CLI feature-block labels the firmware's
// text-config emitter produces. Fastpath config files open sections
// with a bare command line, close them with exit.
func sectionStarts(line string) bool {
	for _, s := range []string{
		"vlan database",
		"configure",
		"lineconfig",
		"snmp-server ",
		"ip ",
		"no sntp client mode",
		"sntp ",
		"users passwd",
		"authentication login",
		"spanning-tree configuration name",
		"voip ",
		"interface ",
		"network mgmt_",
	} {
		if strings.HasPrefix(line, s) {
			return true
		}
	}
	return false
}

// commentValue extracts the quoted value of an "!System ..." style
// annotation ("!System Description \"GS108Tv2\"").
func commentValue(line, prefix string) (string, bool) {
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	v := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"") && len(v) >= 2 {
		return strings.Trim(v, "\""), true
	}
	if v != "" {
		return strings.Trim(v, "\""), true
	}
	return "", false
}

// ValidateTextConfigHeader runs the firmware's own restore-path guards
// against the file bytes BEFORE they travel: (1) the NSDP magic header
// line must be present at line 1 with the "NG" ("0x4e47") prefix —
// GS108Tv2 v5.4.2.36 factory export begins 0x4e 0x47 0x4e 0x47; (2) the
// !System Software Version comment field identifies the target
// firmware, so a file exported from a different generation is refused
// with the "Incompatible text config Firmware revision!" semantics the
// switch itself enforces on upload.
//
// wantDescription, when non-empty (e.g. "GS108Tv2")) is asserted in
// the System Description field; empty disables that check.
func ValidateTextConfigHeader(raw []byte, wantDescription, wantVersion string) error {
	if len(raw) == 0 {
		return fmt.Errorf("fastpath: empty text config")
	}
	tc, err := ParseTextConfig(raw)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(tc.HeaderBytes), "0x4e47") {
		return fmt.Errorf("fastpath: text config does not carry the NSDP hex-header prefix 0x4e47 (\"NG\"); first line = %q", tc.Header)
	}
	if wantDescription != "" && tc.SystemDescription != wantDescription {
		return fmt.Errorf("fastpath: text config was exported from %q, want %q (Incompatible text config revision semantics)", tc.SystemDescription, wantDescription)
	}
	if wantVersion != "" && tc.SystemSoftwareVersion != wantVersion {
		return fmt.Errorf("fastpath: text config firmware %q, want %q", tc.SystemSoftwareVersion, wantVersion)
	}
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
