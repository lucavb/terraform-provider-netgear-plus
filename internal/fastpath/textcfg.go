package fastpath

import (
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
type TextConfigSection struct {
	Label     string // e.g. "vlan database", "configure", "interface 0/1"
	LineCount int    // body lines between the section label and its exit/next label
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
	var current *TextConfigSection
	for _, l := range lines {
		line := strings.TrimRight(l, "\r")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "!"):
			continue // comment annotation
		}
		if sectionStarts(trimmed) {
			tc.Sections = append(tc.Sections, TextConfigSection{Label: trimmed})
			current = &tc.Sections[len(tc.Sections)-1]
			continue
		}
		if trimmed == "exit" && current != nil {
			current = nil
			continue
		}
		if current != nil {
			current.LineCount++
		}
	}

	return tc, nil
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
