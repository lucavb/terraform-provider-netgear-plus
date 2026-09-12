// Lockout WARNING (do not remove): 3 failed login attempts lock ALL SET
// operations on the switch for ~30 minutes (GS108Ev3 bank1 firmware
// V2.06.24GR, XRAM 0x97EE/0x980F). The status byte value the switch uses
// to report the lockout has NOT yet been observed live — do not guess it;
// treat any unexpected login error as a possible lockout and stop retrying
// rather than burning further attempts.

package nsdp

import (
	"errors"
	"fmt"
)

// ErrNoReply reports that the per-request wait window expired without a
// reply matching the current exchange (expected echo command, sequence and
// MAC echoes). It is returned bare from the read path; the retrying call
// sites wrap it with their attempt counts, preserving errors.Is matching.
var ErrNoReply = errors.New("nsdp: no reply within the per-request wait window")

// ErrStatus reports a structurally valid reply carrying a non-zero status
// byte. FailingTag mirrors the reply's [4-5] field: the switch announces
// the required-but-missing TLV there (live: 0x001A when a login SET lacked
// the auth TLV). Source names the exchange that failed (e.g. "SET login");
// it is filled in by the client, ParseReply leaves it empty.
type ErrStatus struct {
	Status     byte
	FailingTag uint16
	Source     string
	// ExpectedAuth is the switch-expected auth-token value surfaced in an
	// auth-mismatch reply: status 0x0d with a {BE16 len, bytes} payload
	// right after the 32-byte header (observed live as {00 08, 8-byte V2
	// token}, ROUND 8, 2026-09-12). The switch rolls its auth nonce after
	// every authenticated SET and hands back the token it wanted under
	// the rolled nonce. DIAGNOSTIC ONLY: the client refreshes its token
	// before every SET (see Client.SetSystemName / Client.SetRaw); no
	// auto-retry is ever performed with this value.
	ExpectedAuth []byte
}

func (e *ErrStatus) Error() string {
	s := fmt.Sprintf("nsdp: error status 0x%02x (%s)", e.Status, statusName(e.Status))
	if e.FailingTag != 0 {
		s += fmt.Sprintf(", failing tag 0x%04x", e.FailingTag)
	}
	if e.ExpectedAuth != nil {
		s += fmt.Sprintf(", expected auth % x", e.ExpectedAuth)
	}
	if e.Source != "" {
		s += fmt.Sprintf(" (%s)", e.Source)
	}
	return s
}

// ErrMalformed reports a reply that violates the NSDP v2 wire layout:
// wrong version, wrong echo command byte, bad magic, stale sequence, MAC
// echo mismatch, a too-short packet, or a TLV region that truncates
// mid-TLV.
type ErrMalformed struct {
	Reason string
}

func (e *ErrMalformed) Error() string {
	return "nsdp: malformed reply: " + e.Reason
}

// statusNames maps the reply status byte (doc §5 of the protocol notes and
// live observation) to a human-readable name.
var statusNames = map[byte]string{
	0x00: "ok",
	0x01: "bad version",
	0x02: "bad command",
	0x03: "invalid/unknown attribute",
	0x04: "unknown GET body/block tag",
	0x05: "SET-related failure",
	0x07: "manager MAC check failed",
	0x0d: "required TLV missing / auth-token mismatch",
	0x0f: "other failure",
	0x84: "SET / tag-0x10 specific error",
}

func statusName(s byte) string {
	if n, ok := statusNames[s]; ok {
		return n
	}
	return fmt.Sprintf("unknown status 0x%02x", s)
}
