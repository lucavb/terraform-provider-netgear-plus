package gs108tv2

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// PROVISIONAL port-settings grammar + capability table
// (pinned live in phase 0a).
//
// The VLAN templates live in codec.go under the same PROVISIONAL
// banner; this file adds the interface-level port grammar and the
// per-attribute capability table the provider surfaces.
//
// Attribute status semantics:
//   - Supported: byte-exact real-switch grammar pinned live.
//   - Provisional: template implemented from bench observation, to be
//     pinned byte-exact live in phase 0a.
//   - Unsupported: NO text-config grammar exists today; writes to a
//     non-default value are refused BEFORE any upload
//     (ErrUnsupportedAttribute); default values render by absence.
//
// Interface body templates:
//
//	shutdown            → port admin-disabled; ABSENCE = enabled
//	                      (factory shape: empty bodies = all defaults)
//	flow control        → flow control on; `no flow control` = off;
//	                      absence = off (factory default)
//	`no shutdown` is NOT a template: it parses as a foreign line
//	(preserved verbatim — factually it means enabled, which absence
//	already encodes).
//
// Parsing discipline: any non-`vlan` line inside an interface body
// that matches no template above is FOREIGN (unmanaged): preserved on
// render, never failed — those lines are not ours to manage. `vlan`-
// prefixed lines belong to the VLAN codec (codec.go), which fail
// closes on unknown shapes for ITS writes.
// ---------------------------------------------------------------------------

// AttributeStatus classifies a port attribute's grammar maturity.
type AttributeStatus string

const (
	// AttributeSupported marks a byte-exact, live-pinned grammar.
	AttributeSupported AttributeStatus = "supported"
	// AttributeProvisional marks a bench-observed template pending
	// its live pinning in phase 0a.
	AttributeProvisional AttributeStatus = "provisional"
	// AttributeUnsupported marks an attribute with no text-config
	// grammar today: only the default value is renderable (absence).
	AttributeUnsupported AttributeStatus = "unsupported"
)

// PortAttributeStatus is one row of the capability table.
type PortAttributeStatus struct {
	Status AttributeStatus
	Reason string
}

const unpinnedAttributeReason = "no FASTPATH 5.4.2.36 text-config grammar pinned for this attribute yet"

// PortSettingCapabilities is the provider-visible capability table for
// the port attribute set. Keys: "enabled", "flow_control",
// "qos_priority", "ingress_rate", "egress_rate".
// PROVISIONAL (pinned live in phase 0a).
var PortSettingCapabilities = map[string]PortAttributeStatus{
	"enabled": {
		Status: AttributeProvisional,
		Reason: "shutdown/absence grammar implemented from bench observation; pinned live in phase 0a",
	},
	"flow_control": {
		Status: AttributeProvisional,
		Reason: "flow control/no flow control grammar implemented from bench observation; pinned live in phase 0a",
	},
	"qos_priority": {
		Status: AttributeUnsupported,
		Reason: unpinnedAttributeReason,
	},
	"ingress_rate": {
		Status: AttributeUnsupported,
		Reason: unpinnedAttributeReason,
	},
	"egress_rate": {
		Status: AttributeUnsupported,
		Reason: unpinnedAttributeReason,
	},
}

// --- PROVISIONAL port grammar parsers (pinned live in phase 0a) ---

// parseShutdownLine matches "shutdown" (exactly one field). PROVISIONAL
// (pinned live in phase 0a). Returns disabled=true.
func parseShutdownLine(fields []string) (disabled bool, ok bool) {
	if len(fields) == 1 && fields[0] == "shutdown" {
		return true, true
	}
	return false, false
}

// parseFlowControlLine matches "flow control" / "no flow control".
// PROVISIONAL (pinned live in phase 0a). Returns the resulting state
// (true = flow control on).
func parseFlowControlLine(fields []string) (on bool, ok bool) {
	switch {
	case len(fields) == 2 && fields[0] == "flow" && fields[1] == "control":
		return true, true
	case len(fields) == 3 && fields[0] == "no" && fields[1] == "flow" && fields[2] == "control":
		return false, true
	}
	return false, false
}

// --- PROVISIONAL port grammar renderers (pinned live in phase 0a) ---

// shutdownLine renders the disable template (enabled renders by
// absence). PROVISIONAL (pinned live in phase 0a).
func shutdownLine() string { return "shutdown" }

// flowControlLine renders the enable template (off renders by
// absence). PROVISIONAL (pinned live in phase 0a).
func flowControlLine() string { return "flow control" }

// describePortsDelta renders the human diff between the desired and
// the decoded port settings map for drift errors.
func describePortsDelta(want, got map[int]PortSettings) string {
	var deltas []string
	for port := 1; port <= defaultPortCount; port++ {
		w, wok := want[port]
		g, gok := got[port]
		if !wok || !gok {
			deltas = append(deltas, fmt.Sprintf("port %d missing (want=%v got=%v)", port, wok, gok))
			continue
		}
		if w != g {
			deltas = append(deltas, fmt.Sprintf("port %d: enabled=%v/%v flow_control=%v/%v qos=%q/%q ingress=%q/%q egress=%q/%q",
				port,
				w.Enabled, g.Enabled,
				w.FlowControl, g.FlowControl,
				w.QoSPriority, g.QoSPriority,
				w.IngressRate, g.IngressRate,
				w.EgressRate, g.EgressRate))
		}
	}
	if len(deltas) == 0 {
		return "identical"
	}
	return strings.Join(deltas, "; ")
}

// equalPortSettings compares the full 1..8 map (presence matters).
func equalPortSettings(a, b map[int]PortSettings) bool {
	if len(a) != len(b) {
		return false
	}
	for p, sa := range a {
		sb, ok := b[p]
		if !ok || sa != sb {
			return false
		}
	}
	return true
}
