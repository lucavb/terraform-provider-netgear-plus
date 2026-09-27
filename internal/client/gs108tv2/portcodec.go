package gs108tv2

import (
	"fmt"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/fastpath"
)

// PortSettings is the per-port admin state surface, mirroring the
// provider's port_config resource semantics:
//
//	Enabled      = port admin state   (factory: true)
//	FlowControl  = flow control on/off (factory: false)
//	QoSPriority  = "high"/"middle"/"normal"/"low" (default: "low",
//	               rendered by absence; WRITES are refused today)
//	IngressRate  = "none" or "N×" shaping (default "none"; WRITES
//	               are refused today)
//	EgressRate   = same shape as IngressRate
//
// defaults render BY ABSENCE — the factory file has empty interface
// bodies, so an all-default desired map renders byte-identically to
// the fetched config (short-circuit friendly).
type PortSettings struct {
	Enabled     bool
	FlowControl bool
	QoSPriority string
	IngressRate string
	EgressRate  string
}

// Default QoS value: renders by absence like the other defaults, and
// is the only value the capability table lets through until the
// attribute grammar is pinned.
const defaultQoSPriority = "low"

// Default rate values (absence-rendered).
const defaultRate = "none"

// DefaultPortSettings is the factory value set for one port.
func DefaultPortSettings() PortSettings {
	return PortSettings{
		Enabled:     true,
		FlowControl: false,
		QoSPriority: defaultQoSPriority,
		IngressRate: defaultRate,
		EgressRate:  defaultRate,
	}
}

// DefaultPortSettingsMap covers all managed ports 1..8.
func DefaultPortSettingsMap() map[int]PortSettings {
	out := make(map[int]PortSettings, defaultPortCount)
	for port := 1; port <= defaultPortCount; port++ {
		out[port] = DefaultPortSettings()
	}
	return out
}

// ErrUnsupportedAttribute is the typed pre-upload refusal for a
// non-default value of an attribute whose text-config grammar is not
// pinned yet (capability status Unsupported). Nothing is uploaded
// when this is returned past validation.
type ErrUnsupportedAttribute struct {
	Port      int    // 0 = not port-bound (capability-level refusal)
	Attribute string // capability key, e.g. "qos_priority"
	Value     string // requested value
	Reason    string
}

func (e *ErrUnsupportedAttribute) Error() string {
	attrib := e.Attribute
	if e.Port > 0 {
		attrib = fmt.Sprintf("port %d %s", e.Port, attrib)
	}
	return fmt.Sprintf("gs108tv2: refusing to set %s to %q: %s", attrib, e.Value, e.Reason)
}

// validatePortSettings runs the capability table over the desired
// (normalized) port map BEFORE any network traffic: unsupported
// attributes may only carry their default value (absence render).
// PROVISIONAL: relaxing entries in PortSettingCapabilities is the
// single lever once phase 0a pins more grammar.
func validatePortSettings(desired map[int]PortSettings) error {
	for port := 1; port <= defaultPortCount; port++ {
		ps, ok := desired[port]
		if !ok {
			return &ErrUnsupportedAttribute{
				Port:      port,
				Attribute: "enabled",
				Value:     "<absent from desired map>",
				Reason:    "desired port settings must cover all managed ports 1..8 (missing entries are refused, not defaulted)",
			}
		}
		if cap, capok := PortSettingCapabilities["qos_priority"]; capok && cap.Status == AttributeUnsupported && ps.QoSPriority != defaultQoSPriority {
			return &ErrUnsupportedAttribute{Port: port, Attribute: "qos_priority", Value: ps.QoSPriority, Reason: cap.Reason}
		}
		if cap := PortSettingCapabilities["ingress_rate"]; cap.Status == AttributeUnsupported && ps.IngressRate != defaultRate {
			return &ErrUnsupportedAttribute{Port: port, Attribute: "ingress_rate", Value: ps.IngressRate, Reason: cap.Reason}
		}
		if cap := PortSettingCapabilities["egress_rate"]; cap.Status == AttributeUnsupported && ps.EgressRate != defaultRate {
			return &ErrUnsupportedAttribute{Port: port, Attribute: "egress_rate", Value: ps.EgressRate, Reason: cap.Reason}
		}
	}
	return nil
}

// normalizePortSettings fills missing ports with factory defaults so
// the desired map covers all managed ports.
func normalizePortSettings(desired map[int]PortSettings) map[int]PortSettings {
	norm := DefaultPortSettingsMap()
	for port, ps := range desired {
		if port < 1 || port > defaultPortCount {
			continue
		}
		norm[port] = ps
	}
	return norm
}

// renderPortSettings splices the desired port settings into the
// editor's interface 0/1..0/8 bodies: port-grammar lines are
// regenerated from the desired map, everything else (vlan pvid lines,
// foreign lines) passes through in its original order — the port
// codec never edits the VLAN namespace. Sections missing from the
// fetched config are left untouched.
// PROVISIONAL (pinned live in phase 0a).
func renderPortSettings(editor *fastpath.TextConfigEditor, tc fastpath.TextConfig, desired map[int]PortSettings, passthrough map[string][]string) ([]byte, error) {
	for port := 1; port <= defaultPortCount; port++ {
		label := fmt.Sprintf("interface 0/%d", port)
		if _, ok := tc.Section(label); !ok {
			continue
		}
		var managed []string
		ps := desired[port]
		if !ps.Enabled {
			managed = append(managed, shutdownLine())
		}
		if ps.FlowControl {
			managed = append(managed, flowControlLine())
		}
		body := append(append([]string{}, passthrough[label]...), managed...)
		if err := editor.ReplaceSectionBody(label, body); err != nil {
			return nil, err
		}
	}
	return editor.Render()
}
