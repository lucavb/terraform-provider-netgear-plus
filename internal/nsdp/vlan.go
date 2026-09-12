package nsdp

import (
	"encoding/binary"
	"fmt"
)

// VLAN8021QMembership is one 802.1Q VLAN table entry (block 0x28, tag
// 0x2800): the VLAN ID plus its tagged and untagged port sets, carried as
// port bitmaps in the live-proven PortBitmap bit order — port N sets bit
// 1<<(8-N) (port 1 = 0x80 … port 8 = 0x01).
//
// GAP-1 PENDING: which of the two reply bytes carries the TAGGED set is
// not yet proven on live hardware. The role interpretation lives in
// exactly one place — decode8021QEntry below — whose comment block holds
// the pending-verdict swap procedure.
type VLAN8021QMembership struct {
	VLANID   uint16
	Tagged   uint8 // port bitmap: tagged member ports
	Untagged uint8 // port bitmap: untagged member ports
}

// TaggedPorts decodes the tagged bitmap to ascending 1-based port numbers.
func (m VLAN8021QMembership) TaggedPorts() []int { return PortsFromBitmap(m.Tagged) }

// UntaggedPorts decodes the untagged bitmap to ascending 1-based port
// numbers.
func (m VLAN8021QMembership) UntaggedPorts() []int { return PortsFromBitmap(m.Untagged) }

// NewVLAN8021QMembership builds a membership from the Set8021QVLAN
// argument form (VLAN id plus tagged/untagged port lists), encoding the
// port sets with PortBitmap.
func NewVLAN8021QMembership(vlanID int, tagged, untagged []int) VLAN8021QMembership {
	return VLAN8021QMembership{
		VLANID:   uint16(vlanID),
		Tagged:   PortBitmap(tagged),
		Untagged: PortBitmap(untagged),
	}
}

// PortsFromBitmap is the inverse of PortBitmap: every set bit becomes its
// 1-based port number, ascending. An empty bitmap yields nil.
func PortsFromBitmap(b uint8) []int {
	var ports []int
	for p := 1; p <= 8; p++ {
		if b&(1<<(8-p)) != 0 {
			ports = append(ports, p)
		}
	}
	return ports
}

// decode8021QEntry assigns roles to one 4-byte 0x2800 reply entry
// {vlan_id u16 BE, byte2, byte3}.
//
// ───────────────────────────────────────────────────────────────────────
// GAP-1 PENDING — role interpretation unproven on live hardware.
//
// The nsdp-gaps.sh stage-2 probe decides this (asymmetric VLAN 999:
// port 3 TAGGED, port 5 UNTAGGED, with a web-UI confirm cross-check;
// the interpretation matrix lives in the script and its log). One-line
// swap procedure per verdict branch:
//
//	ROLE A = tagged   (UI y) → keep as-is (byte2 = Tagged). No change.
//	ROLE A = untagged (UI y) → swap EXACTLY HERE, one line:
//	        Tagged: byte3, Untagged: byte2.
//	        (The write path is correct — only the read parser swaps.)
//	ROLE A = untagged (UI n) → swap HERE *and* the payload build in
//	        Set8021QVLAN (methods.go): the switch stores byte2 =
//	        UNTAGGED in BOTH directions, so the write order swaps too.
//	ROLE A = tagged   (UI n) → contradictory; re-probe, change nothing.
//
// Default assumption (current, ProSafeLinux-derived, matching
// Set8021QVLAN's payload order): byte2 = TAGGED, byte3 = UNTAGGED.
// This helper is the ONLY place reads assign roles — swap here and the
// whole library surface (Get8021QVLANs, the provider's vlan_state)
// follows. TestDecode8021QEntryDefaultRoles pins the default and must be
// updated together with any swap.
// ───────────────────────────────────────────────────────────────────────
func decode8021QEntry(vlanID uint16, byte2, byte3 byte) VLAN8021QMembership {
	return VLAN8021QMembership{VLANID: vlanID, Tagged: byte2, Untagged: byte3}
}

// Get8021QVLANs reads the full 802.1Q VLAN table (block 0x28) and decodes
// every entry through decode8021QEntry — the GAP-1 role seam. Live replies
// carry one 4-byte TLV per VLAN {vlan_id u16 BE, byte2, byte3}; the walk
// also tolerates several concatenated entries per TLV, like the other nsdp
// table decoders.
func (c *Client) Get8021QVLANs() ([]VLAN8021QMembership, error) {
	attrs, err := c.GetBlock(0x28, nil)
	if err != nil {
		return nil, fmt.Errorf("nsdp: read 802.1q vlan table (block 0x28): %w", err)
	}
	var out []VLAN8021QMembership
	for _, a := range attrs {
		if a.Tag != Tag8021QVLAN {
			continue
		}
		v := a.Value
		if len(v) == 0 || len(v)%4 != 0 {
			return nil, fmt.Errorf("nsdp: 0x%04x value length %d not a positive multiple of 4 for {vlan_id u16 BE, byte2, byte3}", a.Tag, len(v))
		}
		for off := 0; off+4 <= len(v); off += 4 {
			out = append(out, decode8021QEntry(
				binary.BigEndian.Uint16(v[off:off+2]),
				v[off+2], v[off+3]))
		}
	}
	return out, nil
}

// GetPVIDs reads the per-port PVID table (block 0x30): 3-byte entries
// {port u8 1-BASED, vlan_id u16 BE} — the CONFIRMED layout shared with
// the CLI render path (DecodeTLV's TagPVID case), surfaced here as a
// typed read for the vlan_state migration. SetPVID remains the write
// path.
func (c *Client) GetPVIDs() ([]PVIDEntry, error) {
	attrs, err := c.GetBlock(0x30, nil)
	if err != nil {
		return nil, fmt.Errorf("nsdp: read pvid table (block 0x30): %w", err)
	}
	var out []PVIDEntry
	for _, a := range attrs {
		if a.Tag != TagPVID {
			continue
		}
		d := DecodeTLV(TLV{Tag: a.Tag, Value: a.Value})
		entries, ok := d.Decoded.([]PVIDEntry)
		if !ok {
			return nil, fmt.Errorf("nsdp: 0x%04x: %s", a.Tag, d.Note)
		}
		out = append(out, entries...)
	}
	return out, nil
}
