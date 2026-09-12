package nsdp

import (
	"encoding/binary"
	"fmt"
)

// VLAN8021QMembership is one 802.1Q VLAN table entry (block 0x28, tag
// 0x2800): the VLAN ID plus its tagged and untagged port sets, carried as
// port bitmaps in the live-proven PortBitmap bit order — port N sets bit
// 1<<(8-N) (port 1 = 0x80 … port 8 = 0x01). Tagged/Untagged are the
// LOGICAL view: on the wire the entry carries MEMBER and TAGGED bitmaps
// and untagged is derived (see decode8021QEntry, resolved ROUND 19).
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

// decode8021QEntry decodes one 4-byte 0x2800 reply entry
// {vlan_id u16 BE, MEMBER bitmap u8, TAGGED bitmap u8}.
//
// ───────────────────────────────────────────────────────────────────────
// GAP-1 RESOLVED (ROUND 19 — casalta live probe, 2026-09-12,
// gaps-20260912-163538.log). The entry is NOT {vlan, tagged, untagged}:
// byte2 is the MEMBER superset, byte3 the TAGGED subset, and untagged is
// DERIVED (member AND NOT tagged), never carried on the wire.
//
// Live evidence, zero contradictions across all six production VLANs:
// the derived untagged set equals exactly the ports whose PVID is that
// VLAN (V1 untagged {1,2,3,6,7,8} = the PVID-1 ports; V10 untagged {5}
// = the PVID-10 port; V1001 untagged {4}; V5/V1000 0xFFFF = pure tagged
// leftovers — every port in both bytes, impossible under the old
// two-bitmap reading; V4094 members {1,2,8} tagged {1,2,8} = pure
// trunk). The old tagged/untagged payload was falsified on the wire:
// our stage-2 SET {03 e7 20 08} read as members {3}, tagged {5} —
// tagged NOT a subset of members — and the firmware silently dropped
// the whole membership, storing VLAN 999 empty with a OK reply.
//
// Production always carries tagged ⊆ member; byte3 is masked into
// byte2 anyway for safety, so a malformed entry can never report a
// tagged port outside the member set.
// ───────────────────────────────────────────────────────────────────
func decode8021QEntry(vlanID uint16, member, tagged byte) VLAN8021QMembership {
	return VLAN8021QMembership{
		VLANID:   vlanID,
		Tagged:   tagged & member,
		Untagged: member &^ tagged,
	}
}

// Get8021QVLANs reads the full 802.1Q VLAN table (block 0x28) and decodes
// every entry through decode8021QEntry — the ROUND 19 member/tagged
// model. Live replies carry one 4-byte TLV per VLAN {vlan_id u16 BE,
// member bitmap, tagged bitmap}; the walk also tolerates several
// concatenated entries per TLV, like the other nsdp table decoders.
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
			return nil, fmt.Errorf("nsdp: 0x%04x value length %d not a positive multiple of 4 for {vlan_id u16 BE, member, tagged}", a.Tag, len(v))
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
