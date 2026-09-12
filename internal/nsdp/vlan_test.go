package nsdp

import (
	"bytes"
	"testing"
)

// TestPortsFromBitmap pins the PortBitmap bit order's inverse: port N =
// bit 1<<(8-N), ascending port output, empty bitmap = nil.
func TestPortsFromBitmap(t *testing.T) {
	cases := []struct {
		b    byte
		want []int
	}{
		{0x00, nil},
		{0x80, []int{1}},
		{0x01, []int{8}},
		{0x20, []int{3}},
		{0x08, []int{5}},
		{0x3e, []int{3, 4, 5, 6, 7}}, // the live restore-experiment bitmap (ports 3-7)
		{0xff, []int{1, 2, 3, 4, 5, 6, 7, 8}},
	}
	for _, tc := range cases {
		got := PortsFromBitmap(tc.b)
		if len(got) != len(tc.want) {
			t.Fatalf("PortsFromBitmap(0x%02x) = %v, want %v", tc.b, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("PortsFromBitmap(0x%02x) = %v, want %v", tc.b, got, tc.want)
			}
		}
	}
}

// TestPortBitmapRoundTrip: PortBitmap and PortsFromBitmap are inverses.
func TestPortBitmapRoundTrip(t *testing.T) {
	lists := [][]int{
		{1},
		{8},
		{3, 5},
		{1, 2, 8},
		{2, 3, 4, 5, 6, 7},
	}
	for _, ports := range lists {
		b := PortBitmap(ports)
		back := PortsFromBitmap(b)
		if len(back) != len(ports) {
			t.Fatalf("port list %v -> bitmap 0x%02x -> %v: length changed", ports, b, back)
		}
		for i := range back {
			if back[i] != ports[i] {
				t.Fatalf("port list %v -> bitmap 0x%02x -> %v: not round-tripped", ports, b, back)
			}
		}
	}
}

// TestNewVLAN8021QMembership builds the Set8021QVLAN argument form and
// reads it back through the port helpers — exactly the nsdp-gaps.sh
// stage-2 probe shape (port 3 tagged, port 5 untagged).
func TestNewVLAN8021QMembership(t *testing.T) {
	m := NewVLAN8021QMembership(999, []int{3}, []int{5})
	if m.VLANID != 999 || m.Tagged != 0x20 || m.Untagged != 0x08 {
		t.Fatalf("membership = %+v, want {999, Tagged 0x20, Untagged 0x08}", m)
	}
	if tp := m.TaggedPorts(); len(tp) != 1 || tp[0] != 3 {
		t.Fatalf("TaggedPorts() = %v, want [3]", tp)
	}
	if up := m.UntaggedPorts(); len(up) != 1 || up[0] != 5 {
		t.Fatalf("UntaggedPorts() = %v, want [5]", up)
	}
}

// TestDecode8021QEntryMemberTagged pins the ROUND 19 wire model
// (resolved live, casalta 2026-09-12): byte2 = MEMBER superset,
// byte3 = TAGGED subset, untagged derived (member AND NOT tagged).
// Tagged bits outside the member set are masked away — production
// always carries tagged ⊆ members, and the mask keeps a malformed
// entry from reporting a tagged non-member.
func TestDecode8021QEntryMemberTagged(t *testing.T) {
	// The probe shape: members {3,5}, tagged {3} -> tagged {3},
	// untagged {5}.
	if m := decode8021QEntry(999, 0x28, 0x20); m.Tagged != 0x20 || m.Untagged != 0x08 {
		t.Fatalf("decode8021QEntry(999, member 0x28, tagged 0x20) = %+v, want {Tagged 0x20, Untagged 0x08}", m)
	}
	// The FALSIFIED old payload read under the real model: tagged {5}
	// is not a member -> masked to nothing; member {3} derives
	// untagged. (This is the SET the real firmware dropped wholesale.)
	if m := decode8021QEntry(999, 0x20, 0x08); m.Tagged != 0x00 || m.Untagged != 0x20 {
		t.Fatalf("decode8021QEntry(999, member 0x20, tagged 0x08) = %+v, want the non-member tagged bits masked ({Tagged 0x00, Untagged 0x20})", m)
	}
}

// TestDecode8021QProductionSnapshot pins the real-wire regression data
// from the casalta GS108Ev3 production snapshot (ROUND 19,
// gaps-20260912-163538.log stage 0c, 2026-09-12): all six production
// 0x2800 entries decode under the member/tagged model with the derived
// untagged set equal to exactly the ports whose PVID is that VLAN
// (stage-0 PVID table: port 4 -> 1001, port 5 -> 10, all others -> 1) —
// six out of six, zero contradictions. The entryBE16 values are the
// log's exact "entries=" decimals (BE16 over {member, tagged}).
func TestDecode8021QProductionSnapshot(t *testing.T) {
	snapshot := []struct {
		vlan      uint16
		entryBE16 uint16 // the log's decimal entries= value
		tagged    []int
		untagged  []int
		why       string
	}{
		{1, 59136, nil, []int{1, 2, 3, 6, 7, 8}, "untagged = exactly the PVID-1 ports"},
		{5, 65535, []int{1, 2, 3, 4, 5, 6, 7, 8}, nil, "pure tagged leftover (0xFFFF: every port in both bytes)"},
		{10, 65527, []int{1, 2, 3, 4, 6, 7, 8}, []int{5}, "untagged {5} = the PVID-10 port"},
		{1000, 65535, []int{1, 2, 3, 4, 5, 6, 7, 8}, nil, "pure tagged leftover"},
		{1001, 65519, []int{1, 2, 3, 5, 6, 7, 8}, []int{4}, "untagged {4} = the PVID-1001 port"},
		{4094, 49601, []int{1, 2, 8}, nil, "pure trunk on production ports"},
	}
	for _, s := range snapshot {
		m := decode8021QEntry(s.vlan, byte(s.entryBE16>>8), byte(s.entryBE16&0xff))
		if m.VLANID != s.vlan {
			t.Fatalf("vlan id = %d, want %d", m.VLANID, s.vlan)
		}
		if got := m.TaggedPorts(); !equalPorts(got, s.tagged) {
			t.Fatalf("VLAN %d (entries=%d): TaggedPorts() = %v, want %v (%s)", s.vlan, s.entryBE16, got, s.tagged, s.why)
		}
		if got := m.UntaggedPorts(); !equalPorts(got, s.untagged) {
			t.Fatalf("VLAN %d (entries=%d): UntaggedPorts() = %v, want %v (%s)", s.vlan, s.entryBE16, got, s.untagged, s.why)
		}
	}
}

// equalPorts compares two port lists treating nil and empty as equal.
func equalPorts(a, b []int) bool {
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

// TestSet8021QVLANPayload pins the SET wire bytes under the ROUND 19
// model: byte2 = member superset (tagged|untagged), byte3 = tagged
// subset.
func TestSet8021QVLANPayload(t *testing.T) {
	cases := []struct {
		name          string
		vlanID        int
		tagged, untag []int
		want          []byte
		source        string
	}{
		{
			name:   "probe shape: 999 tagged {3} untagged {5}",
			vlanID: 999, tagged: []int{3}, untag: []int{5},
			want:   []byte{0x03, 0xe7, 0x28, 0x20},
			source: "the corrected stage-2 probe: members {3,5}=0x28, tagged {3}=0x20",
		},
		{
			name:   "production VLAN 4094 pure trunk",
			vlanID: 4094, tagged: []int{1, 2, 8}, untag: nil,
			want:   []byte{0x0f, 0xfe, 0xc1, 0xc1},
			source: "matches the live production 4094 entry 0xC1C1 byte for byte",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := vlan8021QPayload(tc.vlanID, tc.tagged, tc.untag)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("vlan8021QPayload(%d, %v, %v) = % x, want % x (%s)", tc.vlanID, tc.tagged, tc.untag, got, tc.want, tc.source)
			}
		})
	}
}

// TestSerialFromBlob covers the identity serial decode: the pinned live
// layout, the trailing NUL/space trimming, the printable-run fallback
// and the too-short/empty rejects.
func TestSerialFromBlob(t *testing.T) {
	// Live GS108Ev3 blob (ROUND 11): {0x01, 0x33, 12-char serial, 0x00,
	// trailing RAM garbage} — 21 bytes.
	live := append([]byte{0x01, 0x33}, []byte("UH77B5R033EE")...)
	live = append(live, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00)
	if got := serialFromBlob(live); got != "UH77B5R033EE" {
		t.Fatalf("serialFromBlob(live 21-byte blob) = %q, want UH77B5R033EE", got)
	}
	// Short serial padded into the pinned window: NULs break the
	// printable window, but the run fallback plus trim recovers it.
	padded := append([]byte{0x01, 0x33}, []byte("SN123456  \x00\x00")...)
	if got := serialFromBlob(padded); got != "SN123456" {
		t.Fatalf("serialFromBlob(padded) = %q, want SN123456 (trailing NULs/spaces trimmed)", got)
	}
	// No pinned prefix at all: longest printable run (>= 8 bytes) wins.
	fallback := []byte("\xff\xffSERIAL9876\x00\x00")
	if got := serialFromBlob(fallback); got != "SERIAL9876" {
		t.Fatalf("serialFromBlob(fallback) = %q, want SERIAL9876", got)
	}
	// Printable runs shorter than 8 bytes and empty blobs reject.
	if got := serialFromBlob([]byte{0x01, 0x33, 'A', 'B'}); got != "" {
		t.Fatalf("serialFromBlob(short) = %q, want \"\"", got)
	}
	if got := serialFromBlob(nil); got != "" {
		t.Fatalf("serialFromBlob(nil) = %q, want \"\"", got)
	}
}
