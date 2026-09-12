package nsdp

import "testing"

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

// TestDecode8021QEntryDefaultRoles pins the CURRENT GAP-1 default
// (ProSafeLinux-derived): reply byte2 lands in Tagged, byte3 in
// Untagged. If the nsdp-gaps.sh verdict swaps the seam, THIS TEST swaps
// with it — the seam and this pin stay in lockstep.
func TestDecode8021QEntryDefaultRoles(t *testing.T) {
	m := decode8021QEntry(999, 0x20, 0x08)
	if m.VLANID != 999 || m.Tagged != 0x20 || m.Untagged != 0x08 {
		t.Fatalf("decode8021QEntry(999, 0x20, 0x08) = %+v, want byte2->Tagged, byte3->Untagged (GAP-1 default)", m)
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
