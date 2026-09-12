package nsdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// TestEncodeBlockGetRequest pins the block-GET wire form (ROUND 6
// block↔tag unification): a GET whose TLV region holds TWO real TLVs —
// {marker 0x0014, len 0} + {tag blockID<<8, len, selector} — with the
// encodeSetTLVs quirk (the byte at wire offset 32 is the first TLV's
// tag-high). With no selector, block 0x78 is the live-proven 44-byte
// probe block sweep: byte-identical to the old {14,00,00,78} entry form
// reinterpreted as the two TLVs.
func TestEncodeBlockGetRequest(t *testing.T) {
	got := EncodeBlockGetRequest(goldenMAC, goldenAgentMAC, goldenSeq, 0x78, BlockMarkerV2, nil)
	want := []byte{
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // version, GET cmd, status/reserved, failing TLV, reserved
		0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8, // Manager ID (8-13)
		0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88, // Agent ID (14-19)
		0x00, 0x00, 0x0a, 0x02, // sequence 2562 (20-23)
		0x4e, 0x53, 0x44, 0x50, // "NSDP" (24-27)
		0x00, 0x00, 0x00, 0x00, // reserved (28-31)
		0x00, 0x14, 0x00, 0x00, // marker TLV {0x0014, len 0} (32-35; high byte = header's trailing 0)
		0x78, 0x00, 0x00, 0x00, // block TLV {0x7800, len 0} (36-39)
		0xff, 0xff, 0x00, 0x00, // terminator (40-43)
	}
	if len(got) != 44 || !bytes.Equal(got, want) {
		t.Fatalf("EncodeBlockGetRequest = %d bytes % x\nwant 44 bytes  % x", len(got), got, want)
	}

	// Selector case: block 0x94 with 2-byte selector {0xff, 0xff} rides as
	// the block TLV's value: 33-byte prefix + 3 + 6 + 4 = 46 bytes.
	got = EncodeBlockGetRequest(goldenMAC, goldenAgentMAC, 7, 0x94, BlockMarkerV2, []byte{0xff, 0xff})
	if len(got) != 46 {
		t.Fatalf("selector request length = %d, want 46", len(got))
	}
	if !bytes.Equal(got[36:42], []byte{0x94, 0x00, 0x00, 0x02, 0xff, 0xff}) {
		t.Fatalf("block TLV with selector = % x, want 94 00 00 02 ff ff", got[36:42])
	}
	if !bytes.Equal(got[42:46], []byte{0xff, 0xff, 0x00, 0x00}) {
		t.Fatalf("terminator after selector = % x, want ff ff 00 00", got[42:46])
	}

	// v1 marker: 0x000F instead of 0x0014 (nsdp.js:55 {0f,00,00,id}).
	got = EncodeBlockGetRequest(goldenMAC, goldenAgentMAC, 7, 0x74, BlockMarkerV1, nil)
	if len(got) != 44 || !bytes.Equal(got[32:40], []byte{0x00, 0x0f, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00}) {
		t.Fatalf("v1 marker request = % x, want 00 0f 00 00 74 00 00 00 in the TLV region", got)
	}
}

// TestDecodeTLV pins the typed decoders against the ROUND 7 reply formats
// as corrected by the third-party sources (ROUND 9/9b/10 notes).
func TestDecodeTLV(t *testing.T) {
	// One 49-byte 0x1000 per-port statistics entry: port 1 (1-BASED),
	// counters received/sent/packets/broadcast/multicast/errors = 1..6.
	portStats := []byte{0x01}
	for _, n := range []uint64{1, 2, 3, 4, 5, 6} {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], n)
		portStats = append(portStats, b[:]...)
	}
	cases := []struct {
		name    string
		tlv     TLV
		decoded any
		note    string // "" = no note expected; "substr" = note must contain
	}{
		{name: "model string", tlv: TLV{0x0001, []byte("GS108Ev3")}, decoded: "GS108Ev3"},
		{name: "system name", tlv: TLV{0x0003, []byte("lab-sw")}, decoded: "lab-sw"},
		{name: "system location string", tlv: TLV{0x0005, []byte("rack 4")}, decoded: "rack 4"},
		{name: "serial string trimmed", tlv: TLV{0x7800, []byte("22Y432P10012S\x00\x00\x00\x00\x00\x00\x00")}, decoded: "22Y432P10012S"},
		{name: "fw config string", tlv: TLV{0x7400, []byte("V2.06.24\x00")}, decoded: "V2.06.24"},
		{name: "fw image string", tlv: TLV{0x8000, []byte("V2.06.24")}, decoded: "V2.06.24"},
		{name: "fw image 1", tlv: TLV{0x000d, []byte("2.06.24GR")}, decoded: "2.06.24GR"},
		{name: "login composite marker empty", tlv: TLV{0x0012, []byte{}}, decoded: ""},
		{name: "model code BE16", tlv: TLV{0x0002, []byte{0x01, 0x02}}, decoded: uint16(0x0102)},
		{name: "mac address", tlv: TLV{0x0004, []byte{0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88}}, decoded: net.HardwareAddr{0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88}},
		{name: "ip address BE32", tlv: TLV{0x0006, []byte{192, 168, 0, 2}}, decoded: net.IP{192, 168, 0, 2}},
		{name: "netmask BE32", tlv: TLV{0x0007, []byte{255, 255, 255, 0}}, decoded: net.IP{255, 255, 255, 0}},
		{name: "gateway BE32", tlv: TLV{0x0008, []byte{192, 168, 0, 1}}, decoded: net.IP{192, 168, 0, 1}},
		{name: "u8 active image", tlv: TLV{0x000f, []byte{0x02}}, decoded: byte(0x02)},
		{name: "dhcp mode enum dhcp", tlv: TLV{0x000b, []byte{0x01}}, decoded: DHCPMode(1)},
		{name: "dhcp mode enum static", tlv: TLV{0x000b, []byte{0x00}}, decoded: DHCPMode(0)},
		{name: "dhcp mode enum refresh", tlv: TLV{0x000b, []byte{0x02}}, decoded: DHCPMode(2)},
		{name: "dhcp mode enum unknown", tlv: TLV{0x000b, []byte{0x07}}, decoded: DHCPMode(7)},
		{name: "capability BE32", tlv: TLV{0x0014, []byte{0x00, 0x00, 0x00, 0x10}}, decoded: uint32(0x10)},
		{name: "nonce raw", tlv: TLV{0x0017, []byte{0x91, 0x6e, 0x11, 0x22}}, decoded: nil, note: "raw nonce"},
		{
			name: "per-port traffic statistics",
			tlv:  TLV{0x1000, portStats},
			decoded: []PortTrafficStats{{
				Port: 1, Received: 1, Sent: 2, Packets: 3,
				Broadcast: 4, Multicast: 5, Errors: 6,
			}},
		},
		{name: "port stats bad length", tlv: TLV{0x1000, []byte{0x01, 0x02}}, decoded: nil, note: "multiple of 49"},
		{
			name:    "802.1q array",
			tlv:     TLV{0x2800, []byte{0x00, 0x03, 0x00, 0x64, 0x00, 0xc8, 0x01, 0x2c}},
			decoded: BE16Array{Prefix: 3, Entries: []uint16{100, 200, 300}},
			note:    "unverified",
		},
		{
			name:    "port based vlan 3-byte entry",
			tlv:     TLV{0x2400, []byte{0x00, 0x01, 0xe7}},
			decoded: []PortBasedVLANEntry{{VLANID: 1, Ports: 0xe7}},
		},
		{
			name:    "pvid confirmed 3-byte entries",
			tlv:     TLV{0x3000, []byte{0x01, 0x00, 0x64, 0x02, 0x01, 0x2c}},
			decoded: []PVIDEntry{{Port: 1, VLANID: 100}, {Port: 2, VLANID: 300}},
		},
		{name: "pvid bad length", tlv: TLV{0x3000, []byte{0x01, 0x00}}, decoded: nil, note: "not a multiple of 3"},
		{
			name:    "port qos confirmed 2-byte entries",
			tlv:     TLV{0x3800, []byte{0x01, 0x03, 0x02, 0x01}},
			decoded: []PortQoSEntry{{Port: 1, Priority: QoSPriority(3)}, {Port: 2, Priority: QoSPriority(1)}},
		},
		{name: "port qos odd length", tlv: TLV{0x3800, []byte{0x01}}, decoded: nil, note: "not a multiple of 2"},
		{
			name:    "ingress rate confirmed 5-byte layout",
			tlv:     TLV{0x4c00, []byte{0x01, 0x00, 0x00, 0x00, 0x05}},
			decoded: BandwidthEntry{Port: 1, Limit: 5},
		},
		{
			name:    "egress rate confirmed 5-byte layout",
			tlv:     TLV{0x5000, []byte{0x03, 0x00, 0x00, 0x01, 0x00}},
			decoded: BandwidthEntry{Port: 3, Limit: 256},
		},
		{
			name:    "broadcast storm rate confirmed 5-byte layout",
			tlv:     TLV{0x5800, []byte{0x08, 0x00, 0x00, 0x00, 0x0b}},
			decoded: BandwidthEntry{Port: 8, Limit: 11},
		},
		{
			name:    "bandwidth reserved bytes flagged",
			tlv:     TLV{0x4c00, []byte{0x01, 0x00, 0x01, 0x00, 0x05}},
			decoded: BandwidthEntry{Port: 1, Limit: 5},
			note:    "reserved bytes non-zero",
		},
		{
			name:    "port mirror 3-byte config",
			tlv:     TLV{0x5c00, []byte{0x08, 0x00, 0xc0}},
			decoded: PortMirrorConfig{DstPort: 8, Reserved: 0, SrcPorts: 0xc0},
			note:    "byte 2 semantics unknown",
		},
		{
			name:    "port mirror disabled",
			tlv:     TLV{0x5c00, []byte{0x00, 0x00, 0x00}},
			decoded: PortMirrorConfig{},
			note:    "byte 2 semantics unknown",
		},
		{
			name:    "igmp snooping confirmed 4-byte layout",
			tlv:     TLV{0x6800, []byte{0x00, 0x01, 0x00, 0x0a}},
			decoded: IGMPConfig{Enabled: 1, VLANID: 10},
		},
		{
			name:    "igmp snooping disabled",
			tlv:     TLV{0x6800, []byte{0x00, 0x00, 0x00, 0x00}},
			decoded: IGMPConfig{},
		},
		{
			name:    "vlan engine mode enum",
			tlv:     TLV{0x2000, []byte{0x03}},
			decoded: VLANEngineMode(3),
		},
		{
			name:    "speed/link 3-byte entries",
			tlv:     TLV{0x0c00, []byte{0x01, 0x05, 0x01, 0x02, 0x00, 0x00}},
			decoded: []SpeedLinkStatus{{Port: 1, Speed: 5, Flow: 1}, {Port: 2, Speed: 0, Flow: 0}},
		},
		{name: "speed/link bad length", tlv: TLV{0x0c00, []byte{0x01, 0x05}}, decoded: nil, note: "not a multiple of 3"},
		{
			name:    "port admin 3-byte entry",
			tlv:     TLV{0x9400, []byte{0x05, 0x01, 0x00}},
			decoded: []PortAdminStatusEntry{{Port: 5, Admin: 1, Flow: 0}},
		},
		{
			name:    "la group multi-entry",
			tlv:     TLV{0x8800, []byte{0x01, 0x00, 0x03, 0x02, 0x00, 0x01}},
			decoded: []PortEntry{{Port: 1, Value: 3}, {Port: 2, Value: 1}},
			note:    "UNVERIFIED",
		},
		{name: "unknown tag raw", tlv: TLV{0xb000, []byte{1, 2, 3}}, decoded: nil},
		{name: "len mismatch raw", tlv: TLV{0x0002, []byte{1, 2, 3}}, decoded: nil, note: "unexpected length"},
		{name: "odd array raw", tlv: TLV{0x2800, []byte{0x00, 0x01, 0x02}}, decoded: nil, note: "odd or short"},
	}
	for _, tc := range cases {
		a := DecodeTLV(tc.tlv)
		if !equalDecoded(a.Decoded, tc.decoded) {
			t.Errorf("%s: Decoded = %#v, want %#v", tc.name, a.Decoded, tc.decoded)
		}
		if tc.note != "" && !contains(a.Note, tc.note) {
			t.Errorf("%s: Note = %q, want substring %q", tc.name, a.Note, tc.note)
		}
		if tc.note == "" && a.Note != "" {
			t.Errorf("%s: Note = %q, want none", tc.name, a.Note)
		}
	}
	// Name-table spot checks via the same decodes.
	if n := TagName(0x7800); n != "serial number" {
		t.Errorf("TagName(0x7800) = %q, want %q", n, "serial number")
	}
	if n := TagName(0x1000); n != "per-port traffic statistics" {
		t.Errorf("TagName(0x1000) = %q, want %q", n, "per-port traffic statistics")
	}
	if n := TagName(0x0005); n != "system location" {
		t.Errorf("TagName(0x0005) = %q, want %q", n, "system location")
	}
	for tag, want := range map[uint16]string{
		TagNewPassword: "new password",
		TagOldPassword: "old password",
	} {
		if n := TagName(tag); !contains(n, want) {
			t.Errorf("TagName(0x%04x) = %q, want substring %q", tag, n, want)
		}
	}
	if n := TagName(0xbeef); n != "" {
		t.Errorf("TagName(0xbeef) = %q, want empty", n)
	}
}

func equalDecoded(got, want any) bool {
	switch w := want.(type) {
	case []PortEntry:
		g, ok := got.([]PortEntry)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if g[i] != w[i] {
				return false
			}
		}
		return true
	case []PortAdminStatusEntry:
		g, ok := got.([]PortAdminStatusEntry)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if g[i] != w[i] {
				return false
			}
		}
		return true
	case []PortBasedVLANEntry:
		g, ok := got.([]PortBasedVLANEntry)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if g[i] != w[i] {
				return false
			}
		}
		return true
	case []PVIDEntry:
		g, ok := got.([]PVIDEntry)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if g[i] != w[i] {
				return false
			}
		}
		return true
	case []PortQoSEntry:
		g, ok := got.([]PortQoSEntry)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if g[i] != w[i] {
				return false
			}
		}
		return true
	case []PortTrafficStats:
		g, ok := got.([]PortTrafficStats)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if g[i] != w[i] {
				return false
			}
		}
		return true
	case []SpeedLinkStatus:
		g, ok := got.([]SpeedLinkStatus)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if g[i] != w[i] {
				return false
			}
		}
		return true
	case BE16Array:
		g, ok := got.(BE16Array)
		if !ok || g.Prefix != w.Prefix || len(g.Entries) != len(w.Entries) {
			return false
		}
		for i := range w.Entries {
			if g.Entries[i] != w.Entries[i] {
				return false
			}
		}
		return true
	case net.HardwareAddr:
		g, ok := got.(net.HardwareAddr)
		return ok && bytes.Equal(g, w)
	case net.IP:
		g, ok := got.(net.IP)
		return ok && bytes.Equal(g, w)
	default:
		return got == nil && want == nil || got == want
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// TestClientDump drives a full Dump against the fake switch: ONE multi-tag
// batch request for the small tags, one block request per default block,
// the block retry schedule for silent blocks (14 attempts, fresh sequence
// each), warn-and-continue semantics (missing blocks land in
// BlockResult.Err, the dump still succeeds).
func TestClientDump(t *testing.T) {
	sim := &switchSim{
		capability: goldenCapability,
		nonce:      []byte{0x91, 0x6e, 0x11, 0x22},
		name:       []byte("lab-sw"),
		attrs: map[byte][]byte{
			0x01: []byte("GS108Ev3"),
			0x02: []byte{0x01, 0x02},
			0x06: []byte{192, 168, 0, 2},
			0x0d: []byte("V2.06.24"),
			0x12: []byte{0x01},
		},
		blocks: map[byte][]TLV{
			0x78: {{Tag: 0x7800, Value: []byte("22Y432P10012S\x00\x00\x00\x00\x00\x00\x00")}},
			0x94: {{Tag: 0x9400, Value: []byte{0x01, 0x00, 0x01, 0x02, 0x00, 0x00}}},
		},
	}
	c := &Client{
		conn:     sim,
		dst:      broadcastUDP(),
		mac:      goldenMAC,
		agentMAC: goldenAgentMAC,
		wait:     time.Millisecond,
		seq:      9000,
	}
	res, err := c.Dump()
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}

	// Small-tag attrs: sorted, decoded. Tags answered: 01,02,03,06,0d,12
	// (attrs/name) + 14 (capability) + 17 (nonce) = 8.
	if len(res.Attrs) != 8 {
		t.Fatalf("dump collected %d small-tag attrs (%+v), want 8", len(res.Attrs), res.Attrs)
	}
	byTag := map[uint16]Attr{}
	for _, a := range res.Attrs {
		byTag[a.Tag] = a
	}
	if got := byTag[0x0001]; got.Decoded != "GS108Ev3" {
		t.Errorf("attr 0x0001 decoded = %#v, want %q", got.Decoded, "GS108Ev3")
	}
	if got := byTag[0x0002]; got.Decoded != uint16(0x0102) {
		t.Errorf("attr 0x0002 decoded = %#v, want 258", got.Decoded)
	}
	if got := byTag[0x0003]; got.Decoded != "lab-sw" {
		t.Errorf("attr 0x0003 decoded = %#v, want %q", got.Decoded, "lab-sw")
	}
	ip, ok := byTag[0x0006].Decoded.(net.IP)
	if !ok || !ip.Equal(net.IPv4(192, 168, 0, 2)) {
		t.Errorf("attr 0x0006 decoded = %#v, want 192.168.0.2", byTag[0x0006].Decoded)
	}
	if got := byTag[0x000d]; got.Decoded != "V2.06.24" {
		t.Errorf("attr 0x000d decoded = %#v, want %q", got.Decoded, "V2.06.24")
	}
	if got := byTag[0x0014]; got.Decoded != uint32(goldenCapability) {
		t.Errorf("attr 0x0014 decoded = %#v, want %d", got.Decoded, goldenCapability)
	}
	if got := byTag[0x0017]; got.Decoded != nil || !contains(got.Note, "raw nonce") {
		t.Errorf("attr 0x0017 = decoded %#v note %q, want raw nonce note", got.Decoded, got.Note)
	}
	for i := 1; i < len(res.Attrs); i++ {
		if res.Attrs[i-1].Tag >= res.Attrs[i].Tag {
			t.Fatalf("attrs not sorted by tag: %v", res.Attrs)
		}
	}

	// Blocks: 0x78 and 0x94 answered; the rest silent (Err, dump continues).
	if len(res.Blocks) != len(DefaultDumpBlockIDs) {
		t.Fatalf("dump collected %d block results, want %d", len(res.Blocks), len(DefaultDumpBlockIDs))
	}
	for _, b := range res.Blocks {
		switch b.BlockID {
		case 0x78:
			if b.Err != nil {
				t.Fatalf("block 0x78: %v", b.Err)
			}
			if len(b.Attrs) != 1 || b.Attrs[0].Decoded != "22Y432P10012S" {
				t.Errorf("block 0x78 attrs = %+v", b.Attrs)
			}
		case 0x94:
			if b.Err != nil {
				t.Fatalf("block 0x94: %v", b.Err)
			}
			entries, ok := b.Attrs[0].Decoded.([]PortAdminStatusEntry)
			if !ok || len(entries) != 2 || entries[0] != (PortAdminStatusEntry{Port: 1, Admin: 0, Flow: 1}) || entries[1] != (PortAdminStatusEntry{Port: 2, Admin: 0, Flow: 0}) {
				t.Errorf("block 0x94 decoded = %#v", b.Attrs[0].Decoded)
			}
			if b.Attrs[0].Note != "" {
				t.Errorf("block 0x94 note = %q, want none (layout live-confirmed)", b.Attrs[0].Note)
			}
		default:
			if b.Err == nil || !errors.Is(b.Err, ErrNoReply) {
				t.Errorf("block 0x%02x: Err = %v, want ErrNoReply", b.BlockID, b.Err)
			}
		}
	}

	// Request shape: exactly ONE small-tag batch request (no other small-tag
	// GETs), one block request per answered block, and the full 14-attempt
	// retry schedule per silent block — with a fresh sequence per attempt.
	batch, blockReqs := 0, map[byte][]uint32{}
	for _, req := range sim.written {
		if req[1] != cmdGet {
			continue
		}
		if req[33] == attrCapability && req[36] != 0 { // block GET
			blockReqs[req[36]] = append(blockReqs[req[36]], binary.BigEndian.Uint32(req[20:24]))
		} else {
			batch++
		}
	}
	if batch != 1 {
		t.Fatalf("small-tag batch requests = %d, want 1", batch)
	}
	for _, id := range DefaultDumpBlockIDs {
		want := defaultAttempts
		if id == 0x78 || id == 0x94 {
			want = 1
		}
		if len(blockReqs[id]) != want {
			t.Errorf("block 0x%02x requests = %d, want %d", id, len(blockReqs[id]), want)
		}
	}
	for id, seqs := range blockReqs {
		for i := 1; i < len(seqs); i++ {
			if seqs[i] <= seqs[i-1] {
				t.Errorf("block 0x%02x sequences not increasing: %v", id, seqs)
			}
		}
	}
}

// TestSetRawAuthBeforeUserTLV drives the auto-login + nonce refresh +
// SetRaw flow against the fake switch and pins the wire discipline: the
// auth TLV (refreshed token — ROUND 8: the login SET rolled the nonce —
// tag per capability branch) precedes the user TLV, both followed by the
// terminator.
func TestSetRawAuthBeforeUserTLV(t *testing.T) {
	nonce := []byte{0x91, 0x6e, 0x11, 0x22}
	password := []byte("hunter2")
	sim := &switchSim{
		capability: goldenCapability,
		nonce:      append([]byte(nil), nonce...),
		name:       []byte("old-name"),
		password:   append([]byte(nil), password...),
	}
	c := &Client{
		conn:     sim,
		dst:      broadcastUDP(),
		mac:      goldenMAC,
		agentMAC: goldenAgentMAC,
		password: password,
		wait:     time.Millisecond,
		seq:      5000,
	}
	if err := c.SetRaw(TagPortAdminStatus, []byte{0x01, 0x00, 0x01}); err != nil {
		t.Fatalf("SetRaw: %v", err)
	}
	reqs := sim.written
	if len(reqs) != 5 {
		t.Fatalf("sent %d requests, want 5 (GET 0x14, GET 0x17, SET login, GET 0x17 refresh, SET raw)", len(reqs))
	}
	// Request 3: the ROUND 8 nonce refresh between login SET and raw SET.
	if reqs[3][1] != cmdGet || reqs[3][33] != attrNonce {
		t.Fatalf("request 3 is not a GET attr 0x17 nonce refresh: % x", reqs[3])
	}
	raw := reqs[4]
	if raw[1] != cmdSet {
		t.Fatalf("raw request cmd byte = 0x%02x, want 0x03", raw[1])
	}
	// 33-byte prefix + auth TLV 12 + user TLV (2+2+3) + terminator 4 = 55.
	if len(raw) != 55 {
		t.Fatalf("raw request = %d bytes, want 55", len(raw))
	}
	// The login SET rolled the sim's nonce; the raw SET must carry the
	// token for the rolled nonce.
	wantToken := loginToken(goldenCapability, incBE(nonce), goldenAgentMAC, password)
	authTLV := append([]byte{0x00, byte(loginTagV2), 0x00, byte(len(wantToken))}, wantToken...)
	if !bytes.Equal(raw[32:32+len(authTLV)], authTLV) {
		t.Fatalf("auth TLV = % x, want tag 0x001a len %d + refreshed token % x", raw[32:], len(wantToken), wantToken)
	}
	off := 32 + len(authTLV)
	if !bytes.Equal(raw[off:off+7], []byte{0x94, 0x00, 0x00, 0x03, 0x01, 0x00, 0x01}) {
		t.Fatalf("user TLV = % x, want {0x9400, len 3, 01 00 01} after the auth TLV", raw[off:off+7])
	}
	if !bytes.Equal(raw[off+7:], []byte{0xff, 0xff, 0x00, 0x00}) {
		t.Fatalf("terminator = % x", raw[off+7:])
	}
}
