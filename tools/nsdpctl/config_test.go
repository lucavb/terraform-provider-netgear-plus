package main

import (
	"encoding/binary"
	"testing"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// TestRenderValueLiveFixtures pins renderValue against bytes observed on a
// live GS108Ev3 (ROUND 11 dump, ROUND 12b composite) and against the
// source-confirmed layouts, always exercised through the real DecodeTLV so
// decoder regressions surface here too.
func TestRenderValueLiveFixtures(t *testing.T) {
	tests := []struct {
		name string
		tlv  nsdp.TLV
		want string
	}{
		{
			name: "dhcp mode static (live)",
			tlv:  nsdp.TLV{Tag: nsdp.TagDHCPMode, Value: []byte{0x00}},
			want: "Static",
		},
		{
			name: "speed/link port 1 connected (live)",
			tlv:  nsdp.TLV{Tag: nsdp.TagSpeedLinkStatus, Value: []byte{0x01, 0x05, 0x00}},
			want: "port 1: speed=5 flow=0",
		},
		{
			name: "speed/link port 3 idle (live)",
			tlv:  nsdp.TLV{Tag: nsdp.TagSpeedLinkStatus, Value: []byte{0x03, 0x00, 0x00}},
			want: "port 3: speed=0 flow=0",
		},
		{
			name: "pvid port 4 on vlan 1001 (live)",
			tlv:  nsdp.TLV{Tag: nsdp.TagPVID, Value: []byte{0x04, 0x03, 0xe9}},
			want: "port 4: pvid=1001",
		},
		{
			name: "pvid port 5 on vlan 10 (live)",
			tlv:  nsdp.TLV{Tag: nsdp.TagPVID, Value: []byte{0x05, 0x00, 0x0a}},
			want: "port 5: pvid=10",
		},
		{
			name: "port admin status 0x9400 (live)",
			tlv:  nsdp.TLV{Tag: nsdp.TagPortAdminStatus, Value: []byte{0x01, 0x01, 0x00}},
			want: "port 1: admin=1 flow=0",
		},
		{
			name: "qos mode port-based (live)",
			tlv:  nsdp.TLV{Tag: nsdp.TagQoSMode, Value: []byte{0x01}},
			want: "port-based",
		},
		{
			name: "qos mode 802.1p",
			tlv:  nsdp.TLV{Tag: nsdp.TagQoSMode, Value: []byte{0x02}},
			want: "802.1p",
		},
		{
			name: "block unknown multicast on (live)",
			tlv:  nsdp.TLV{Tag: nsdp.TagBlockUnknownMulticast, Value: []byte{0x01}},
			want: "1",
		},
		{
			name: "port based vlan entry (live)",
			tlv:  nsdp.TLV{Tag: nsdp.TagPortBasedVLAN, Value: []byte{0x00, 0x01, 0xe7}},
			want: "vlan 1: ports=0xe7",
		},
		{
			name: "qos port 1 normal",
			tlv:  nsdp.TLV{Tag: nsdp.TagPortBasedQoS, Value: []byte{0x01, 0x03}},
			want: "port 1: priority=Normal",
		},
		{
			name: "ingress bandwidth limit 100",
			tlv:  nsdp.TLV{Tag: nsdp.TagIngressRate, Value: []byte{0x01, 0x00, 0x00, 0x00, 0x64}},
			want: "port 1: limit=100",
		},
		{
			name: "igmp snooping enabled on vlan 10",
			tlv:  nsdp.TLV{Tag: nsdp.TagIGMPSnooping, Value: []byte{0x00, 0x01, 0x00, 0x0a}},
			want: "enabled=1 vlan=10",
		},
		{
			name: "port mirror dst 1 src bitmap aa",
			tlv:  nsdp.TLV{Tag: nsdp.TagPortMirroring, Value: []byte{0x01, 0x00, 0xaa}},
			want: "dst=1 src-ports=0xaa reserved=0x00",
		},
		{
			name: "per-port traffic statistics",
			tlv:  nsdp.TLV{Tag: nsdp.TagPortTrafficStats, Value: portStatsValue(2, 100, 200, 300, 10, 20, 0)},
			want: "port 2: rx=100 tx=200 pkt=300 bcst=10 mcst=20 err=0",
		},
		{
			name: "serial blob pinned layout (live 21 bytes)",
			tlv: nsdp.TLV{Tag: nsdp.TagSerialNumber, Value: []byte{
				0x01, 0x33, 'U', 'H', '7', '7', 'B', '5', 'R', '0', '3', '3', 'E', 'E', 0x00,
				'Z', 'v', 'S', 'o', 'I', 'o',
			}},
			want: "serial UH77B5R033EE (+7 trailing bytes)",
		},
		{
			name: "serial blob printable-run fallback",
			tlv: nsdp.TLV{Tag: nsdp.TagSerialNumber, Value: append([]byte{0x00, 0xff, 0x00},
				append([]byte("UH77B5R033EE"), 0x00)...)},
			want: "serial UH77B5R033EE (+1 trailing bytes)",
		},
		{
			name: "login blob with suspected {00 12} trailing",
			tlv: nsdp.TLV{Tag: nsdp.TagString0011, Value: []byte{
				0x00, 0x14, 0x00, 0x04, 0x00, 0x00, 0x00, 0x10,
				0x00, 0x17, 0x00, 0x04, 0x5c, 0x8e, 0x0a, 0x2c,
				0x00, 0x12,
			}},
			want: "login blob: capability=0x00000010 nonce=5c 8e 0a 2c trailing=00 12",
		},
		{
			name: "login blob with terminator tail",
			tlv: nsdp.TLV{Tag: nsdp.TagString0011, Value: []byte{
				0x00, 0x14, 0x00, 0x04, 0x00, 0x00, 0x00, 0x10,
				0x00, 0x17, 0x00, 0x04, 0x4e, 0x5d, 0x1a, 0x8e,
				0xff, 0xff,
			}},
			want: "login blob: capability=0x00000010 nonce=4e 5d 1a 8e trailing=ff ff",
		},
		{
			name: "plain string decode quotes",
			tlv:  nsdp.TLV{Tag: nsdp.TagSystemName, Value: []byte("lab-test\x00\x00")},
			want: `"lab-test"`,
		},
		{
			name: "scalar uint8",
			tlv:  nsdp.TLV{Tag: nsdp.TagScalar000c, Value: []byte{0x01}},
			want: "1",
		},
		{
			name: "raw hex fallback",
			tlv:  nsdp.TLV{Tag: 0x0013, Value: []byte{0xde, 0xad}},
			want: "de ad",
		},
		{
			name: "login composite marker 0x12 empty echo",
			tlv:  nsdp.TLV{Tag: nsdp.TagScalar0012},
			want: `""`,
		},
		{
			// Live 13:21 {12,14,17,11} reply: the dangling 0x0012 tag
			// swallows the 0x0014 length as its own length, re-packing
			// the capability+nonce TLVs plus the 0x0011 dangling tag
			// and terminator bytes into one composite value (ROUND 13).
			name: "login composite marker 0x12 composite",
			tlv: nsdp.TLV{Tag: nsdp.TagScalar0012, Value: []byte{
				0x00, 0x04, 0x00, 0x00, 0x00, 0x10,
				0x00, 0x17, 0x00, 0x04, 0x4e, 0x5d, 0x1a, 0x8e,
				0x00, 0x11, 0x00, 0x00,
				0xff, 0xff,
			}},
			want: "login blob: capability=0x00000010 nonce=4e 5d 1a 8e [tlv 0x0011=] trailing=ff ff",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderValue(nsdp.DecodeTLV(tt.tlv))
			if got != tt.want {
				t.Errorf("renderValue() = %q, want %q", got, tt.want)
			}
		})
	}
}

// portStatsValue builds one 49-byte tag-0x1000 entry:
// {port u8, received/sent/packets/broadcast/multicast/errors u64 BE}.
func portStatsValue(port byte, rx, tx, pkt, bcst, mcst, errs uint64) []byte {
	v := make([]byte, 0, 49)
	v = append(v, port)
	for _, n := range []uint64{rx, tx, pkt, bcst, mcst, errs} {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, n)
		v = append(v, b...)
	}
	return v
}
