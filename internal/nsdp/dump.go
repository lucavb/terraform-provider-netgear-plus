package nsdp

// Typed read layer: block-GET encoding (ROUND 6 block↔tag unification)
// and the typed reply-value decoders (ROUND 7 reply parser FUN_0048edc0,
// cross-checked and corrected against the third-party sources of the
// ROUND 9/9b/10 notes: ProSafeLinux psl_typ.py, wireshark/nsdp.lua, the
// Linux-Magazin article, the Wikipedia NSDP article), plus the Client
// read methods built on them (GetBlock, Dump).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
)

// Block GET markers: the first TLV of a block read announces the marker
// tag, the second carries the block itself. v2 switches use 0x0014; v1
// switches use 0x000F instead (nsdp.js:55 {0f,00,00,id}).
const (
	BlockMarkerV2 uint16 = 0x0014
	BlockMarkerV1 uint16 = 0x000F
)

// encodeGetTLVs builds a GET request whose TLV region holds real TLVs,
// mirroring the encodeSetTLVs quirk handling: the byte at wire offset 32
// (EncodeHeader's trailing 0x00) is the FIRST TLV's tag-high byte; later
// TLVs carry their full 4-byte tag+len headers. The region ends with the
// {0xFFFF, 0x0000} terminator.
func encodeGetTLVs(mac, agentMAC net.HardwareAddr, seq uint32, tlvs ...TLV) []byte {
	req := EncodeHeader(mac, agentMAC, seq)
	req[1] = cmdGet
	for i, t := range tlvs {
		if i == 0 {
			req[32] = byte(t.Tag >> 8) // tag high byte at wire offset 32
			req = append(req, byte(t.Tag), byte(len(t.Value)>>8), byte(len(t.Value)))
		} else {
			req = append(req, byte(t.Tag>>8), byte(t.Tag), byte(len(t.Value)>>8), byte(len(t.Value)))
		}
		req = append(req, t.Value...)
	}
	req = append(req, 0xff, 0xff, 0x00, 0x00) // terminator TLV {0xFFFF, 0x0000}
	return req
}

// EncodeBlockGetRequest builds a block read: a GET (cmd 1) whose TLV region
// holds TWO real TLVs (ROUND 6 block↔tag unification — the attr-switch
// listing is the switch-side ground truth):
//
//	{tag marker, len 0}                     (marker = 0x0014 on v2, 0x000F on v1)
//	{tag blockID<<8, len len(selector), selector}
//	{0xFFFF, 0x0000}                        terminator
//
// The block id NN IS the tag high byte (block 0x78 reads tag 0x7800, the
// serial number). With no selector the frame is 44 bytes and is
// byte-identical to the probe's live-proven block-sweep entry form
// {14,00,00,id} reinterpreted as the two TLVs. A non-empty selector (e.g.
// 0xffff = "all groups" for 0x8800) rides as the second TLV's value.
func EncodeBlockGetRequest(mac, agentMAC net.HardwareAddr, seq uint32, blockID byte, marker uint16, selector []byte) []byte {
	return encodeGetTLVs(mac, agentMAC, seq,
		TLV{Tag: marker},
		TLV{Tag: uint16(blockID) << 8, Value: selector},
	)
}

// BE16Array is the (len-2)/2 × BE16 reply layout of tag 0x2800: a
// leading BE16 (semantics unverified — presumed entry count or index)
// followed by that many big-endian entries.
type BE16Array struct {
	Prefix  uint16
	Entries []uint16
}

// DHCPMode is the tag-0x000b DHCP mode enum (Wikipedia NSDP article +
// ProSafeLinux + wireshark agree): 0=Static, 1=DHCP, 2=Refresh DHCP.
type DHCPMode byte

// String renders the DHCP mode enum value.
func (m DHCPMode) String() string {
	switch m {
	case 0:
		return "Static"
	case 1:
		return "DHCP"
	case 2:
		return "Refresh DHCP"
	}
	return fmt.Sprintf("unknown(%d)", byte(m))
}

// VLANEngineMode is the 1-byte tag-0x2000 VLAN engine mode enum
// (ProSafeLinux PslTypVlanSupport + wireshark dissector agree — 2-of-3
// sources): 0=none, 1=port-based, 2=ID/subnet-based, 3=802.1Q port-based,
// 4=802.1Q extended.
type VLANEngineMode byte

// String renders the VLAN engine mode enum value.
func (m VLANEngineMode) String() string {
	switch m {
	case 0:
		return "none"
	case 1:
		return "port-based"
	case 2:
		return "id-based"
	case 3:
		return "802.1q port-based"
	case 4:
		return "802.1q extended"
	}
	return fmt.Sprintf("unknown(%d)", byte(m))
}

// QoSPriority is the tag-0x3800 per-port QoS priority byte
// (ProSafeLinux PslTypPortBasedQOS — 2-of-3 sources): 1=High, 2=Middle,
// 3=Normal, 4=Low.
type QoSPriority byte

// String renders the QoS priority enum value.
func (p QoSPriority) String() string {
	switch p {
	case 1:
		return "High"
	case 2:
		return "Middle"
	case 3:
		return "Normal"
	case 4:
		return "Low"
	}
	return fmt.Sprintf("unknown(%d)", byte(p))
}

// PortTrafficStats is one 49-byte tag-0x1000 entry: {port u8 1-BASED,
// 6 × u64 BE counters}. Three sources agree (ProSafeLinux PslTypPortStat
// "!b6Q", wireshark "Port Traffic Statistic", Wikipedia) — this corrects
// the ROUND 7 "serial blob" mislabel (the serial number is tag 0x7800).
type PortTrafficStats struct {
	Port      byte   // 1-based port number
	Received  uint64 // bytes received
	Sent      uint64 // bytes sent
	Packets   uint64 // total packets
	Broadcast uint64 // broadcast packets
	Multicast uint64 // multicast packets
	Errors    uint64 // CRC errors
}

// PVIDEntry is one 3-byte tag-0x3000 reply entry: {port u8 1-BASED,
// vlan_id u16 BE}. Layout CONFIRMED by ProSafeLinux psl_typ.py:595-612
// (PslTypVlanPVID ">Bh"); 2-of-3 sources — wireshark names the tag but
// only PSL pins the layout, and the nsdpmanager reply parser confirms the
// 3-byte length.
type PVIDEntry struct {
	Port   byte   // 1-based port number
	VLANID uint16 // PVID applied to untagged ingress on this port
}

// PortQoSEntry is one 2-byte tag-0x3800 reply entry: {port u8 1-BASED,
// priority u8}. Layout CONFIRMED by ProSafeLinux psl_typ.py:680-734
// (PslTypPortBasedQOS ">BB"); 2-of-3 sources.
type PortQoSEntry struct {
	Port     byte        // 1-based port number
	Priority QoSPriority // 1=High, 2=Middle, 3=Normal, 4=Low
}

// BandwidthEntry is one 5-byte tag-0x4c00/0x5000/0x5800 reply entry
// (ingress / egress / broadcast-storm rate limit): {port u8 1-BASED,
// 00 00 reserved, limit u16 BE}. Layout CONFIRMED by ProSafeLinux
// PslTypBandwidth (pack ">bbbh", unpack port=value[0],
// limit=BE16(value[3:])); 2-of-3 sources — this corrects ROUND 7's
// "4+1 concat" artifact (bytes 1-2 are reserved zeros, not the middle of
// a BE32).
type BandwidthEntry struct {
	Port  byte   // 1-based port number
	Limit uint16 // rate limit enum (PSL: 0=none, 1=512K … 11=512M)
}

// IGMPConfig is the 4-byte tag-0x6800 value: {enabled u16 BE (0=off,
// 1=on), vlan_id u16 BE}. ProSafeLinux PslTypIGMPSnooping (">hh") and the
// ROUND 7 reply parser (2 × BE16) agree.
type IGMPConfig struct {
	Enabled uint16 // 0 = disabled, 1 = enabled
	VLANID  uint16 // IGMP snooping VLAN
}

// PortMirrorConfig is the 3-byte tag-0x5c00 value: {dst_port u8 (0 =
// mirroring disabled), reserved u8 (semantics unknown — "fixme" in PSL),
// src_ports u8 bitmap (bit 0x80=port 1 … 0x01=port 8)}. 2-of-3 sources:
// ProSafeLinux PslTypPortMirror (">bbb") pins the layout; the nsdpmanager
// reply parser instead reported a string form for this tag.
type PortMirrorConfig struct {
	DstPort  byte // 1-based mirror destination port; 0 = no mirroring
	Reserved byte // byte 2 semantics unknown
	SrcPorts byte // bitmap of 1-based mirror source ports
}

// SpeedLinkStatus is one 3-byte tag-0x0c00 reply entry: {port u8 1-BASED,
// speed u8, flow u8}. ProSafeLinux PslTypSpeedStat + wireshark
// "Speed/Link Status" agree (2-of-3 sources) — resolves the old "unknown
// block 0x0c". Speed per PSL: 0=none, 1=10M half, 2=10M full, 3=100M
// half, 4=100M full, 5=1G. The third byte is NOT the link state — it is
// the FLOW-CONTROL flag mirroring the 0x9400 flow byte (semantics
// live-proven via the web UI, notes ROUND 18; it is NOT a generic
// "status" byte).
type SpeedLinkStatus struct {
	Port  byte // 1-based port number
	Speed byte // 0=none 1=10M half 2=10M full 3=100M half 4=100M full 5=1G
	Flow  byte // flow-control mirror of the 0x9400 flow byte; NOT the link state
}

// PortAdminStatusEntry is one 3-byte tag-0x9400 reply entry:
// {port u8 1-BASED, admin u8, flow u8}. Semantics LIVE-PROVEN via the web
// UI (notes ROUND 18): admin 0 = port disabled (the UI renders the port's
// Speed config column as "Disable"), 1 = enabled (the factory value on all
// 8 ports); flow 0 = flow control off (factory), 1 = on (the UI Flow
// Control column flips to "Enable"). The layout matches the firmware SET
// handler (bank1 0x81f6, shared verbatim with tag 0x0c00): admin ->
// config 0x9bff, flow -> config 0x9c08, and the SET always writes ALL
// THREE bytes per port (no partial write). OPEN QUESTION: the admin byte
// may be a full speed-config enum (0=Disable, 1=Auto, 2+=forced speeds)
// rather than a bare enable flag — the nsdp API only ever writes 0/1.
type PortAdminStatusEntry struct {
	Port  byte // 1-based port number
	Admin byte // 0 = port disabled, 1 = enabled (factory value on all ports)
	Flow  byte // 0 = flow control off (factory), 1 = on
}

// PortBasedVLANEntry is one 3-byte tag-0x2400 reply entry:
// {vlan_id u16 BE, port_bitmap u8}. Matches the SetPortBasedVLAN wire
// layout (ProSafeLinux PslTypVlanId pack_py); live replies carry one
// 3-byte entry per TLV, the decoder tolerates concatenated entries.
type PortBasedVLANEntry struct {
	VLANID uint16
	Ports  byte // bitmap of 1-based member ports (0x80=port 1 … 0x01=port 8)
}

// PortEntry is the best-effort reading of the still-UNVERIFIED 3-byte
// per-port entry layouts (0x8800 LA groups, 0x9c00 one-to-one mirror /
// "VLAN config" entries): presumed {port index u8, value BE16}. The
// decoder marks every such value with a
// layout-UNVERIFIED note — do not build typed SETs on it without live
// verification. (The sibling 0x3000 PVID and 0x9400 port admin layouts
// are now confirmed; see PVIDEntry and PortAdminStatusEntry. Port
// numbers are presumed 1-based like every confirmed per-port layout.)
type PortEntry struct {
	Port  byte
	Value uint16
}

// Deprecated: BE16Pair misread the confirmed tag-0x6800 IGMP layout (see
// IGMPConfig). Kept only so tools/nsdpctl keeps compiling.
type BE16Pair struct {
	First  uint16
	Second uint16
}

// Deprecated: BE32PlusU8 misread the confirmed 5-byte bandwidth layout of
// tags 0x4c00/0x5000/0x5800 (see BandwidthEntry). Kept only so
// tools/nsdpctl keeps compiling.
type BE32PlusU8 struct {
	Value uint32
	Extra byte
}

// Attr is a reply TLV with its best-effort typed interpretation. Decoded is
// nil when no decoder applies (the CLI falls back to hex); Note carries
// decode caveats such as "layout UNVERIFIED".
type Attr struct {
	Tag     uint16
	Name    string
	Value   []byte
	Decoded any    // typed value per ROUND 7, or nil
	Note    string // decode caveat ("" when none)
}

// DecodeTLVs decodes a slice of reply TLVs into Attrs.
func DecodeTLVs(tlvs []TLV) []Attr {
	out := make([]Attr, 0, len(tlvs))
	for _, t := range tlvs {
		out = append(out, DecodeTLV(t))
	}
	return out
}

// DecodeTLV decodes one reply TLV per the ROUND 7 typed value formats as
// cross-checked against the third-party sources (ROUND 9/9b/10 notes:
// ProSafeLinux psl_typ.py, its wireshark/nsdp.lua dissector, the
// Linux-Magazin article, the Wikipedia NSDP article):
//
//	strings 0x01/0x03/0x05(location)/0x0d/0x0e/0x11/0x12 (small) and
//	    0x7400/0x7800/0x8000 (family, trailing NUL/0xFF padding trimmed)
//	0x02 BE16 model code | 0x04 raw 6-byte MAC | 0x06/0x07/0x08 BE32 → net.IP
//	0x0b DHCPMode enum (0=Static, 1=DHCP, 2=Refresh DHCP) |
//	    0x0c/0x0f u8 | 0x14 BE32 capability | 0x17 raw 4-byte nonce
//	    (0x12: string since ROUND 13 — empty or nested login composite)
//	0x1000 per-port traffic statistics: 49-byte entries {port u8 1-BASED,
//	    6 × u64 BE} — CONFIRMED (was mislabeled "serial blob"; serial is
//	    0x7800)
//	0x2400 port-based VLAN: 3-byte entries {vlan_id u16 BE, port_bitmap u8}
//	    — live-confirmed (matches the SetPortBasedVLAN SET layout)
//	0x2800 (len-2)/2 × BE16 array
//	0x3000 PVID: 3-byte entries {port u8 1-BASED, vlan_id u16 BE} — CONFIRMED
//	0x3400 QoS mode: 1B enum (1=port-based, 2=802.1p)
//	0x3800 port QoS: 2-byte entries {port u8 1-BASED, priority u8} — CONFIRMED
//	0x4c00/0x5000/0x5800 bandwidth: 5-byte entries {port u8 1-BASED,
//	    00 00 reserved, limit u16 BE} — CONFIRMED (corrects "4+1 concat")
//	0x5c00 port mirror: 3B {dst_port u8, reserved u8, src_ports u8 bitmap}
//	0x6800 IGMP snooping: 4B {enabled u16 BE, vlan_id u16 BE} — CONFIRMED
//	0x6c00 block unknown multicast: 1B boolean (0=off, 1=on)
//	0x2000 VLAN engine mode: 1B enum
//	0x0c00 speed/link: 3-byte entries {port u8 1-BASED, speed u8,
//	    flow u8} — the flow byte mirrors the 0x9400 flow-control byte,
//	    it is NOT the link state (ROUND 18)
//	0x9400 port admin status: 3-byte entries {port u8 1-BASED, admin u8
//	    (1=enabled), flow u8 (1=on)} — semantics live-proven via the web
//	    UI (ROUND 18)
//	0x8800/0x9c00 best-effort 3-byte {port, BE16} entries —
//	    LAYOUT UNVERIFIED (both the code note and Attr.Note say so)
//
// Anything else (and any value whose length breaks the expected layout)
// stays raw: Decoded nil, the CLI prints hex.
func DecodeTLV(t TLV) Attr {
	a := Attr{Tag: t.Tag, Name: TagName(t.Tag), Value: t.Value}
	v := t.Value
	wantLen := func(want int) {
		a.Note = fmt.Sprintf("unexpected length %d (want %d)", len(v), want)
	}
	switch t.Tag {
	case TagProductName, TagSystemName, TagSystemLocation, TagFirmware1,
		TagFirmware2, TagString0011, TagFWConfigString, TagSerialNumber, TagStaticRouterPort,
		// 0x0012 is NOT a scalar (the u8 label came from ProSafeLinux and
		// is wrong): live replies carry 0x0012 either empty (a bare
		// dangling tag the firmware never fills) or as a nested-TLV login
		// composite ({0x0014 cap} + {0x0017 nonce} + trailing) that a
		// composite-hungry 0x0011 swallow re-packs (ROUND 13). Both forms
		// render best as trimmed strings; nsdpctl prints the composite
		// via its 0x0011 blob renderer.
		TagScalar0012:
		a.Decoded = asciiTrim(v)
	case TagModelCode:
		if len(v) == 2 {
			a.Decoded = binary.BigEndian.Uint16(v)
		} else {
			wantLen(2)
		}
	case TagMACAddress:
		if len(v) == 6 {
			a.Decoded = net.HardwareAddr(append(net.HardwareAddr(nil), v...))
		} else {
			wantLen(6)
		}
	case TagIPAddress, TagSubnetMask, TagGatewayAddr:
		if len(v) == 4 {
			a.Decoded = net.IP(append(net.IP(nil), v...)).To4()
		} else {
			wantLen(4)
		}
	case TagDHCPMode:
		if len(v) == 1 {
			a.Decoded = DHCPMode(v[0])
		} else {
			wantLen(1)
		}
	case TagScalar000c, TagActiveImage:
		if len(v) == 1 {
			a.Decoded = v[0]
		} else {
			wantLen(1)
		}
	case TagCapabilityTag:
		if len(v) == 4 {
			a.Decoded = binary.BigEndian.Uint32(v)
		} else {
			wantLen(4)
		}
	case TagNonceTag:
		if len(v) == 4 {
			a.Note = "raw nonce bytes (untyped)"
		} else {
			wantLen(4)
		}
	case TagPortTrafficStats:
		// CONFIRMED (ROUND 9/10): 49-byte entries {port u8 1-based,
		// 6 × u64 BE counters}. One entry per port; the decoder also
		// tolerates several concatenated entries in one TLV.
		const entryLen = 49
		if len(v) > 0 && len(v)%entryLen == 0 {
			entries := make([]PortTrafficStats, len(v)/entryLen)
			for i := range entries {
				e := v[i*entryLen : (i+1)*entryLen]
				entries[i] = PortTrafficStats{
					Port:      e[0],
					Received:  binary.BigEndian.Uint64(e[1:9]),
					Sent:      binary.BigEndian.Uint64(e[9:17]),
					Packets:   binary.BigEndian.Uint64(e[17:25]),
					Broadcast: binary.BigEndian.Uint64(e[25:33]),
					Multicast: binary.BigEndian.Uint64(e[33:41]),
					Errors:    binary.BigEndian.Uint64(e[41:49]),
				}
			}
			a.Decoded = entries
		} else {
			a.Note = fmt.Sprintf("length %d not a positive multiple of %d for per-port statistics entries", len(v), entryLen)
		}
	case TagPortBasedVLAN:
		// Live-confirmed 3-byte entries {vlan_id u16 BE, port_bitmap u8}
		// (live replies carry one entry per TLV; concatenated entries
		// tolerated).
		if len(v) > 0 && len(v)%3 == 0 {
			entries := make([]PortBasedVLANEntry, len(v)/3)
			for i := range entries {
				entries[i] = PortBasedVLANEntry{VLANID: binary.BigEndian.Uint16(v[3*i : 3*i+2]), Ports: v[3*i+2]}
			}
			a.Decoded = entries
		} else {
			a.Note = fmt.Sprintf("length %d not a multiple of 3 for port-based VLAN entries {vlan_id u16 BE, port_bitmap u8}", len(v))
		}
	case Tag8021QVLAN:
		if len(v) >= 2 && len(v)%2 == 0 {
			arr := BE16Array{Prefix: binary.BigEndian.Uint16(v[0:2])}
			for off := 2; off+2 <= len(v); off += 2 {
				arr.Entries = append(arr.Entries, binary.BigEndian.Uint16(v[off:off+2]))
			}
			a.Decoded = arr
			a.Note = "leading BE16 semantics unverified (presumed count/index)"
		} else {
			a.Note = "odd or short length for (len-2)/2 × BE16 array"
		}
	case TagPVID:
		// CONFIRMED (ROUND 9, ProSafeLinux psl_typ.py:595-612; 2-of-3
		// sources): 3-byte entries {port u8 1-BASED, vlan_id u16 BE},
		// one per port.
		if len(v) > 0 && len(v)%3 == 0 {
			entries := make([]PVIDEntry, len(v)/3)
			for i := range entries {
				entries[i] = PVIDEntry{Port: v[3*i], VLANID: binary.BigEndian.Uint16(v[3*i+1 : 3*i+3])}
			}
			a.Decoded = entries
		} else {
			a.Note = fmt.Sprintf("length %d not a multiple of 3 for PVID entries {port u8, vlan_id u16 BE}", len(v))
		}
	case TagQoSMode:
		// Global QoS mode enum (tags.go 0x3400): 1=port-based, 2=802.1p.
		// The firmware SET handler (bank1 0x7b98) accepts only 1-2.
		if len(v) == 1 {
			a.Decoded = QoSMode(v[0])
		} else {
			wantLen(1)
		}
	case TagPortBasedQoS:
		// CONFIRMED (ROUND 9, ProSafeLinux psl_typ.py:680-734; 2-of-3
		// sources): 2-byte entries {port u8 1-BASED, priority u8}.
		if len(v) > 0 && len(v)%2 == 0 {
			entries := make([]PortQoSEntry, len(v)/2)
			for i := range entries {
				entries[i] = PortQoSEntry{Port: v[2*i], Priority: QoSPriority(v[2*i+1])}
			}
			a.Decoded = entries
		} else {
			a.Note = fmt.Sprintf("length %d not a multiple of 2 for port QoS entries {port u8, priority u8}", len(v))
		}
	case TagIngressRate, TagEgressRate, TagBroadcastStormRate:
		// CONFIRMED (ROUND 9, ProSafeLinux PslTypBandwidth; 2-of-3
		// sources): 5-byte {port u8 1-BASED, 00 00 reserved,
		// limit u16 BE}.
		if len(v) == 5 {
			a.Decoded = BandwidthEntry{Port: v[0], Limit: binary.BigEndian.Uint16(v[3:5])}
			if v[1] != 0 || v[2] != 0 {
				a.Note = fmt.Sprintf("reserved bytes non-zero: %02x %02x", v[1], v[2])
			}
		} else {
			wantLen(5)
		}
	case TagPortMirroring:
		// 2-of-3 sources (ROUND 9, ProSafeLinux PslTypPortMirror):
		// 3-byte {dst_port u8 (0=off), reserved u8, src_ports u8
		// bitmap}. The nsdpmanager reply parser saw a string form
		// instead, so only well-formed 3-byte values decode typed.
		if len(v) == 3 {
			a.Decoded = PortMirrorConfig{DstPort: v[0], Reserved: v[1], SrcPorts: v[2]}
			a.Note = "byte 2 semantics unknown"
		} else {
			wantLen(3)
		}
	case TagIGMPSnooping:
		// CONFIRMED (ROUND 9, ProSafeLinux PslTypIGMPSnooping; agrees
		// with the ROUND 7 reply parser's 2 × BE16): {enabled u16 BE,
		// vlan_id u16 BE}.
		if len(v) == 4 {
			a.Decoded = IGMPConfig{Enabled: binary.BigEndian.Uint16(v[0:2]), VLANID: binary.BigEndian.Uint16(v[2:4])}
		} else {
			wantLen(4)
		}
	case TagBlockUnknownMulticast:
		// Global 1-byte boolean (0=off, 1=on): the firmware SET handler
		// (bank1 0x7c58) reads a single value byte and commits the
		// "mcast" config section.
		if len(v) == 1 {
			a.Decoded = v[0]
		} else {
			wantLen(1)
		}
	case TagVLANEngineMode:
		// 2-of-3 sources (ROUND 9, ProSafeLinux PslTypVlanSupport +
		// wireshark): 1-byte engine mode enum.
		if len(v) == 1 {
			a.Decoded = VLANEngineMode(v[0])
		} else {
			wantLen(1)
		}
	case TagSpeedLinkStatus:
		// 2-of-3 sources (ROUND 9, ProSafeLinux PslTypSpeedStat +
		// wireshark "Speed/Link Status"): 3-byte entries
		// {port u8 1-BASED, speed u8, flow u8}, one per port. The third
		// byte is NOT the link state — it is the flow-control flag
		// mirroring the 0x9400 flow byte (ROUND 18).
		if len(v) > 0 && len(v)%3 == 0 {
			entries := make([]SpeedLinkStatus, len(v)/3)
			for i := range entries {
				entries[i] = SpeedLinkStatus{Port: v[3*i], Speed: v[3*i+1], Flow: v[3*i+2]}
			}
			a.Decoded = entries
		} else {
			a.Note = fmt.Sprintf("length %d not a multiple of 3 for speed/link entries {port u8, speed u8, flow u8}", len(v))
		}
	case TagPortAdminStatus:
		// 3-byte entries {port u8 1-BASED, admin u8, flow u8}; semantics
		// live-proven via the web UI (ROUND 18): admin 0 = port disabled,
		// 1 = enabled (factory value on all ports); flow 0 = flow control
		// off (factory), 1 = on. The flow byte is mirrored by the 0x0c00
		// third byte.
		if len(v) > 0 && len(v)%3 == 0 {
			entries := make([]PortAdminStatusEntry, len(v)/3)
			for i := range entries {
				entries[i] = PortAdminStatusEntry{Port: v[3*i], Admin: v[3*i+1], Flow: v[3*i+2]}
			}
			a.Decoded = entries
		} else {
			a.Note = fmt.Sprintf("length %d not a multiple of 3 for port admin status entries {port u8, admin u8, flow u8}", len(v))
		}
	case TagLAGroupSetting, TagOneToOneMirror:
		// LAYOUT UNVERIFIED (notes ROUND 7): presumed 3-byte {port u8,
		// value BE16} entries, one per port/group. The Attr.Note says so.
		if len(v) > 0 && len(v)%3 == 0 {
			entries := make([]PortEntry, len(v)/3)
			for i := range entries {
				entries[i] = PortEntry{Port: v[3*i], Value: binary.BigEndian.Uint16(v[3*i+1 : 3*i+3])}
			}
			a.Decoded = entries
			a.Note = "3-byte entry layout UNVERIFIED: presumed {port u8, BE16 value}"
		} else {
			a.Note = fmt.Sprintf("length %d not a multiple of 3 for the presumed {port, BE16} entries (layout UNVERIFIED)", len(v))
		}
	}
	return a
}

// DefaultDumpSmallTags is the batch of small tags a Dump reads in ONE
// multi-tag GET: the ROUND 7 client-parsed set (strings, model code, MAC,
// IP/mask/gateway, scalars, fw images, active image, capability, nonce).
var DefaultDumpSmallTags = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11, 0x12, 0x14, 0x17,
}

// DefaultDumpBlockIDs is the block list a Dump reads, one block request
// each: 0x78 serial, 0x74 fw/config, 0x0c speed/link status, 0x30 PVID,
// 0x94 port admin status.
var DefaultDumpBlockIDs = []byte{0x78, 0x74, 0x0c, 0x30, 0x94}

// BlockResult is the outcome of one block read within a Dump: the decoded
// reply Attrs, or Err (warning-level — a Dump continues past failing
// blocks).
type BlockResult struct {
	BlockID byte
	Attrs   []Attr
	Err     error
}

// DumpResult is the outcome of a full Dump: the small-tag Attrs (sorted by
// tag) and one BlockResult per DefaultDumpBlockIDs entry, in order.
type DumpResult struct {
	Attrs  []Attr
	Blocks []BlockResult
}

// GetBlock reads one block (family tag 0xNN00) via a block GET and returns
// the decoded reply Attrs. The v2 marker (0x0014) is used; retries follow
// the client-faithful GET schedule (up to 14 attempts, one fresh sequence
// number per attempt). selector may be nil (read the whole block) or carry
// per-item selector bytes (e.g. 0xffff = "all groups" for 0x8800).
func (c *Client) GetBlock(blockID byte, selector []byte) ([]Attr, error) {
	for i := 1; ; i++ {
		seq := c.nextSeq()
		req := EncodeBlockGetRequest(c.mac, c.agentMAC, seq, blockID, BlockMarkerV2, selector)
		if c.verbose != nil {
			fmt.Fprintf(c.verbose, "GET block 0x%02x00 seq=%d request (%d bytes):\n%s", blockID, seq, len(req), hexDump(req))
		}
		if err := c.send(req); err != nil {
			return nil, fmt.Errorf("GET block 0x%02x: %w", blockID, err)
		}
		reply, err := c.readReply(seq, cmdGetReply, fmt.Sprintf("GET block 0x%02x00", blockID))
		if err != nil {
			if !errors.Is(err, ErrNoReply) {
				return nil, fmt.Errorf("GET block 0x%02x: %w", blockID, err)
			}
			if i >= defaultAttempts {
				break
			}
			if c.verbose != nil {
				fmt.Fprintf(c.verbose, "GET block 0x%02x00: no response (attempt %d/%d), retrying\n", blockID, i, defaultAttempts)
			}
			continue
		}
		return DecodeTLVs(reply.TLVs), nil
	}
	return nil, fmt.Errorf("GET block 0x%02x: no valid response after %d attempts: %w", blockID, defaultAttempts, ErrNoReply)
}

// Dump reads the switch config surface with GETs only (no login): one
// multi-tag GET batch for the small tags (DefaultDumpSmallTags), then one
// block request each for DefaultDumpBlockIDs. A failing block is recorded
// in its BlockResult.Err and the dump continues; only a total small-tag
// batch failure aborts the dump.
func (c *Client) Dump() (*DumpResult, error) {
	m, err := c.GetAttrs(DefaultDumpSmallTags...)
	if err != nil {
		return nil, fmt.Errorf("dump: small-tag batch: %w", err)
	}
	res := &DumpResult{}
	for tag, val := range m {
		res.Attrs = append(res.Attrs, DecodeTLV(TLV{Tag: uint16(tag), Value: val}))
	}
	sort.Slice(res.Attrs, func(i, j int) bool { return res.Attrs[i].Tag < res.Attrs[j].Tag })
	for _, id := range DefaultDumpBlockIDs {
		attrs, err := c.GetBlock(id, nil)
		res.Blocks = append(res.Blocks, BlockResult{BlockID: id, Attrs: attrs, Err: err})
	}
	return res, nil
}
