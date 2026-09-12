package nsdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// NSDP v2 wire constants (live-proven 2026-09-12 against a GS108Ev3 fw
// 2.06.24GR; evidence trail in doc.go).
const (
	protoVersion = 0x01 // header [0]

	cmdGet      = 0x01 // header [1]: GET request
	cmdSet      = 0x03 // header [1]: SET request
	cmdGetReply = 0x02 // header [1]: GET reply (request cmd + 1)
	cmdSetReply = 0x04 // header [1]: SET reply (request cmd + 1)

	headerLen   = 32
	replyMinLen = 36 // header + at least the 4-byte terminator TLV

	tlvTermTag = 0xFFFF // TLV terminator tag; the terminator TLV is ff ff 00 00

	systemNameTag = 0x0003 // GET/SET TLV: switch system name (ASCII, plaintext)

	// statusAuthMismatch is the status byte that doubles as a required-TLV
	// parse error AND an auth-verify mismatch (ROUND 8, live 2026-09-12:
	// a SET carrying a stale auth token fails 0x0d with failing tag
	// 0x001A and a {BE16 len, expected-token} payload after the header).
	statusAuthMismatch = 0x0d
)

// magic is the protocol signature at header offset 24-27.
var magic = [4]byte{'N', 'S', 'D', 'P'}

// EncodeHeader builds the 32-byte NSDP request header for a GET request
// (command byte 1) followed by ONE extra 0x00 byte at wire offset 32.
//
// That trailing byte is a wire-format quirk carried over from NETGEAR's
// own client: it is the HIGH byte of the first TLV's tag. Builders that
// follow (EncodeGetRequest, encodeSetTLVs) overwrite it with tag>>8 of the
// first TLV; a caller building frames by hand must do the same.
//
// mac must be at least 6 bytes long (panics otherwise — a programming
// error); agentMAC nil or any length other than 6 means broadcast (an
// all-zero Agent ID). The command byte is left at 0x01 (GET); SET builders
// set it to 0x03.
func EncodeHeader(mac, agentMAC net.HardwareAddr, seq uint32) []byte {
	req := make([]byte, 0, 92)
	req = append(req,
		protoVersion, // version (0)
		cmdGet,       // command: GET (1) — SET builders overwrite this
		0x00, 0x00,   // status, reserved (2-3)
		0x00, 0x00, // failing TLV (4-5)
		0x00, 0x00, // reserved (6-7)
	)
	req = append(req, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]) // Manager ID (8-13)
	if len(agentMAC) == 6 {
		req = append(req, agentMAC[0], agentMAC[1], agentMAC[2], agentMAC[3], agentMAC[4], agentMAC[5]) // Agent ID (14-19)
	} else {
		req = append(req, 0, 0, 0, 0, 0, 0) // Agent ID: broadcast (14-19)
	}
	var seqb [4]byte
	binary.BigEndian.PutUint32(seqb[:], seq)
	req = append(req, seqb[:]...)  // sequence (20-23)
	req = append(req, magic[:]...) // "NSDP" (24-27)
	req = append(req, 0, 0, 0, 0)  // reserved (28-31)
	req = append(req, 0)           // wire offset 32: first TLV tag's HIGH byte
	return req
}

// EncodeGetRequest builds a multi-tag NSDP v2 GET request: the 33-byte
// header prefix (32-byte header + the byte at wire offset 32, which is the
// first entry's tag-high byte), one 4-byte entry {tag, 00, 00, 00} per
// requested attr tag, and the 7-byte trailer 00 00 00 ff ff 00 00.
//
// A single-tag request is exactly the live-proven 44-byte probe request:
// 01 01 00 00 00 00 00 00 <mgr6> <agent6> <seq4 BE> 4e 53 44 50 00 00 00 00
// 00 tag 00 00 00 00 00 00 ff ff 00 00
func EncodeGetRequest(mac, agentMAC net.HardwareAddr, seq uint32, tags ...byte) []byte {
	req := EncodeHeader(mac, agentMAC, seq)
	req[1] = cmdGet
	for _, tag := range tags {
		req = append(req, tag, 0x00, 0x00, 0x00)
	}
	req = append(req, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00) // terminator
	return req
}

// encodeSetTLVs builds a CMD_SET_REQUEST: the 33-byte header prefix with
// command byte 3, the given TLVs (the first TLV's tag-high byte overwrites
// the header's trailing byte at wire offset 32), and the {0xFFFF, 0x0000}
// terminator TLV — exactly what nsdp_command_start emits after the
// command's TLV list.
func encodeSetTLVs(mac, agentMAC net.HardwareAddr, seq uint32, tlvs ...TLV) []byte {
	req := EncodeHeader(mac, agentMAC, seq)
	req[1] = cmdSet
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

// EncodeSetLoginRequest builds the NSDP LOGIN SET request: the SET header
// plus the single capability-selected password/auth TLV — computed
// internally from the login handshake inputs — plus the terminator:
//
//	tag 0x001A, len 8, V2 token      when capability&0x10 (GS108Ev3 branch)
//	tag 0x0018, len 4, V1 token      when capability&0x08
//	tag 0x000A, len len(pw), pw      otherwise (plaintext; NtgrRock-XORed
//	                                 first when capability&0x01)
//
// nonce is the 4 raw nonce bytes from GET attr 0x17, and agentMAC is both
// the header Agent ID and an input of the token mix (the token is derived
// from the switch MAC, so a nil agentMAC is a programming error here).
// The V2-branch frame is the live-proven 48-byte login SET.
func EncodeSetLoginRequest(mac, agentMAC net.HardwareAddr, seq uint32, capability uint32, nonce, password []byte) []byte {
	tag := loginTagFor(capability)
	token := loginToken(capability, nonce, agentMAC, password)
	return encodeSetTLVs(mac, agentMAC, seq, TLV{Tag: tag, Value: token})
}

// EncodeSetNameRequest builds the config SET request for the switch system
// name. Every CMD_SET_REQUEST attaches the login auth TLV BEFORE the
// type-specific TLV (nsdpmanager.exe nsdp_command_start, FUN_00492b80),
// so the frame is:
//
//	header (cmd 3) + auth TLV {tag per capability branch, len, token}
//	+ name TLV {tag 0x0003, len, name ASCII} + terminator
//
// The auth TLV carries the token cached from a successful Login() (the
// token is derived from the login nonce, so only the client that logged in
// can produce it). Config string values go out as PLAINTEXT TLVs — only
// password TLVs (types 9/10) are encrypted (nsdpmanager.exe
// nsdp_set_tlv_string_enhance, FUN_004945d0).
//
// With the 8-byte V2 token and a 6-byte name the frame is
// 32 + 12 + 10 + 4 = 58 bytes.
func EncodeSetNameRequest(mac, agentMAC net.HardwareAddr, seq uint32, capability uint32, token []byte, name string) []byte {
	return encodeSetTLVs(mac, agentMAC, seq,
		TLV{Tag: loginTagFor(capability), Value: token},
		TLV{Tag: systemNameTag, Value: []byte(name)},
	)
}

// EncodeReply builds an NSDP reply answering the request req: the command
// byte is the request's command + 1 (GET 0x01 → 0x02, SET 0x03 → 0x04),
// the header echoes the request's manager MAC, agent MAC and sequence and
// carries the given status and failing-tag fields. payload, when
// non-empty, is emitted directly after the header, BEFORE the TLV region —
// the auth-mismatch expected-token blob {BE16 len, bytes} is NOT a TLV
// (WalkTLVs truncates on it, see expectedAuthPayload). The tlvs then
// follow as full {tag BE16, len BE16, value} entries — reply TLV regions
// carry no request-side offset-32 quirk (the live golden reply pins the
// full 4-byte first-TLV header at wire offset 32) — terminated by the
// {0xFFFF, 0x0000} terminator. A reply built here with status 0 parses
// identically to the firmware's truncated-tail form (ROUND 13): ParseReply
// accepts both.
//
// This is the reply-side counterpart of the request builders: the client
// never sends replies, but the nsdptest fake agent (and future tests) need
// frames ParseReply accepts. req must be a full request frame (a 32-byte
// header at least) built by one of the Encode* constructors.
func EncodeReply(req []byte, status byte, failingTag uint16, payload []byte, tlvs ...TLV) []byte {
	pkt := make([]byte, 0, headerLen+len(payload)+8*len(tlvs)+4)
	pkt = append(pkt, protoVersion, byte(req[1]+1), status, 0x00)
	pkt = append(pkt, byte(failingTag>>8), byte(failingTag), 0x00, 0x00)
	pkt = append(pkt, req[8:24]...) // manager + agent MAC echo, sequence echo
	pkt = append(pkt, magic[:]...)
	pkt = append(pkt, 0, 0, 0, 0)
	pkt = append(pkt, payload...)
	for _, t := range tlvs {
		pkt = append(pkt, byte(t.Tag>>8), byte(t.Tag), byte(len(t.Value)>>8), byte(len(t.Value)))
		pkt = append(pkt, t.Value...)
	}
	pkt = append(pkt, 0xff, 0xff, 0x00, 0x00) // terminator TLV {0xFFFF, 0x0000}
	return pkt
}

// TLV is one NSDP type-length-value entry of the reply TLV region:
// {tag BE16, len BE16, value}. Value references the packet buffer it was
// walked from.
type TLV struct {
	Tag   uint16
	Value []byte
}

// WalkTLVs walks the TLV region starting at wire offset 32 of a reply
// packet: {tag BE16, len BE16, value} entries, stopping at the {0xFFFF,
// 0x0000} terminator. It reports truncated=true when a TLV header promises
// more value bytes than the packet carries (a truncated TLV region still
// yields the TLVs parsed before the cut, mirroring the probe instrument).
func WalkTLVs(pkt []byte) (tlvs []TLV, truncated bool) {
	off := headerLen
	for off+4 <= len(pkt) {
		tag := binary.BigEndian.Uint16(pkt[off : off+2])
		if tag == tlvTermTag { // terminator FF FF 00 00
			break
		}
		length := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if off+4+length > len(pkt) {
			return tlvs, true // truncated mid-TLV
		}
		tlvs = append(tlvs, TLV{Tag: tag, Value: pkt[off+4 : off+4+length]})
		off += 4 + length
	}
	return tlvs, false
}

// Reply is a parsed NSDP reply. Status and FailingTag mirror the header
// fields; TLVs are the walked reply TLV region (nil when the reply carries
// only the terminator). Truncated reports that the TLV region cut off
// mid-TLV after the returned TLVs: firmware GET replies end in wire bytes
// "… 00 00 FF FF 00 00", so the walker reads a dangling tag 0x0000 with a
// bogus length and stops mid-TLV (ROUND 13). The official web client and
// the probe instrument both accept such replies — the TLVs parsed before
// the cut are authoritative.
type Reply struct {
	Status     byte
	FailingTag uint16
	Seq        uint32
	ManagerMAC net.HardwareAddr
	AgentMAC   net.HardwareAddr
	TLVs       []TLV
	Truncated  bool
}

// ParseReply validates and parses an NSDP reply against the exchange it
// answers: the expected echo command byte (0x02 for GET replies, 0x04 for
// SET replies) and the echoed sequence and manager/agent MACs. A nil
// managerMAC or agentMAC skips the corresponding echo check (broadcast
// requests have no agent MAC to echo).
//
// Structural violations return *ErrMalformed. A reply with a non-zero
// status byte returns both the parsed Reply and an *ErrStatus carrying the
// status and the failing-tag field ([4-5] announces the required-but-
// missing TLV, e.g. tag 0x001A on a login SET that lacked the auth TLV).
// On an auth-mismatch reply (status 0x0d) the *ErrStatus also carries
// ExpectedAuth: the switch-expected auth value from the {BE16 len, bytes}
// payload after the header (diagnostic only). For status 0, a TLV region
// that truncates mid-TLV is accepted: Reply.Truncated reports the cut and
// TLVs holds the entries parsed before it (firmware replies end in a
// dangling {tag 0x0000, bogus length} pseudo-TLV — ROUND 13 — which the
// official web client and the probe instrument both tolerate).
func ParseReply(pkt []byte, expectCmd byte, wantSeq uint32, managerMAC, agentMAC net.HardwareAddr) (*Reply, error) {
	if len(pkt) < replyMinLen {
		return nil, &ErrMalformed{Reason: fmt.Sprintf("short packet (%d bytes, want at least %d)", len(pkt), replyMinLen)}
	}
	if pkt[0] != protoVersion {
		return nil, &ErrMalformed{Reason: fmt.Sprintf("version byte 0x%02x != 0x%02x", pkt[0], protoVersion)}
	}
	if pkt[1] != expectCmd {
		return nil, &ErrMalformed{Reason: fmt.Sprintf("command byte 0x%02x != 0x%02x", pkt[1], expectCmd)}
	}
	if !bytes.Equal(pkt[24:28], magic[:]) {
		return nil, &ErrMalformed{Reason: fmt.Sprintf("bad magic % x", pkt[24:28])}
	}
	seq := binary.BigEndian.Uint32(pkt[20:24])
	if seq != wantSeq {
		return nil, &ErrMalformed{Reason: fmt.Sprintf("stale sequence %d (want %d)", seq, wantSeq)}
	}
	if len(managerMAC) == 6 && !bytes.Equal(pkt[8:14], managerMAC) {
		return nil, &ErrMalformed{Reason: fmt.Sprintf("manager MAC echo %s != %s", net.HardwareAddr(pkt[8:14]), managerMAC)}
	}
	if len(agentMAC) == 6 && !bytes.Equal(pkt[14:20], agentMAC) {
		return nil, &ErrMalformed{Reason: fmt.Sprintf("agent MAC echo %s != %s", net.HardwareAddr(pkt[14:20]), agentMAC)}
	}

	r := &Reply{
		Status:     pkt[2],
		FailingTag: binary.BigEndian.Uint16(pkt[4:6]),
		Seq:        seq,
		ManagerMAC: append(net.HardwareAddr(nil), pkt[8:14]...),
		AgentMAC:   append(net.HardwareAddr(nil), pkt[14:20]...),
	}
	r.TLVs, r.Truncated = WalkTLVs(pkt)
	if r.Status != 0 {
		es := &ErrStatus{Status: r.Status, FailingTag: r.FailingTag}
		if r.Status == statusAuthMismatch {
			es.ExpectedAuth = expectedAuthPayload(pkt)
		}
		return r, es
	}
	return r, nil
}

// expectedAuthPayload extracts the switch-expected auth value from an
// auth-mismatch reply (status 0x0d): bytes [32:34] are a BE16 length N,
// then N value bytes (live-proven ROUND 8: 00 08 + an 8-byte V2 token,
// e.g. 8f 9f cf fa a7 cc 90 dd). The payload is NOT a TLV — WalkTLVs
// truncates on it — so the bytes are read directly. Returns nil when the
// payload is absent or malformed.
func expectedAuthPayload(pkt []byte) []byte {
	if len(pkt) < headerLen+2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(pkt[headerLen : headerLen+2]))
	if n == 0 || headerLen+2+n > len(pkt) {
		return nil
	}
	return append([]byte(nil), pkt[headerLen+2:headerLen+2+n]...)
}
