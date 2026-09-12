package nsdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

// Live 2026-09-12 run constants shared by the golden tests: manager MAC,
// agent (switch) MAC, sequence 2562 and the V2 login token the switch
// accepted.
var (
	goldenMAC        = net.HardwareAddr{0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8}
	goldenAgentMAC   = net.HardwareAddr{0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88}
	goldenSeq        = uint32(2562) // 0x00000a02
	goldenLoginSeq   = uint32(260)  // 0x00000104
	goldenV2Token    = []byte{0x6f, 0x07, 0xc3, 0x8e, 0x47, 0x54, 0x9c, 0xa9}
	goldenCapability = uint32(0x10) // live: capability TLV 0x0014 = 00 00 00 10
)

// TestEncodeGetRequest pins the exact single-tag GET wire layout with the
// live 44-byte request (tag 0x14, seq 2562, 2026-09-12). The TLV region
// starts at wire offset 32, where EncodeHeader's trailing 0x00 is the first
// entry's tag HIGH byte, followed by the 4-byte entry {tag, 00, 00, 00}
// and the 7-byte trailer 00 00 00 ff ff 00 00. The multi-tag section pins
// the general form: 33-byte header prefix + one 4-byte entry PER tag +
// trailer.
func TestEncodeGetRequest(t *testing.T) {
	got := EncodeGetRequest(goldenMAC, goldenAgentMAC, goldenSeq, 0x14)
	want := []byte{
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // version, GET cmd, status/reserved, failing TLV, reserved
		0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8, // Manager ID (8-13)
		0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88, // Agent ID (14-19)
		0x00, 0x00, 0x0a, 0x02, // sequence 2562 (20-23)
		0x4e, 0x53, 0x44, 0x50, // "NSDP" (24-27)
		0x00, 0x00, 0x00, 0x00, // reserved (28-31)
		0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // first entry: tag high (header byte 32), tag low 0x14 + entry tail (33-39)
		0xff, 0xff, 0x00, 0x00, // trailer (40-43)
	}
	if len(got) != 44 || !bytes.Equal(got, want) {
		t.Fatalf("EncodeGetRequest(single) = %d bytes % x\nwant 44 bytes  % x", len(got), got, want)
	}

	// Multi-tag GET: 33-byte header prefix + 4-byte entry per tag +
	// 7-byte trailer. For tags {0x03, 0x17}: 33 + 8 + 7 = 48 bytes; the
	// first entry's tag-high byte lives in the header's trailing byte, the
	// second entry carries its own (always 0x00) tag-high byte.
	got = EncodeGetRequest(goldenMAC, goldenAgentMAC, 7, 0x03, 0x17)
	if len(got) != 48 {
		t.Fatalf("EncodeGetRequest(multi) length = %d, want 48", len(got))
	}
	if got[32] != 0x00 || got[33] != 0x03 {
		t.Fatalf("first entry = % x, want 00 03", got[32:34])
	}
	if got[37] != 0x17 {
		t.Fatalf("second entry tag low = 0x%02x, want 0x17", got[37])
	}
	if !bytes.Equal(got[38:41], []byte{0x00, 0x00, 0x00}) {
		t.Fatalf("second entry tail = % x, want 00 00 00", got[38:41])
	}
	if !bytes.Equal(got[41:48], []byte{0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00}) {
		t.Fatalf("trailer = % x, want 00 00 00 ff ff 00 00", got[41:48])
	}
	if s := binary.BigEndian.Uint32(got[20:24]); s != 7 {
		t.Fatalf("sequence = %d, want 7", s)
	}
}

// TestEncodeSetLoginRequest pins the exact live 48-byte V2 login SET frame
// (2026-09-12: MACs, sequence 260, accepted token). EncodeSetLoginRequest
// derives the token internally from capability+nonce+password, so the test
// first pins the token math: with a zero nonce and a password solved
// byte-by-byte from the inverse of the V2 token equations (all other
// inputs zeroed), the V2 mix reproduces the live token exactly — then the
// full frame must equal the live bytes.
func TestEncodeSetLoginRequest(t *testing.T) {
	nonce := []byte{0x00, 0x00, 0x00, 0x00}
	password := []byte{
		0xdc, 0x00, 0x00, 0x3a, 0xaa, 0x00, 0x00, 0x00, 0x4b, 0x00,
		0x00, 0x1d, 0xf4, 0x00, 0x00, 0x00, 0x00, 0xc3, 0x00, 0xc8,
	}
	// Precondition: the derived inputs must reproduce the live token.
	if got := V2LoginToken(nonce, goldenAgentMAC, padPassword(password)); !bytes.Equal(got, goldenV2Token) {
		t.Fatalf("precondition: V2LoginToken = % x, want live token % x", got, goldenV2Token)
	}

	got := EncodeSetLoginRequest(goldenMAC, goldenAgentMAC, goldenLoginSeq, goldenCapability, nonce, password)
	want := []byte{
		0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // version, SET cmd, status/reserved, failing TLV, reserved
		0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8, // Manager ID (8-13)
		0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88, // Agent ID (14-19)
		0x00, 0x00, 0x01, 0x04, // sequence 260 (20-23)
		0x4e, 0x53, 0x44, 0x50, // "NSDP" (24-27)
		0x00, 0x00, 0x00, 0x00, // reserved (28-31)
		0x00, 0x1a, // auth TLV tag 0x001A (32-33; high byte = header's trailing 0)
		0x00, 0x08, // auth TLV len 8 (34-35)
		0x6f, 0x07, 0xc3, 0x8e, 0x47, 0x54, 0x9c, 0xa9, // V2 token (36-43)
		0xff, 0xff, 0x00, 0x00, // terminator TLV {0xFFFF, 0x0000} (44-47)
	}
	if len(got) != 48 || !bytes.Equal(got, want) {
		t.Fatalf("EncodeSetLoginRequest = %d bytes % x\nwant 48 bytes  % x", len(got), got, want)
	}
}

// TestEncodeSetNameRequest pins the config-SET wire layout for the system
// name under the nsdp_command_start rule that EVERY CMD_SET_REQUEST
// attaches the auth TLV BEFORE the type-specific TLV:
//
//	header (cmd 3) + auth TLV {0x001A, 8, token} + name TLV {0x0003, len,
//	name} + terminator = 32 + 12 + 10 + 4 = 58 bytes for a 6-char name.
//
// The auth TLV's tag-high byte reuses the header's trailing byte at wire
// offset 32; the name TLV then carries its own full 4-byte tag+len header.
func TestEncodeSetNameRequest(t *testing.T) {
	got := EncodeSetNameRequest(goldenMAC, goldenAgentMAC, goldenLoginSeq, goldenCapability, goldenV2Token, "lab-sw")
	want := []byte{
		0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // version, SET cmd, status/reserved, failing TLV, reserved
		0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8, // Manager ID (8-13)
		0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88, // Agent ID (14-19)
		0x00, 0x00, 0x01, 0x04, // sequence 260 (20-23)
		0x4e, 0x53, 0x44, 0x50, // "NSDP" (24-27)
		0x00, 0x00, 0x00, 0x00, // reserved (28-31)
		0x00, 0x1a, // auth TLV tag 0x001A (32-33; high byte = header's trailing 0)
		0x00, 0x08, // auth TLV len 8 (34-35)
		0x6f, 0x07, 0xc3, 0x8e, 0x47, 0x54, 0x9c, 0xa9, // cached V2 token (36-43)
		0x00, 0x03, // name TLV tag 0x0003 (44-45)
		0x00, 0x06, // name TLV len 6 (46-47)
		0x6c, 0x61, 0x62, 0x2d, 0x73, 0x77, // "lab-sw" (48-53) — plaintext (FUN_004945d0)
		0xff, 0xff, 0x00, 0x00, // terminator TLV {0xFFFF, 0x0000} (54-57)
	}
	if len(got) != 58 || !bytes.Equal(got, want) {
		t.Fatalf("EncodeSetNameRequest = %d bytes % x\nwant 58 bytes  % x", len(got), got, want)
	}
	// Field-wise asserts per the pinned layout.
	if got[1] != cmdSet {
		t.Fatalf("cmd byte = 0x%02x, want 0x03", got[1])
	}
	if s := binary.BigEndian.Uint32(got[20:24]); s != goldenLoginSeq {
		t.Fatalf("sequence = %d, want %d", s, goldenLoginSeq)
	}
	if !bytes.Equal(got[32:44], append([]byte{0x00, byte(loginTagV2), 0x00, 0x08}, goldenV2Token...)) {
		t.Fatalf("auth TLV = % x, want tag 0x%04x len 8 + token % x", got[32:44], loginTagV2, goldenV2Token)
	}
	if !bytes.Equal(got[44:54], []byte{0x00, 0x03, 0x00, 0x06, 'l', 'a', 'b', '-', 's', 'w'}) {
		t.Fatalf("name TLV = % x", got[44:54])
	}
	if !bytes.Equal(got[54:58], []byte{0xff, 0xff, 0x00, 0x00}) {
		t.Fatalf("terminator = % x, want ff ff 00 00", got[54:58])
	}

	// Plaintext branch: capability without token bits sends the raw
	// (NtgrRock-XORed when bit 1) password bytes as auth TLV {0x000A}.
	got = EncodeSetNameRequest(goldenMAC, goldenAgentMAC, 7, 0, []byte("abc"), "n1")
	wantPlaintext := []byte{
		0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8,
		0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88,
		0x00, 0x00, 0x00, 0x07,
		0x4e, 0x53, 0x44, 0x50,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x0a, 0x00, 0x03, 'a', 'b', 'c', // auth TLV {0x000A, "abc"}
		0x00, 0x03, 0x00, 0x02, 'n', '1', // name TLV {0x0003, "n1"}
		0xff, 0xff, 0x00, 0x00,
	}
	if !bytes.Equal(got, wantPlaintext) {
		t.Fatalf("EncodeSetNameRequest(plaintext) = % x\nwant              % x", got, wantPlaintext)
	}
}

// TestParseReplySuccess pins the reply validation on the live 36-byte
// SET success reply: header echoes (cmd 0x04, seq 2562, both MACs), zero
// status, empty TLV region (terminator only).
func TestParseReplySuccess(t *testing.T) {
	pkt := []byte{
		0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8,
		0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88,
		0x00, 0x00, 0x0a, 0x04,
		0x4e, 0x53, 0x44, 0x50,
		0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x00,
	}
	reply, err := ParseReply(pkt, cmdSetReply, 0x0a04, goldenMAC, goldenAgentMAC)
	if err != nil {
		t.Fatalf("ParseReply: %v", err)
	}
	if reply.Status != 0 {
		t.Fatalf("status = 0x%02x, want 0", reply.Status)
	}
	if reply.FailingTag != 0 {
		t.Fatalf("failing tag = 0x%04x, want 0", reply.FailingTag)
	}
	if reply.Seq != 0x0a04 {
		t.Fatalf("seq = %d, want %d", reply.Seq, 0x0a04)
	}
	if !bytes.Equal(reply.ManagerMAC, goldenMAC) {
		t.Fatalf("manager MAC = %s, want %s", reply.ManagerMAC, goldenMAC)
	}
	if !bytes.Equal(reply.AgentMAC, goldenAgentMAC) {
		t.Fatalf("agent MAC = %s, want %s", reply.AgentMAC, goldenAgentMAC)
	}
	if len(reply.TLVs) != 0 {
		t.Fatalf("TLVs = %v, want none", reply.TLVs)
	}
}

// TestParseReplyTruncatedTail pins ROUND 13: firmware GET replies end in
// wire bytes "… 00 00 FF FF 00 00", so the TLV walk reads a dangling
// {tag 0x0000, len 0xFFFF} pseudo-TLV and cuts off mid-TLV after the
// served TLVs. ParseReply must accept such replies — the official web
// client and the probe instrument both do — with Reply.Truncated set and
// the TLVs parsed before the cut intact.
func TestParseReplyTruncatedTail(t *testing.T) {
	pkt := []byte{
		0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8,
		0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88,
		0x00, 0x00, 0x0a, 0x04,
		0x4e, 0x53, 0x44, 0x50,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x14, 0x00, 0x04, 0x00, 0x00, 0x00, 0x10, // TLV{0x0014, capability 0x10}
		0x00, 0x00, 0xff, 0xff, 0x00, 0x00, // dangling {tag 0x0000, len 0xFFFF} + terminator tail
	}
	reply, err := ParseReply(pkt, cmdGetReply, 0x0a04, goldenMAC, goldenAgentMAC)
	if err != nil {
		t.Fatalf("ParseReply: %v", err)
	}
	if !reply.Truncated {
		t.Fatal("reply.Truncated = false, want true")
	}
	if len(reply.TLVs) != 1 || reply.TLVs[0].Tag != TagCapabilityTag {
		t.Fatalf("TLVs = %v, want the single 0x0014 capability TLV", reply.TLVs)
	}
}

// TestParseReplyError pins the live error-reply shape: status 0x0d
// (required TLV missing/parse error AND auth-verify mismatch) with the
// failing-tag field [4-5] announcing the required-but-missing TLV (0x001A
// when the auth TLV was missing/wrong on a SET), plus the ROUND 8
// expected-auth payload: {BE16 len, expected token} read directly after
// the header (NOT a TLV — WalkTLVs truncates on it). This golden is the
// ROUND 5 live capture: the all-zero expected token under an empty/zero
// nonce context (resolved by ROUND 8).
func TestParseReplyError(t *testing.T) {
	pkt := []byte{
		0x01, 0x04, 0x0d, 0x00, 0x00, 0x1a, 0x00, 0x00,
		0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8,
		0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88,
		0x00, 0x00, 0x0a, 0x04,
		0x4e, 0x53, 0x44, 0x50,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
	}
	reply, err := ParseReply(pkt, cmdSetReply, 0x0a04, goldenMAC, goldenAgentMAC)
	if err == nil {
		t.Fatal("ParseReply: want error, got nil")
	}
	var es *ErrStatus
	if !errors.As(err, &es) {
		t.Fatalf("error = %T (%v), want *ErrStatus", err, err)
	}
	if es.Status != 0x0d {
		t.Fatalf("status = 0x%02x, want 0x0d", es.Status)
	}
	if es.FailingTag != loginTagV2 {
		t.Fatalf("failing tag = 0x%04x, want 0x%04x", es.FailingTag, loginTagV2)
	}
	wantAuth := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(es.ExpectedAuth, wantAuth) {
		t.Fatalf("ExpectedAuth = % x, want % x (BE16 len 8 at [32:34], then 8 zero bytes)", es.ExpectedAuth, wantAuth)
	}
	if reply == nil || reply.Status != 0x0d || reply.FailingTag != loginTagV2 {
		t.Fatalf("parsed reply = %+v, want status 0x0d failing tag 0x001a", reply)
	}
}

// TestParseReplyMalformed walks the structural validation: each mutated
// (or mismatched) reply must yield *ErrMalformed with a reason.
func TestParseReplyMalformed(t *testing.T) {
	good := []byte{
		0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8,
		0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88,
		0x00, 0x00, 0x0a, 0x04,
		0x4e, 0x53, 0x44, 0x50,
		0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x00,
	}
	mut := func(f func(pkt []byte)) []byte {
		p := append([]byte(nil), good...)
		f(p)
		return p
	}
	cases := []struct {
		name    string
		pkt     []byte
		wantSeq uint32
		mgr     net.HardwareAddr
		agent   net.HardwareAddr
	}{
		{"short packet", good[:35], 0x0a04, goldenMAC, goldenAgentMAC},
		{"bad version", mut(func(p []byte) { p[0] = 0x02 }), 0x0a04, goldenMAC, goldenAgentMAC},
		{"bad command echo", mut(func(p []byte) { p[1] = 0x02 }), 0x0a04, goldenMAC, goldenAgentMAC},
		{"bad magic", mut(func(p []byte) { p[24] = 'X' }), 0x0a04, goldenMAC, goldenAgentMAC},
		{"stale sequence", good, 0x0a05, goldenMAC, goldenAgentMAC},
		{"manager MAC echo mismatch", good, 0x0a04, net.HardwareAddr{1, 2, 3, 4, 5, 6}, goldenAgentMAC},
		{"agent MAC echo mismatch", good, 0x0a04, goldenMAC, net.HardwareAddr{1, 2, 3, 4, 5, 6}},
	}
	for _, tc := range cases {
		_, err := ParseReply(tc.pkt, cmdSetReply, tc.wantSeq, tc.mgr, tc.agent)
		var em *ErrMalformed
		if !errors.As(err, &em) {
			t.Errorf("%s: error = %T (%v), want *ErrMalformed", tc.name, err, err)
		}
	}
}
