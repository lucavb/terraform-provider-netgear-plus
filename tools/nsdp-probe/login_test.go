package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// TestV2LoginTokenNonceMix probes the nonce index mix: with n={1,0,0,0}
// (n0=1) and zeroed MAC/password, only the token bytes fed by n0 may be set.
func TestV2LoginTokenNonceMix(t *testing.T) {
	n := []byte{1, 0, 0, 0}
	m := make([]byte, 6)
	p := make([]byte, 20)
	want := []byte{0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01}
	got := v2LoginToken(n, m, p)
	if !bytes.Equal(got, want) {
		t.Fatalf("v2LoginToken(nonce mix) = % x, want % x", got, want)
	}
}

// TestV2LoginTokenMACMix probes the MAC index mix: with m={1,0,0,0,0,0}
// (m0=1) and zeroed nonce/password, only the token bytes fed by m0 may be set.
func TestV2LoginTokenMACMix(t *testing.T) {
	n := make([]byte, 4)
	m := []byte{1, 0, 0, 0, 0, 0}
	p := make([]byte, 20)
	want := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}
	got := v2LoginToken(n, m, p)
	if !bytes.Equal(got, want) {
		t.Fatalf("v2LoginToken(MAC mix) = % x, want % x", got, want)
	}
}

// TestNtgrRockXOR checks the V&1 branch: password "abc" XORed with the
// first three key bytes of "NtgrSmartSwitchRock" ('N', 't', 'g').
func TestNtgrRockXOR(t *testing.T) {
	want := []byte{0x2f, 0x16, 0x04} // 'a'^'N', 'b'^'t', 'c'^'g'
	got := ntgrRockXOR([]byte("abc"))
	if !bytes.Equal(got, want) {
		t.Fatalf("ntgrRockXOR(\"abc\") = % x, want % x", got, want)
	}
}

// TestBuildSetLoginRequest pins the exact SET wire layout: the TLV region
// starts at header offset 32, where buildHeader's trailing 0x00 is the HIGH
// byte of the first TLV tag (overwritten with tag>>8 by the builder), and
// the password TLV tag is capability-selected — 0x001A on the V2 branch,
// the tag the switch reported in its error reply's [4-5] failing-tag field
// when we sent anything else (status 0x0d, live 2026-09-12). Golden bytes
// reproduce that live run's MACs, sequence and token.
func TestBuildSetLoginRequest(t *testing.T) {
	mac := net.HardwareAddr{0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8}
	agentMAC := net.HardwareAddr{0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88}
	token := []byte{0x6f, 0x07, 0xc3, 0x8e, 0x47, 0x54, 0x9c, 0xa9}
	got := buildSetLoginRequest(mac, agentMAC, 260, loginTLVTagV2, token)
	want := []byte{
		0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // version, SET cmd, status/reserved, failing TLV, reserved
		0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8, // Manager ID (8-13)
		0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88, // Agent ID (14-19)
		0x00, 0x00, 0x01, 0x04, // sequence 260 (20-23)
		0x4e, 0x53, 0x44, 0x50, // "NSDP" (24-27)
		0x00, 0x00, 0x00, 0x00, // reserved (28-31)
		0x00, 0x1a, // TLV tag 0x001A (32-33; high byte = buildHeader's trailing 0)
		0x00, 0x08, // TLV len 8 (34-35)
		0x6f, 0x07, 0xc3, 0x8e, 0x47, 0x54, 0x9c, 0xa9, // token (36-43)
		0xff, 0xff, 0x00, 0x00, // terminator TLV {0xFFFF, 0x0000} (44-47)
	}
	if len(got) != 48 || !bytes.Equal(got, want) {
		t.Fatalf("buildSetLoginRequest = % x\nwant                    % x", got, want)
	}
}

// TestBuildSetNameRequest pins the config-SET wire layout for the system
// name. Per nsdp_command_start (FUN_00492b80) every CMD_SET_REQUEST
// attaches the AUTH TLV before its type-specific TLV, so the request is:
// AUTH TLV {0x001A, 8, token} (tag high byte rides at wire offset 32, the
// first-TLV slot), then the plaintext name TLV {0x0003, len, name} (config
// strings go out unencrypted — only password TLVs 9/10 are,
// nsdp_set_tlv_string_enhance FUN_004945d0) and the terminator. As the
// SECOND TLV, the name tag's high byte is an ordinary appended byte, so
// with the 8-byte token of TestBuildSetLoginRequest and a 6-byte name the
// request is 33 + (1+2+8) + (1+1+2+6) + 4 = 58 bytes.
func TestBuildSetNameRequest(t *testing.T) {
	mac := net.HardwareAddr{0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8}
	agentMAC := net.HardwareAddr{0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88}
	token := []byte{0x6f, 0x07, 0xc3, 0x8e, 0x47, 0x54, 0x9c, 0xa9}
	got := buildSetNameRequest(mac, agentMAC, 260, loginTLVTagV2, token, "lab-sw")
	want := []byte{
		0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // version, SET cmd, status/reserved, failing TLV, reserved
		0x2e, 0x85, 0xe5, 0xbe, 0x3b, 0xb8, // Manager ID (8-13)
		0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88, // Agent ID (14-19)
		0x00, 0x00, 0x01, 0x04, // sequence 260 (20-23)
		0x4e, 0x53, 0x44, 0x50, // "NSDP" (24-27)
		0x00, 0x00, 0x00, 0x00, // reserved (28-31)
		0x00, 0x1a, // AUTH TLV tag 0x001A (32-33; high byte = buildHeader's trailing 0)
		0x00, 0x08, // AUTH TLV len 8 (34-35)
		0x6f, 0x07, 0xc3, 0x8e, 0x47, 0x54, 0x9c, 0xa9, // token (36-43)
		0x00, 0x03, // name TLV tag 0x0003 (44-45; second TLV, full 2-byte tag appended)
		0x00, 0x06, // name TLV len 6 (46-47)
		0x6c, 0x61, 0x62, 0x2d, 0x73, 0x77, // "lab-sw" (48-53)
		0xff, 0xff, 0x00, 0x00, // terminator TLV {0xFFFF, 0x0000} (54-57)
	}
	if len(got) != 58 || !bytes.Equal(got, want) {
		t.Fatalf("buildSetNameRequest = % x\nwant                   % x", got, want)
	}
	// Field-wise asserts per the pinned layout.
	if got[1] != 0x03 {
		t.Fatalf("cmd byte = 0x%02x, want 0x03", got[1])
	}
	if s := binary.BigEndian.Uint32(got[20:24]); s != 260 {
		t.Fatalf("sequence = %d, want 260", s)
	}
	wantAuth := append([]byte{0x00, 0x1a, 0x00, 0x08}, token...)
	if !bytes.Equal(got[32:44], wantAuth) {
		t.Fatalf("AUTH TLV = % x, want % x", got[32:44], wantAuth)
	}
	wantName := append([]byte{0x00, 0x03, 0x00, 0x06}, []byte("lab-sw")...)
	if !bytes.Equal(got[44:54], wantName) {
		t.Fatalf("name TLV = % x, want % x", got[44:54], wantName)
	}
	if !bytes.Equal(got[54:58], []byte{0xff, 0xff, 0x00, 0x00}) {
		t.Fatalf("terminator = % x, want ff ff 00 00", got[54:58])
	}
}

// TestLoginTLVTagFor checks the per-branch password-TLV tag selection
// (nsdp_command_start: 0x1a for V2, 0x18 for V1, 0x0a otherwise).
func TestLoginTLVTagFor(t *testing.T) {
	cases := []struct {
		v    uint32
		want uint16
	}{
		{0x10, loginTLVTagV2},
		{0x11, loginTLVTagV2}, // rock pre-transform composes with V2
		{0x08, loginTLVTagV1},
		{0x09, loginTLVTagV1},
		{0x01, loginTLVTagPlain},
		{0x00, loginTLVTagPlain},
	}
	for _, c := range cases {
		if got := loginTLVTagFor(c.v); got != c.want {
			t.Fatalf("loginTLVTagFor(0x%02x) = 0x%04x, want 0x%04x", c.v, got, c.want)
		}
	}
}

// TestLoginTokenRockComposition checks that the V&1 NtgrSmartSwitchRock
// pre-transform composes with the encoding branches the way the client does
// (XOR first, then V2/V1/plaintext selection) instead of being a separate
// terminal branch.
func TestLoginTokenRockComposition(t *testing.T) {
	rocked := ntgrRockXOR([]byte("abc"))
	if got := loginToken(1, nil, nil, []byte("abc")); !bytes.Equal(got, rocked) {
		t.Fatalf("loginToken(V&1 only) = % x, want rock'd % x", got, rocked)
	}
	n := make([]byte, 4)
	m := make([]byte, 6)
	want := v2LoginToken(n, m, padPassword(rocked))
	if got := loginToken(0x11, n, m, []byte("abc")); !bytes.Equal(got, want) {
		t.Fatalf("loginToken(V&1|V&0x10) = % x, want V2-mixed rock'd % x", got, want)
	}
}
