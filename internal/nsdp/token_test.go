package nsdp

import (
	"bytes"
	"testing"
)

// TestV2LoginTokenNonceMix probes the nonce index mix: with n={1,0,0,0}
// (n0=1) and zeroed MAC/password, only the token bytes fed by n0 may be set.
func TestV2LoginTokenNonceMix(t *testing.T) {
	nonce := []byte{1, 0, 0, 0}
	mac := make([]byte, 6)
	pw := make([]byte, 20)
	want := []byte{0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01}
	got := V2LoginToken(nonce, mac, pw)
	if !bytes.Equal(got, want) {
		t.Fatalf("V2LoginToken(nonce mix) = % x, want % x", got, want)
	}
}

// TestV2LoginTokenMACMix probes the MAC index mix: with m={1,0,0,0,0,0}
// (m0=1) and zeroed nonce/password, only the token bytes fed by m0 may be
// set.
func TestV2LoginTokenMACMix(t *testing.T) {
	nonce := make([]byte, 4)
	mac := []byte{1, 0, 0, 0, 0, 0}
	pw := make([]byte, 20)
	want := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}
	got := V2LoginToken(nonce, mac, pw)
	if !bytes.Equal(got, want) {
		t.Fatalf("V2LoginToken(MAC mix) = % x, want % x", got, want)
	}
}

// TestNtgrRockXOR checks the V&1 branch: password "abc" XORed with the
// first three key bytes of "NtgrSmartSwitchRock" ('N', 't', 'g').
func TestNtgrRockXOR(t *testing.T) {
	want := []byte{0x2f, 0x16, 0x04} // 'a'^'N', 'b'^'t', 'c'^'g'
	got := NtgrRock([]byte("abc"))
	if !bytes.Equal(got, want) {
		t.Fatalf("NtgrRock(\"abc\") = % x, want % x", got, want)
	}
}

// TestLoginTLVTagFor checks the per-branch auth-TLV tag selection
// (nsdp_command_start: 0x1a for V2, 0x18 for V1, 0x0a otherwise).
func TestLoginTLVTagFor(t *testing.T) {
	cases := []struct {
		capability uint32
		want       uint16
	}{
		{0x10, loginTagV2},
		{0x11, loginTagV2}, // rock pre-transform composes with V2
		{0x08, loginTagV1},
		{0x09, loginTagV1},
		{0x01, loginTagPlain},
		{0x00, loginTagPlain},
	}
	for _, c := range cases {
		if got := loginTagFor(c.capability); got != c.want {
			t.Fatalf("loginTagFor(0x%02x) = 0x%04x, want 0x%04x", c.capability, got, c.want)
		}
	}
}

// TestLoginTokenRockComposition checks that the V&1 NtgrSmartSwitchRock
// pre-transform composes with the encoding branches the way the client
// does (XOR first, then V2/V1/plaintext selection) instead of being a
// separate terminal branch.
func TestLoginTokenRockComposition(t *testing.T) {
	rocked := NtgrRock([]byte("abc"))
	if got := loginToken(1, nil, nil, []byte("abc")); !bytes.Equal(got, rocked) {
		t.Fatalf("loginToken(V&1 only) = % x, want rock'd % x", got, rocked)
	}
	nonce := make([]byte, 4)
	mac := make([]byte, 6)
	want := V2LoginToken(nonce, mac, padPassword(rocked))
	if got := loginToken(0x11, nonce, mac, []byte("abc")); !bytes.Equal(got, want) {
		t.Fatalf("loginToken(V&1|V&0x10) = % x, want V2-mixed rock'd % x", got, want)
	}
}
