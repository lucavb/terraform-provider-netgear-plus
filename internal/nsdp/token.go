package nsdp

// Login password/auth-TLV tags, one per capability-selected encoding
// (nsdpmanager.exe nsdp_command_start, FUN_00492b80):
//
//	V&0x10 → 8-byte V2 token:     nsdp_set_tlv(0x1a, 8, token)
//	V&0x08 → 4-byte V1 token:     inline {htons(0x18), htons(4), token}
//	else   → plaintext password:  nsdp_set_tlv(0x0a, strlen, pw)
//
// The switch's error reply reports the required-but-missing tag in its
// [4-5] failing-tag field — live: status 0x0d with [5]=0x1a when the
// password was sent under any other tag (2026-09-12).
const (
	loginTagPlain = 0x000A
	loginTagV1    = 0x0018
	loginTagV2    = 0x001A

	// ntgrRockKey is the repeating 19-byte XOR key of the V&1 password
	// pre-transform (capability bit 0x01), applied by the client before the
	// encoding branch is selected.
	ntgrRockKey = "NtgrSmartSwitchRock"
)

// padPassword zero-pads (or truncates) the password to the fixed 20-byte
// window that the V1/V2 token mixes index into.
func padPassword(pw []byte) []byte {
	p := make([]byte, 20)
	copy(p, pw)
	return p
}

// NtgrRock derives the V&1 branch password pre-transform: the password
// bytes XORed with the repeating 19-byte key "NtgrSmartSwitchRock".
func NtgrRock(pw []byte) []byte {
	out := make([]byte, len(pw))
	for i, c := range pw {
		out[i] = c ^ ntgrRockKey[i%len(ntgrRockKey)]
	}
	return out
}

// V2LoginToken computes the 8-byte token of the V&0x10 capability branch
// (the one a GS108Ev3 uses). nonce = 4 raw nonce bytes (wire order, from
// GET attr 0x17), mac = 6 switch MAC bytes, password = 20 zero-padded
// password bytes. Each token byte is a fixed XOR mix of nonce, MAC and
// password bytes, matching nsdpmanager.exe nsdp_command_start.
func V2LoginToken(nonce, mac, password []byte) []byte {
	n, m, p := nonce, mac, password
	return []byte{
		n[3] ^ n[2] ^ m[1] ^ m[5] ^ p[2] ^ p[1] ^ p[0],
		n[3] ^ n[1] ^ m[4] ^ m[0] ^ p[4] ^ p[3] ^ p[5],
		n[0] ^ n[2] ^ m[3] ^ m[2] ^ p[8] ^ p[6] ^ p[7],
		n[0] ^ n[1] ^ m[4] ^ m[5] ^ p[11] ^ p[10] ^ p[9],
		n[3] ^ n[2] ^ m[1] ^ m[5] ^ p[12] ^ p[14] ^ p[13],
		n[3] ^ n[1] ^ m[4] ^ m[0] ^ p[17] ^ p[16] ^ p[15],
		n[0] ^ n[2] ^ m[3] ^ m[2] ^ p[19] ^ p[18] ^ p[0],
		n[0] ^ n[1] ^ m[4] ^ m[5] ^ p[3] ^ p[5] ^ p[1],
	}
}

// V1LoginToken computes the 4-byte token of the V&0x08 capability branch
// (older switches); same inputs as V2LoginToken.
func V1LoginToken(nonce, mac, password []byte) []byte {
	n, m, p := nonce, mac, password
	return []byte{
		m[1] ^ n[3] ^ n[2] ^ p[13] ^ p[9] ^ m[5] ^ p[7] ^ p[1],
		n[3] ^ n[1] ^ m[4] ^ p[14] ^ p[10] ^ p[6] ^ p[2] ^ m[0],
		m[3] ^ m[2] ^ n[0] ^ n[2] ^ p[12] ^ p[8] ^ p[5] ^ p[0],
		n[0] ^ n[1] ^ m[4] ^ p[15] ^ p[11] ^ p[4] ^ p[3] ^ m[5],
	}
}

// loginToken derives the SET password/auth-TLV value from the capability
// word V, the raw nonce bytes, the switch MAC and the admin password. When
// V&1 is set the client first XORs the password with the repeating
// "NtgrSmartSwitchRock" key; the encoding branch then follows the firmware
// precedence (checked in this order): V&0x10 V2 token, V&8 V1 token, else
// the (possibly XORed) password bytes verbatim.
func loginToken(capability uint32, nonce, mac, password []byte) []byte {
	pw := password
	if capability&1 != 0 {
		pw = NtgrRock(password)
	}
	switch {
	case capability&0x10 != 0:
		return V2LoginToken(nonce, mac, padPassword(pw))
	case capability&8 != 0:
		return V1LoginToken(nonce, mac, padPassword(pw))
	default:
		return append([]byte(nil), pw...)
	}
}

// loginTagFor selects the SET auth-TLV tag matching the encoding branch.
// Every CMD_SET_REQUEST attaches this TLV before the type-specific TLV
// (nsdp_command_start); the switch rejects a SET whose auth TLV carries
// any other tag (status 0x0d; the required tag is reported in the reply's
// [4-5] failing-tag field).
func loginTagFor(capability uint32) uint16 {
	switch {
	case capability&0x10 != 0:
		return loginTagV2
	case capability&8 != 0:
		return loginTagV1
	default:
		return loginTagPlain
	}
}
