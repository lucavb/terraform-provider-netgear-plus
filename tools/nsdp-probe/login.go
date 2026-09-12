package main

// NSDP LOGIN: a 3-exchange UDP handshake on the same port pair and with the
// same header construction as the GET probe paths. Reverse-engineered from
// NETGEAR's own client (nsdpmanager.exe) and verified against GS108Ev3
// firmware — see runLogin for the exchange sequence and loginToken for the
// capability-selected token derivation.
//
// NONCE ROLL RULE (live-proven, ROUND 8 2026-09-12): the switch ROLLS its
// auth nonce after every authenticated SET. The probe's login SET, whose
// token was derived from a fresh GET-0x17 nonce, was accepted — but the
// name SET immediately after it, re-carrying that SAME cached token, failed
// with status 0x0d / failing tag 0x001A, and the switch's error reply
// contained the 8-byte token it expected, which decodes as a well-formed V2
// token for the rolled nonce. Every SET must therefore carry a token
// derived from a nonce fetched immediately before it; runLogin's login SET
// already does (GET 0x17 → SET with nothing in between) and must keep doing
// so.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	// Login SET password-TLV tags, one per capability-selected encoding
	// (nsdpmanager.exe nsdp_command_start disasm, 2026-09-12):
	//   V&0x10 → 8-byte V2 token:    PUSH 0x1a @0x492faa, nsdp_set_tlv(0x1a, 8, token)
	//   V&8    → 4-byte V1 token:    PUSH 0x18 @0x492f2b, inline {htons(0x18), htons(4), token}
	//   else   → plaintext password: PUSH 0x0a @0x49300b, nsdp_set_tlv(0xa, strlen, pw)
	// The switch's error reply reports the required-but-missing tag in its
	// [4-5] failing-tag field — live: status 0x0d with [5]=0x1a when we sent
	// the password under any other tag.
	loginTLVTagPlain = 0x000A
	loginTLVTagV1    = 0x0018
	loginTLVTagV2    = 0x001A
	// ntgrRockKey is the repeating 19-byte XOR key of the V&1 password
	// pre-transform (capability bit 0x01), applied by the client before the
	// encoding branch is selected.
	ntgrRockKey = "NtgrSmartSwitchRock"
	// systemNameTLVTag is the config SET TLV carrying the switch system
	// name; GET attr byte 0x03 replies as TLV 0x0003. Config string values
	// go out as PLAINTEXT TLVs — only password TLVs (types 9/10) are
	// encrypted (nsdpmanager.exe nsdp_set_tlv_string_enhance,
	// FUN_004945d0).
	systemNameTLVTag = 0x0003
)

// padPassword zero-pads (or truncates) the password to the fixed 20-byte
// window that the V1/V2 token mixes index into.
func padPassword(pw []byte) []byte {
	p := make([]byte, 20)
	copy(p, pw)
	return p
}

// ntgrRockXOR derives the V&1 branch token: the password bytes XORed with
// the repeating 19-byte key "NtgrSmartSwitchRock".
func ntgrRockXOR(pw []byte) []byte {
	out := make([]byte, len(pw))
	for i, c := range pw {
		out[i] = c ^ ntgrRockKey[i%len(ntgrRockKey)]
	}
	return out
}

// v2LoginToken computes the 8-byte token of the V&0x10 branch (the one a
// GS108Ev3 uses). n = 4 raw nonce bytes (wire order), m = 6 switch MAC bytes,
// p = 20 zero-padded password bytes. Each token byte is a fixed XOR mix of
// nonce, MAC and password bytes, matching nsdpmanager.exe.
func v2LoginToken(n, m, p []byte) []byte {
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

// v1LoginToken computes the 4-byte token of the V&8 branch (older switches),
// with the same n/m/p inputs as v2LoginToken.
func v1LoginToken(n, m, p []byte) []byte {
	return []byte{
		m[1] ^ n[3] ^ n[2] ^ p[13] ^ p[9] ^ m[5] ^ p[7] ^ p[1],
		n[3] ^ n[1] ^ m[4] ^ p[14] ^ p[10] ^ p[6] ^ p[2] ^ m[0],
		m[3] ^ m[2] ^ n[0] ^ n[2] ^ p[12] ^ p[8] ^ p[5] ^ p[0],
		n[0] ^ n[1] ^ m[4] ^ p[15] ^ p[11] ^ p[4] ^ p[3] ^ m[5],
	}
}

// loginToken derives the login SET password-TLV value from the capability
// word V, the raw nonce bytes, the switch MAC and the admin password. When
// V&1 is set the client first XORs the password with the repeating
// "NtgrSmartSwitchRock" key; the encoding branch then follows the firmware
// precedence (checked in this order): V&0x10 v2 token, V&8 v1 token, else
// the (possibly XORed) password bytes verbatim.
func loginToken(v uint32, nonce, mac, password []byte) []byte {
	pw := password
	if v&1 != 0 {
		pw = ntgrRockXOR(password)
	}
	switch {
	case v&0x10 != 0:
		return v2LoginToken(nonce, mac, padPassword(pw))
	case v&8 != 0:
		return v1LoginToken(nonce, mac, padPassword(pw))
	default:
		return append([]byte(nil), pw...)
	}
}

// loginTLVTagFor selects the SET TLV tag matching the encoding branch. The
// switch rejects a login SET whose password TLV carries any other tag
// (status 0x0d; the required tag is reported in reply [4-5]).
func loginTLVTagFor(v uint32) uint16 {
	switch {
	case v&0x10 != 0:
		return loginTLVTagV2
	case v&8 != 0:
		return loginTLVTagV1
	default:
		return loginTLVTagPlain
	}
}

// capabilityBits renders the capability word V decoded into its known login
// branches: bit 0x10 = v2 token login, bit 0x08 = v1 token login,
// bit 0x01 = NtgrSmartSwitchRock password XOR.
func capabilityBits(v uint32) string {
	var parts []string
	if v&0x10 != 0 {
		parts = append(parts, "bit 0x10: v2 token login")
	}
	if v&8 != 0 {
		parts = append(parts, "bit 0x08: v1 token login")
	}
	if v&1 != 0 {
		parts = append(parts, "bit 0x01: NtgrSmartSwitchRock password XOR login")
	}
	if unknown := v &^ 0x19; unknown != 0 {
		parts = append(parts, fmt.Sprintf("unknown bits 0x%08x", unknown))
	}
	if len(parts) == 0 {
		return "no known login bits (plaintext password branch)"
	}
	return strings.Join(parts, ", ")
}

// checkReplyHeader validates the reply header fields for a given expected
// command byte (0x02 for GET replies, 0x04 for the SET login reply):
// minimum length, magic "NSDP" at offset 24 and the command byte.
// checkResponseHeader in main.go is the GET-specific variant.
func checkReplyHeader(pkt []byte, expectCmd byte) (string, bool) {
	if len(pkt) < 32 {
		return fmt.Sprintf("short packet (%d bytes)", len(pkt)), false
	}
	if string(pkt[24:28]) != "NSDP" {
		return fmt.Sprintf("bad magic % x", pkt[24:28]), false
	}
	if pkt[1] != expectCmd {
		return fmt.Sprintf("command byte 0x%02x != 0x%02x", pkt[1], expectCmd), false
	}
	return "", true
}

// buildSetLoginRequest builds the NSDP LOGIN SET request: the same 32-byte
// header as a GET (Manager/Agent IDs, sequence, magic) but with cmd byte 3,
// one password TLV {tag,len,value} and the 4-byte terminator TLV.
//
// Wire layout (live-verified 2026-09-12 + nsdp_command_start disasm): the
// TLV region starts at header offset 32 — the byte buildHeader appends
// there, long labelled a "filler", is the HIGH byte of the first TLV's tag
// and is overwritten with tag>>8 here. The terminator is the TLV {tag
// 0xFFFF, len 0x0000}, exactly what nsdp_command_start writes at
// LAB_00493c6a after the login command's single password TLV.
func buildSetLoginRequest(mac, agentMAC net.HardwareAddr, seq uint32, tag uint16, token []byte) []byte {
	req := buildHeader(mac, agentMAC, seq)                              // 33 bytes; [32] = first TLV tag high byte
	req[1] = 0x03                                                       // command: SET (3)
	req[32] = byte(tag >> 8)                                            // tag high byte at wire offset 32
	req = append(req, byte(tag), byte(len(token)>>8), byte(len(token))) // tag lo, len hi, len lo
	req = append(req, token...)
	req = append(req, 0xff, 0xff, 0x00, 0x00) // terminator TLV {0xFFFF, 0x0000}
	return req
}

// buildSetNameRequest builds the config SET request for the switch system
// name, mirroring buildSetLoginRequest's header and TLV conventions. Per
// nsdpmanager.exe nsdp_command_start (FUN_00492b80), EVERY CMD_SET_REQUEST
// attaches the AUTH TLV before its type-specific TLV — the function
// unconditionally runs the login/password branches ("Begin CMD_SET_REQUEST,
// password is: %s" → V2: tag 0x001A len 8 token; V1: tag 0x0018 len 4;
// plaintext: tag 0x000A) BEFORE the per-type switch. Layout: 33-byte header
// (cmd byte 3; wire offset 32 = AUTH tag's high byte), AUTH TLV {authTag,
// len(token), token}, then the plaintext name TLV {0x0003, len(name), name}
// (config strings go out unencrypted — only password TLVs 9/10 are,
// nsdp_set_tlv_string_enhance FUN_004945d0), then the {0xFFFF, 0x0000}
// terminator TLV. Only the first TLV's tag high byte rides at offset 32;
// the name TLV is second, so its full 2-byte tag is appended. With an
// 8-byte token and a 6-byte name: 33 + (1+2+8) + (1+1+2+6) + 4 = 58 bytes.
func buildSetNameRequest(mac, agentMAC net.HardwareAddr, seq uint32, authTag uint16, token []byte, name string) []byte {
	req := buildHeader(mac, agentMAC, seq)                                  // 33 bytes; [32] = AUTH TLV tag high byte
	req[1] = 0x03                                                           // command: SET (3)
	req[32] = byte(authTag >> 8)                                            // AUTH tag high byte at wire offset 32
	req = append(req, byte(authTag), byte(len(token)>>8), byte(len(token))) // AUTH tag lo, len hi, len lo
	req = append(req, token...)
	req = append(req, byte(systemNameTLVTag)>>8, byte(systemNameTLVTag), byte(len(name)>>8), byte(len(name))) // name tag hi+lo, len hi+lo
	req = append(req, name...)
	req = append(req, 0xff, 0xff, 0x00, 0x00) // terminator TLV {0xFFFF, 0x0000}
	return req
}

// readLoginReply waits up to wait for a packet from ANY source address/port
// whose header matches the current exchange: magic "NSDP", command byte
// expectCmd and the echoed sequence wantSeq. Mismatching packets are dropped
// and the window keeps running, like the sweep path. Returns ok=false when
// the window expires with no matching reply.
func readLoginReply(conn net.PacketConn, label string, wantSeq uint32, expectCmd byte, wait time.Duration, verbose bool) (pkt []byte, src string, ok bool) {
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		fmt.Fprintf(os.Stderr, "nsdp-probe: set read deadline: %v\n", err)
		os.Exit(2)
	}
	buf := make([]byte, 4096)
	for {
		n, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil, "", false
			}
			fmt.Fprintf(os.Stderr, "nsdp-probe: read: %v\n", err)
			os.Exit(2)
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		src = ""
		if ua, ok := raddr.(*net.UDPAddr); ok {
			src = ua.IP.String()
		}
		if reason, ok := checkReplyHeader(pkt, expectCmd); !ok {
			if verbose {
				fmt.Fprintf(os.Stderr, "drop packet from %s: %s\n", src, reason)
			}
			continue
		}
		if gotSeq := binary.BigEndian.Uint32(pkt[20:24]); gotSeq != wantSeq {
			if verbose {
				fmt.Fprintf(os.Stderr, "drop packet from %s: stale sequence %d (want %d for %s)\n", src, gotSeq, wantSeq, label)
			}
			continue
		}
		return pkt, src, true
	}
}

// getLoginAttr performs a single-tag GET exchange, retrying a silent switch
// like the client does (nsdp_command_start: GET type 0x14 → 5 attempts,
// otherwise 14), each attempt with a fresh sequence number (doc §6
// anti-replay), consuming *seq. The attr byte N replies as TLV tag 0x000N,
// like the probe paths. Prints the failure reason and returns ok=false when
// all attempts go unanswered, the reply carries an error status, or the TLV
// is missing.
func getLoginAttr(conn net.PacketConn, dst net.Addr, mac, agentMAC net.HardwareAddr, seq *uint32, attr byte, wait time.Duration, verbose bool) ([]byte, bool) {
	attempts := 14
	if attr == 0x14 {
		attempts = 5
	}
	for i := 1; ; i++ {
		req := buildSweepRequest(mac, agentMAC, *seq, [4]byte{attr, 0x00, 0x00, 0x00})
		if verbose {
			fmt.Printf("GET attr 0x%02x seq=%d request (%d bytes):\n%s", attr, *seq, len(req), hexDump(req))
		}
		if _, err := conn.WriteTo(req, dst); err != nil {
			fmt.Fprintf(os.Stderr, "nsdp-probe: send GET attr 0x%02x: %v\n", attr, err)
			os.Exit(2)
		}
		pkt, src, ok := readLoginReply(conn, fmt.Sprintf("GET attr 0x%02x", attr), *seq, 0x02, wait, verbose)
		(*seq)++
		if ok {
			if status := pkt[2]; status != 0 {
				fmt.Printf("login failed: %s: GET attr 0x%02x error status 0x%02x (%s)\n", src, attr, status, statusName(status))
				return nil, false
			}
			tlvs, _ := walkTLVs(pkt)
			for _, t := range tlvs {
				if t.tag == uint16(attr) {
					return t.val, true
				}
			}
			fmt.Printf("login failed: %s: reply carries no TLV 0x%04x\n", src, attr)
			return nil, false
		}
		if i >= attempts {
			break
		}
		fmt.Printf("GET attr 0x%02x: no response (attempt %d/%d), retrying\n", attr, i, attempts)
	}
	fmt.Printf("login failed: no valid response to GET attr 0x%02x after %d attempts\n", attr, attempts)
	return nil, false
}

// runLogin performs the NSDP LOGIN handshake against the switch identified
// by agentMAC, one fresh sequence per request (the switch drops stale
// sequences, doc §6 — the GET legs retry with a new sequence per attempt,
// mirroring the client: 5 attempts for attr 0x14, 14 for others):
//
//  1. GET attr 0x14 -> TLV {0x0014, 4 bytes} = capability word V (BE u32)
//  2. GET attr 0x17 -> TLV {0x0017, 4 bytes} = nonce n[0..3] (raw wire order)
//  3. SET (cmd 3) one password TLV {tag per capability — 0x001A on the V2
//     branch, len, token} -> reply cmd byte 4, status byte 0 = accepted
//
// Returns whether the switch accepted the login, the next unused sequence
// number (every GET attempt and the login SET consume one, so follow-up
// requests on the logged-in session — e.g. the -set-name flow — must
// continue from the returned counter, not baseSeq+N), the capability word
// V (follow-up flows need it to re-derive the session token from a
// refreshed nonce), and the session's auth material: the
// capability-selected password-TLV tag (loginTLVTagFor) and the token
// bytes sent in the login SET (nil on early failure paths; STALE for any
// SET after this one — the switch rolls its nonce after every
// authenticated SET, so every later SET must first re-GET attr 0x17 and
// re-derive its token, as the -set-name flow does). Every client
// CMD_SET_REQUEST re-attaches the refreshed AUTH TLV before its
// type-specific TLV (nsdp_command_start FUN_00492b80).
func runLogin(conn net.PacketConn, dst net.Addr, mac, agentMAC net.HardwareAddr, baseSeq uint32, wait time.Duration, password []byte, verbose bool) (bool, uint32, uint32, uint16, []byte) {
	seq := baseSeq
	var v uint32
	var authTag uint16
	var token []byte
	capVal, ok := getLoginAttr(conn, dst, mac, agentMAC, &seq, 0x14, wait, verbose)
	if !ok {
		return false, seq, v, authTag, token
	}
	if len(capVal) != 4 {
		fmt.Printf("login failed: capability TLV 0x0014 has %d value bytes, want 4\n", len(capVal))
		return false, seq, v, authTag, token
	}
	v = binary.BigEndian.Uint32(capVal)
	fmt.Printf("capability: % x (V=0x%08x; %s)\n", capVal, v, capabilityBits(v))

	nonce, ok := getLoginAttr(conn, dst, mac, agentMAC, &seq, 0x17, wait, verbose)
	if !ok {
		return false, seq, v, authTag, token
	}
	if len(nonce) != 4 {
		fmt.Printf("login failed: nonce TLV 0x0017 has %d value bytes, want 4\n", len(nonce))
		return false, seq, v, authTag, token
	}
	fmt.Printf("nonce: % x\n", nonce)

	token = loginToken(v, nonce, agentMAC, password)
	authTag = loginTLVTagFor(v)
	fmt.Printf("token: tag 0x%04x len %d value % x\n", authTag, len(token), token)

	req := buildSetLoginRequest(mac, agentMAC, seq, authTag, token)
	if verbose {
		fmt.Printf("SET login request seq=%d (%d bytes):\n%s", seq, len(req), hexDump(req))
	}
	if _, err := conn.WriteTo(req, dst); err != nil {
		fmt.Fprintf(os.Stderr, "nsdp-probe: send SET login: %v\n", err)
		os.Exit(2)
	}
	pkt, src, ok := readLoginReply(conn, "SET login", seq, 0x04, wait, verbose)
	seq++ // the login SET consumed its sequence
	if !ok {
		fmt.Println("login failed: no response to SET login request")
		return false, seq, v, authTag, token
	}
	fmt.Printf("SET reply from %s (%d bytes):\n%s", src, len(pkt), hexDump(pkt))
	fmt.Printf("SET reply: cmd byte 0x%02x (want 0x04), status byte 0x%02x (%s)\n", pkt[1], pkt[2], statusName(pkt[2]))
	if pkt[2] != 0 {
		fmt.Println("login REJECTED")
		return false, seq, v, authTag, token
	}
	fmt.Println("login OK")
	return true, seq, v, authTag, token
}
