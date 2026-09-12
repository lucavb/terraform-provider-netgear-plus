// Package nsdp implements the NETGEAR Smart Discovery Protocol (NSDP) v2
// wire protocol spoken by NETGEAR Plus series smart switches (GS105E,
// GS108E, GS308P, ...), as a Go client library.
//
// # Evidence
//
// Every wire format in this package is LIVE-PROVEN against a GS108Ev3
// running firmware V2.06.24GR (2026-09-12) by the tools/nsdp-probe
// instrument, and cross-checked against NETGEAR's own Windows client
// (nsdpmanager.exe, shipped with the ProSAFE Plus Utility):
//
//   - nsdpmanager.exe FUN_00492b80 (nsdp_command_start): GET/SET command
//     construction; the login handshake (GET attr 0x14 = capability word,
//     GET attr 0x17 = nonce, then one SET carrying the capability-selected
//     password TLV — tag 0x001A for the 8-byte V2 token, 0x0018 for the
//     4-byte V1 token, 0x000A for the plaintext password); the auth TLV
//     attached to EVERY CMD_SET_REQUEST before the type-specific TLV; and
//     the client retry counts (5 attempts for GET attr 0x14, 14 for other
//     GETs, one FRESH sequence number per attempt).
//   - nsdpmanager.exe FUN_004945d0 (nsdp_set_tlv_string_enhance): config
//     string values (e.g. the system name, TLV 0x0003) are sent as
//     PLAINTEXT — only the password TLVs (types 9/10) are encrypted.
//   - GS108Ev3 bank1 firmware V2.06.24GR: the anti-replay sequence check
//     that silently drops recycled sequence numbers, and the ~30-minute
//     lockout of ALL SET operations after 3 failed logins (XRAM
//     0x97EE/0x980F; see errors.go for the lockout caveats).
//
// # Auth nonce roll (ROUND 8, live-proven 2026-09-12)
//
// The switch ROLLS the auth nonce after every authenticated SET: a second
// SET carrying the login-time token fails with status 0x0d, failing tag
// 0x001A, and a payload {BE16 len, expected-token} right after the header
// (observed live as {00 08, 8-byte V2 token}, e.g.
// 8f 9f cf fa a7 cc 90 dd) — the token the switch wanted under the rolled
// nonce (the XOR-delta vs the sent token repeats with the V2 token
// formula's period). The client therefore refreshes the nonce (GET attr
// 0x17) and recomputes the token immediately before EVERY authenticated
// SET (Client.refreshToken); Login's own fetch-nonce-then-SET-immediately
// chain already complies. ErrStatus.ExpectedAuth surfaces the mismatch
// payload for diagnostics only — no auto-retry is ever performed with it.
// The earlier all-zero "00 08 00 00..." mismatch payload (ROUND 5) was the
// same mechanism: the expected token under an empty/zero nonce context.
//
// # Wire format
//
// Header (32 bytes): [0]=0x01 version; [1]=command (0x01 GET, 0x03 SET;
// replies echo command+1: GET→0x02, SET→0x04); [2]=status (replies; 0x00
// ok, 0x0d = required TLV missing/parse error AND auth-verify mismatch); [3]=0; [4-5]=in REPLIES the
// failing-tag BE16 (0x0000 when ok); [6-7]=0; [8-13]=manager (client) MAC;
// [14-19]=agent (switch) MAC; [20-23]=sequence BE32; [24-27]="NSDP";
// [28-31]=0.
//
// The TLV region starts at wire offset 32 with the quirk that EncodeHeader
// appends one 0x00 byte there: it is the HIGH byte of the FIRST TLV's tag.
// TLVs are {tag BE16, len BE16, value}, terminated by the TLV
// {0xFFFF, 0x0000} = bytes ff ff 00 00.
//
// # Transport
//
// UDP; the client binds the local v2 client port 63321 and sends broadcast
// requests to 255.255.255.255:63322 (the v2 switch port). The manager MAC
// is the hardware MAC of the local network interface (first non-loopback
// interface with a hardware address, lowest index, overridable by name).
package nsdp
