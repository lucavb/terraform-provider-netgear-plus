// Command nsdp-probe sends NSDP v2 requests (as documented in
// docs/nsdp-protocol.md) as UDP broadcasts and prints what switches answer.
// It is a standalone verification tool for the reverse-engineered NSDP wire
// protocol of the NETGEAR GS108Ev3. GET (command 1) only — except in
// -password login mode, which performs the NSDP LOGIN handshake and sends a
// single SET (command 3) request carrying the derived login token, and
// -set-name mode, which additionally SETs the system name.
//
// Usage:
//
//	go run ./tools/nsdp-probe [-timeout 10s] [-iface en0] [-seq 258] [-verbose]
//	                         [-tags 01,03,04] [-blocks 78,74] [-agent-mac 8c:3b:ad:25:1b:88]
//	                         [-lport 63321] [-dport 63322]
//	go run ./tools/nsdp-probe -sweep attrs  [-wait 800ms] [-agent-mac ...]
//	go run ./tools/nsdp-probe -sweep blocks [-blocks 0c,30,94,78,74] [-wait 800ms] [-agent-mac ...]
//	go run ./tools/nsdp-probe -password <admin-pw> -agent-mac 8c:3b:ad:25:1b:88
//	                         [-iface en0] [-seq 258] [-wait 800ms] [-lport 63321] [-dport 63322]
//	go run ./tools/nsdp-probe -set-name <string> -password <admin-pw> -agent-mac 8c:3b:ad:25:1b:88
//	                         [-iface en0] [-wait 800ms] [-lport 63321] [-dport 63322]
//
// -lport is the local UDP bind port and -dport the destination port of the
// broadcast request; both apply in normal and -sweep mode. The defaults are
// the v2 port pair (doc §2); the legacy v1 pair is 63323/63324, which the
// firmware also serves (`-lport 63323 -dport 63324`). Replies arrive from the
// switch's own port (63322 on v2, 63324 on v1) but responses from ANY source
// address/port are accepted — the NSDP header validation is the filter.
//
// Login mode (-password, requires -agent-mac): a 3-exchange handshake —
// GET attr 0x14 (capability word V), GET attr 0x17 (nonce), then one SET
// (cmd 3) with the derived token in the capability-selected password TLV
// (0x001A on the V2 branch, 0x0018 on V1, 0x000A plaintext); the SET reply
// must have cmd byte 4 and status byte 0. See login.go. WARNING: 3 failed
// login attempts lock ALL SET operations on the switch for ~30 minutes.
//
// Set-name mode (-set-name <string>, requires -password and -agent-mac):
// runs the login handshake first, then reads the current system name,
// refreshes the auth nonce (a fresh GET attr 0x17 immediately before the
// SET) and recomputes the token, and SETs the new value as a SET carrying
// the per-branch AUTH TLV (like EVERY client CMD_SET_REQUEST —
// nsdp_command_start FUN_00492b80 attaches the password TLV before the
// per-type switch) followed by the plaintext string TLV 0x0003 (only
// password TLVs 9/10 are encrypted — nsdp_set_tlv_string_enhance
// FUN_004945d0), reads it back and exits 0 only on a matching read-back.
// It supersedes plain login mode (the login flow runs, the config SET
// continues the same logged-in session). An explicit -set-name ” is the
// RESTORE variant: it SETs the empty string (the flag's presence, not its
// value, selects the mode).
//
// The nonce refresh is mandatory: the switch ROLLS its auth nonce after
// every authenticated SET. Live evidence (ROUND 8, 2026-09-12): the probe's
// login SET — whose token was derived from a fresh GET-0x17 nonce —
// succeeded, but the immediately following name SET re-carrying that SAME
// cached token failed with status 0x0d / failing tag 0x001A; the switch's
// error reply even contained the 8-byte token it expected, which decodes
// as a well-formed V2 token for the rolled nonce. Every SET must carry a
// token derived from a nonce fetched immediately before it — the login
// flow already does (GET 0x17 → login SET with nothing in between) and
// must keep doing so.
//
// Default (no new flags) behavior is byte-identical to the fixed 92-byte
// Appendix-B discovery request. In -sweep mode one attribute/block is probed
// per request with a fresh sequence per item (doc §6 anti-replay) and a
// per-item response window of -wait; -timeout is ignored there.
//
// Exit codes: 0 = at least one switch responded (login accepted; set-name:
// read-back matched), 1 = no switch answered / login rejected / set-name
// failed or mismatched, 2 = usage or socket error.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	defaultClientPort = 63321 // default -lport: v2 client bind port (doc §2)
	defaultServerPort = 63322 // default -dport: v2 switch port (doc §2)
	broadcastIP       = "255.255.255.255"
	resendAfter       = 5 * time.Second
)

// Default request content, reproducing the official v2 discovery request
// from Appendix B byte for byte. Note that the two default block entries use
// different entry tag bytes there: {14 00 00 78} for the SN block but
// {00 00 00 74} for block 0x74 — hence entries are stored verbatim.
var (
	defaultAttrTags      = []byte{0x01, 0x03, 0x04, 0x06, 0x07, 0x08, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	defaultBlockEntries  = [][4]byte{{0x14, 0x00, 0x00, 0x78}, {0x00, 0x00, 0x00, 0x74}}
	sweepAttrTags        = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a}
	defaultSweepBlockIDs = []byte{0x0c, 0x30, 0x94, 0x78, 0x74}
)

// statusNames maps the response status byte (doc §5) to a human-readable name.
var statusNames = map[byte]string{
	0:    "ok",
	1:    "bad version",
	2:    "bad command",
	3:    "invalid/unknown attribute",
	4:    "unknown GET body/block tag",
	5:    "SET-related failure",
	7:    "manager MAC check failed",
	0x84: "SET / tag-0x10 specific error",
	0x0F: "other failure",
}

func statusName(s byte) string {
	if n, ok := statusNames[s]; ok {
		return n
	}
	return fmt.Sprintf("unknown status 0x%02x", s)
}

func main() {
	timeout := flag.Duration("timeout", 10*time.Second, "how long to listen for responses (ignored in -sweep mode)")
	ifaceName := flag.String("iface", "", "network interface to use (default: first non-loopback interface with a hardware address, lowest index)")
	seqFlag := flag.Uint("seq", 258, "base NSDP sequence number (32-bit big-endian, request offsets 20-23); in sweeps item i uses seq+i")
	verbose := flag.Bool("verbose", false, "print request bytes, non-inventory TLVs and dropped packets")
	tagsFlag := flag.String("tags", "", "comma-separated hex attr tags (e.g. 01,03,04); replaces the default 11-tag header-attr list; ignored in -sweep attrs mode")
	blocksFlag := flag.String("blocks", "", "comma-separated hex block IDs (e.g. 78,74,0c); each emitted as {14,00,00,id}; also overrides the -sweep blocks list")
	agentMACFlag := flag.String("agent-mac", "", "target switch MAC for request bytes 14-19 (Agent ID), e.g. 8c:3b:ad:25:1b:88; default all-zero broadcast")
	waitFlag := flag.Duration("wait", 800*time.Millisecond, "per-request response window in sweep mode")
	sweepFlag := flag.String("sweep", "", "sweep mode: probe one attr/block per request — \"attrs\" or \"blocks\"")
	lportFlag := flag.Int("lport", defaultClientPort, "local UDP port to bind (v2 default 63321; v1 uses 63323)")
	dportFlag := flag.Int("dport", defaultServerPort, "destination UDP port of the broadcast request (v2 default 63322; v1 uses 63324)")
	passwordFlag := flag.String("password", "", "switch admin password — when set, run the NSDP LOGIN handshake instead of the GET/sweep modes (requires -agent-mac)")
	setName := flag.String("set-name", "", "set the switch system name (requires -password and -agent-mac): logs in, prints the current name, refreshes the auth nonce before the SET, applies the new value, reads it back")
	// flag uses ExitOnError, which already exits with status 2 on bad flags.
	flag.Parse()

	for _, p := range []struct {
		name string
		val  int
	}{
		{"lport", *lportFlag},
		{"dport", *dportFlag},
	} {
		if p.val < 1 || p.val > 65535 {
			fmt.Fprintf(os.Stderr, "nsdp-probe: -%s must be 1-65535, got %d\n", p.name, p.val)
			os.Exit(2)
		}
	}

	sweep := strings.ToLower(strings.TrimSpace(*sweepFlag))
	if sweep != "" && sweep != "attrs" && sweep != "blocks" {
		fmt.Fprintf(os.Stderr, "nsdp-probe: -sweep must be \"attrs\" or \"blocks\", got %q\n", *sweepFlag)
		os.Exit(2)
	}

	iface, err := pickInterface(*ifaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nsdp-probe: %v\n", err)
		os.Exit(2)
	}
	if len(iface.HardwareAddr) != 6 {
		fmt.Fprintf(os.Stderr, "nsdp-probe: interface %q has no usable 6-byte hardware address\n", iface.Name)
		os.Exit(2)
	}

	// Attr tag list: defaults reproduce Appendix B; -tags replaces it.
	attrTags := defaultAttrTags
	if *tagsFlag != "" {
		if attrTags, err = parseHexList(*tagsFlag, "attr tag"); err != nil {
			fmt.Fprintf(os.Stderr, "nsdp-probe: %v\n", err)
			os.Exit(2)
		}
	}
	if sweep == "attrs" && *tagsFlag != "" {
		fmt.Fprintf(os.Stderr, "nsdp-probe: note: -tags is ignored in -sweep attrs mode (fixed 0x01..0x1a list)\n")
	}

	// Block entries: defaults reproduce Appendix B verbatim; -blocks replaces
	// them with {14,00,00,id} entries and also overrides the sweep block list.
	blockEntries := defaultBlockEntries
	sweepBlockIDs := defaultSweepBlockIDs
	if *blocksFlag != "" {
		var ids []byte
		if ids, err = parseHexList(*blocksFlag, "block id"); err != nil {
			fmt.Fprintf(os.Stderr, "nsdp-probe: %v\n", err)
			os.Exit(2)
		}
		blockEntries = blockEntriesFor(ids)
		sweepBlockIDs = ids
	}

	// Agent ID (request bytes 14-19): default all-zero broadcast.
	var agentMAC net.HardwareAddr
	if *agentMACFlag != "" {
		if agentMAC, err = net.ParseMAC(*agentMACFlag); err != nil {
			fmt.Fprintf(os.Stderr, "nsdp-probe: -agent-mac %q: %v\n", *agentMACFlag, err)
			os.Exit(2)
		}
	}

	// Set-name mode (-set-name): privileged config-SET verification —
	// login first, then read the system name, SET it, read it back. The
	// config SET must follow the LOGIN handshake, so -password is
	// mandatory; -agent-mac is checked by the login block below.
	setNameMode := *setName != ""
	// An explicit `-set-name ''` is the RESTORE variant — it SETs the name
	// back to the empty string (the switch's live current name), so the
	// flag's presence, not its value, selects the mode.
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "set-name" {
			setNameMode = true
		}
	})
	if setNameMode && *passwordFlag == "" {
		fmt.Fprintf(os.Stderr, "nsdp-probe: -set-name requires -password: the system-name SET must follow the NSDP LOGIN handshake\n")
		os.Exit(2)
	}

	// Login mode (-password): runs the NSDP LOGIN handshake instead of the
	// GET/sweep behavior. The login token mixes in the switch MAC, so
	// -agent-mac is mandatory.
	login := *passwordFlag != ""
	if login {
		if agentMAC == nil {
			fmt.Fprintf(os.Stderr, "nsdp-probe: -password (login mode) requires -agent-mac: the login token is derived from the switch MAC\n")
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "NOTE: 3 failed login attempts lock ALL SET operations on the switch for ~30 minutes. Double-check the password before running.")
		if sweep != "" {
			fmt.Fprintf(os.Stderr, "nsdp-probe: note: -sweep is ignored in login mode (-password)\n")
		}
	}

	seq := uint32(*seqFlag)
	if login {
		// The client picks a random base sequence per session
		// (nsdp_command_start: rand()%1000, then +1 per command); fresh
		// high sequences stay outside the switch's anti-replay window.
		// Live run 3 (2026-09-12) went silent re-using base 258 for the
		// third time. An explicit -seq always wins.
		explicitSeq := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "seq" {
				explicitSeq = true
			}
		})
		if !explicitSeq {
			rng := rand.New(rand.NewSource(time.Now().UnixNano()))
			seq = uint32(1000 + rng.Intn(9000))
		}
	}
	broadcastDest := fmt.Sprintf("%s:%d", broadcastIP, *dportFlag)

	if login {
		mode := "login"
		if setNameMode {
			mode = "set-name"
		}
		fmt.Printf("nsdp-probe: %s iface=%s mac=%s agent=%s seq=%d wait=%s dest=%s\n",
			mode, iface.Name, iface.HardwareAddr, agentMAC, seq, *waitFlag, broadcastDest)
		if setNameMode {
			fmt.Printf("nsdp-probe: new name: %q\n", *setName)
		}
	} else if sweep != "" {
		fmt.Printf("nsdp-probe: sweep=%s iface=%s mac=%s seq=%d wait=%s dest=%s\n",
			sweep, iface.Name, iface.HardwareAddr, seq, *waitFlag, broadcastDest)
		if agentMAC != nil {
			fmt.Printf("nsdp-probe: agent-mac=%s\n", agentMAC)
		}
	} else {
		req := buildRequest(iface.HardwareAddr, agentMAC, seq, attrTags, blockEntries)
		fmt.Printf("nsdp-probe: iface=%s mac=%s seq=%d timeout=%s dest=%s\n",
			iface.Name, iface.HardwareAddr, seq, *timeout, broadcastDest)
		if *verbose {
			fmt.Printf("request (%d bytes):\n%s", len(req), hexDump(req))
		}
	}

	conn, boundAddr, err := listenUDP4(iface, *lportFlag, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nsdp-probe: %v\n", err)
		os.Exit(2)
	}
	defer conn.Close()
	fmt.Printf("listening on %s\n", boundAddr)

	dst, err := net.ResolveUDPAddr("udp4", broadcastDest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nsdp-probe: resolve broadcast address: %v\n", err)
		os.Exit(2)
	}

	if login {
		ok, nextSeq, v, _, _ := runLogin(conn, dst, iface.HardwareAddr, agentMAC, seq, *waitFlag, []byte(*passwordFlag), *verbose)
		if !ok {
			os.Exit(1)
		}
		if setNameMode {
			// -set-name supersedes plain login: continue the logged-in
			// session with the config SET + read-back flow (exits itself).
			// runSetName re-GETs attr 0x17 and re-derives the token
			// immediately before the SET — the switch rolls its nonce
			// after every authenticated SET (ROUND 8, 2026-09-12), so the
			// login SET's token is stale by then. The SET then carries the
			// refreshed AUTH TLV, like every client CMD_SET_REQUEST
			// (nsdp_command_start FUN_00492b80).
			runSetName(conn, dst, iface.HardwareAddr, agentMAC, nextSeq, v, []byte(*passwordFlag), *waitFlag, *setName, *verbose)
		}
		os.Exit(0)
	}

	if sweep != "" {
		items := sweepItems(sweep, sweepAttrTags, sweepBlockIDs)
		values, errs, silent := runSweep(conn, dst, iface.HardwareAddr, agentMAC, seq, *waitFlag, *verbose, items)
		fmt.Printf("sweep done: %d items — %d values, %d errors, %d silent\n", len(items), values, errs, silent)
		if values+errs == 0 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	req := buildRequest(iface.HardwareAddr, agentMAC, seq, attrTags, blockEntries)

	if _, err := conn.WriteTo(req, dst); err != nil {
		fmt.Fprintf(os.Stderr, "nsdp-probe: send request: %v\n", err)
		os.Exit(2)
	}
	// Same sequence is re-sent once: the firmware tolerates <2 retries per
	// sequence (doc §6).
	if *timeout > resendAfter {
		time.AfterFunc(resendAfter, func() {
			if n, err := conn.WriteTo(req, dst); err != nil {
				fmt.Fprintf(os.Stderr, "nsdp-probe: re-send request: %v\n", err)
			} else if *verbose {
				fmt.Printf("re-sent %d bytes after %s\n", n, resendAfter)
			}
		})
	}

	found := collectResponses(conn, *timeout, seq, *verbose)

	fmt.Printf("%d switch(es) found\n", found)
	if found == 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

// runSetName performs the privileged config-SET verification flow on a
// logged-in session (-set-name): read the current system name (GET attr
// 0x03), refresh the auth nonce (GET attr 0x17) and recompute the token,
// then apply the new name via a SET carrying that refreshed AUTH TLV
// followed by the plaintext string TLV 0x0003, then read it back and
// compare.
//
// NONCE REFRESH — the switch rolls its auth nonce after every
// authenticated SET. Live proof (ROUND 8, 2026-09-12, run #5): the login
// SET, whose token came from a fresh GET 0x17, was accepted (status 0x00),
// but the name SET re-carrying that SAME cached token failed with status
// 0x0d / failing tag 0x001A — and the switch's 0x0d reply carried the
// 8-byte token it expected, which decodes as a well-formed V2 token for
// the rolled nonce (~1 in 2^24 coincidence). Every SET must therefore
// carry a token derived from a nonce fetched immediately before it. The
// refresh here runs AFTER the old-name read so the nonce GET is the last
// exchange before the SET; the token is recomputed with the same
// capability branch and password as the login — only the nonce changes.
//
// v and password are the login session's capability word and admin
// password (the runLogin inputs), needed to re-derive the token. seq is
// the next unused sequence counter handed back by runLogin; every request
// — and every GET retry — consumes one (threaded through as *uint32 by
// getLoginAttr). Exits 0 only on a matching read-back, 1 on any failure,
// 2 on socket errors.
func runSetName(conn net.PacketConn, dst net.Addr, mac, agentMAC net.HardwareAddr, seq uint32, v uint32, password []byte, wait time.Duration, newName string, verbose bool) {
	oldName, ok := getLoginAttr(conn, dst, mac, agentMAC, &seq, 0x03, wait, verbose)
	if !ok {
		fmt.Println("set-name failed: could not read the current system name")
		os.Exit(1)
	}
	printSysName("current", oldName)

	// Refresh the auth nonce immediately before the SET: the login SET's
	// token is stale here — the switch rolled its nonce when it accepted
	// the login (ROUND 8 evidence above).
	nonce, ok := getLoginAttr(conn, dst, mac, agentMAC, &seq, 0x17, wait, verbose)
	if !ok {
		fmt.Println("set-name failed: could not refresh the auth nonce")
		os.Exit(1)
	}
	if len(nonce) != 4 {
		fmt.Printf("set-name failed: nonce TLV 0x0017 has %d value bytes, want 4\n", len(nonce))
		os.Exit(1)
	}
	fmt.Printf("nonce refreshed: % x\n", nonce)

	token := loginToken(v, nonce, agentMAC, password)
	authTag := loginTLVTagFor(v)
	fmt.Printf("token refreshed: tag 0x%04x len %d value % x\n", authTag, len(token), token)

	req := buildSetNameRequest(mac, agentMAC, seq, authTag, token, newName)
	if verbose {
		fmt.Printf("SET name request seq=%d (%d bytes):\n%s", seq, len(req), hexDump(req))
	}
	if _, err := conn.WriteTo(req, dst); err != nil {
		fmt.Fprintf(os.Stderr, "nsdp-probe: send SET name: %v\n", err)
		os.Exit(2)
	}
	pkt, src, ok := readLoginReply(conn, "SET name", seq, 0x04, wait, verbose)
	seq++ // the SET name request consumed its sequence
	if !ok {
		fmt.Println("set-name failed: no valid response to SET name")
		os.Exit(1)
	}
	fmt.Printf("SET reply from %s (%d bytes):\n%s", src, len(pkt), hexDump(pkt))
	fmt.Printf("SET reply: cmd byte 0x%02x (want 0x04), status byte 0x%02x (%s)\n", pkt[1], pkt[2], statusName(pkt[2]))
	if status := pkt[2]; status != 0 {
		fmt.Printf("set-name failed: %s: SET name error status 0x%02x (%s)\n", src, status, statusName(status))
		os.Exit(1)
	}
	fmt.Printf("set-name: applied OK (status 0x00 from %s)\n", src)

	gotName, ok := getLoginAttr(conn, dst, mac, agentMAC, &seq, 0x03, wait, verbose)
	if !ok {
		fmt.Println("set-name failed: could not read back the system name")
		os.Exit(1)
	}
	printSysName("read-back", gotName)
	if string(gotName) == newName {
		fmt.Printf("read-back match: system name is now %q\n", newName)
		os.Exit(0)
	}
	fmt.Printf("read-back MISMATCH: got %q, want %q\n", string(gotName), newName)
	os.Exit(1)
}

// printSysName prints a system-name TLV value as a quoted string and hex,
// e.g.: current name: "GS108Ev3" (9 bytes: 47 53 ...).
func printSysName(label string, val []byte) {
	fmt.Printf("%s name: %q (%d bytes: % x)\n", label, string(val), len(val), val)
}

// parseHexList parses a comma-separated list of hex byte values ("01,03,0a"
// or "0x01,0x03,0x0a") into a byte slice. Empty string yields nil (handled
// by callers).
func parseHexList(s, what string) ([]byte, error) {
	parts := strings.Split(s, ",")
	out := make([]byte, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.TrimPrefix(p, "0X")
		p = strings.TrimPrefix(p, "0x")
		var v int
		if _, err := fmt.Sscanf(p, "%x", &v); err != nil || v < 0 || v > 0xff {
			return nil, fmt.Errorf("bad %s %q (want a hex byte like 01 or 0x0a)", what, p)
		}
		out = append(out, byte(v))
	}
	return out, nil
}

// blockEntriesFor turns block IDs into {14,00,00,id} request entries (doc §3).
func blockEntriesFor(ids []byte) [][4]byte {
	out := make([][4]byte, len(ids))
	for i, id := range ids {
		out[i] = [4]byte{0x14, 0x00, 0x00, id}
	}
	return out
}

// pickInterface returns the interface to use: by name when name is non-empty,
// otherwise the non-loopback interface with a hardware address that has the
// lowest index.
func pickInterface(name string) (*net.Interface, error) {
	if name != "" {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", name, err)
		}
		return iface, nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].Index < ifaces[j].Index })
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagLoopback == 0 && len(ifaces[i].HardwareAddr) > 0 {
			return &ifaces[i], nil
		}
	}
	return nil, fmt.Errorf("no non-loopback interface with a hardware address found")
}

// controlSockopts sets SO_REUSEADDR and SO_BROADCAST on the socket before it
// is bound. Uses only syscall constants that exist on both darwin and linux.
func controlSockopts(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		for _, opt := range []int{syscall.SO_REUSEADDR, syscall.SO_BROADCAST} {
			if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, opt, 1); e != nil && serr == nil {
				serr = fmt.Errorf("setsockopt %d: %w", opt, e)
			}
		}
	})
	if err != nil {
		return err
	}
	return serr
}

// listenUDP4 binds the given UDP4 port. It first tries the interface's IPv4
// address and falls back to the wildcard address 0.0.0.0:<port>.
// ListenPacket takes a context.Context but the import set for this tool is
// restricted; a nil context is safe here because the listen address is always
// numeric, so the resolver never dereferences the context.
func listenUDP4(iface *net.Interface, port int, verbose bool) (net.PacketConn, string, error) {
	lc := net.ListenConfig{Control: controlSockopts}
	if addrs, err := iface.Addrs(); err == nil {
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil {
				continue
			}
			addr := fmt.Sprintf("%s:%d", ip4, port)
			conn, err := lc.ListenPacket(nil, "udp4", addr)
			if err == nil {
				return conn, addr, nil
			}
			if verbose {
				fmt.Fprintf(os.Stderr, "nsdp-probe: bind %s failed (%v), falling back to wildcard\n", addr, err)
			}
		}
	}
	addr := fmt.Sprintf(":%d", port) // 0.0.0.0:<port>
	conn, err := lc.ListenPacket(nil, "udp4", addr)
	if err != nil {
		return nil, "", fmt.Errorf("bind %s: %w", addr, err)
	}
	return conn, addr, nil
}

// buildHeader builds the 32-byte NSDP request header (doc §3) followed by the
// 0x00 filler byte at offset 32. agentMAC nil means broadcast (all-zero
// Agent ID).
func buildHeader(mac, agentMAC net.HardwareAddr, seq uint32) []byte {
	req := make([]byte, 0, 92)
	req = append(req,
		0x01,       // version (0)
		0x01,       // command: GET (1) — this tool never sends SET (3)
		0x00, 0x00, // status, reserved (2-3)
		0x00, 0x00, // failure TLV (4-5)
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
	req = append(req, seqb[:]...) // sequence (20-23)
	req = append(req, "NSDP"...)  // magic (24-27)
	req = append(req, 0, 0, 0, 0) // reserved (28-31)
	req = append(req, 0)          // filler (32)
	return req
}

// buildRequest builds an NSDP v2 GET request: header, filler byte, header-attr
// entries {tag,00,00,00}, block entries, terminator (doc §3, Appendix B).
// With the default tag/block lists this is the exact 92-byte discovery request.
func buildRequest(mac, agentMAC net.HardwareAddr, seq uint32, attrTags []byte, blockEntries [][4]byte) []byte {
	req := buildHeader(mac, agentMAC, seq)
	for _, tag := range attrTags {
		req = append(req, tag, 0x00, 0x00, 0x00) // header attribute entries
	}
	for _, e := range blockEntries {
		req = append(req, e[0], e[1], e[2], e[3]) // block read entries (verbatim)
	}
	req = append(req, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00) // terminator
	return req
}

// buildSweepRequest builds a single-item probe request: 32-byte header,
// filler byte, one 4-byte entry, terminator = 44 bytes.
func buildSweepRequest(mac, agentMAC net.HardwareAddr, seq uint32, entry [4]byte) []byte {
	req := buildHeader(mac, agentMAC, seq)
	req = append(req, entry[0], entry[1], entry[2], entry[3])
	req = append(req, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00) // terminator
	return req
}

type tlv struct {
	tag uint16
	val []byte
}

// checkResponseHeader validates the NSDP response header fields shared by all
// GET responses (doc §4): minimum length, magic "NSDP" at offset 24, and
// command byte 2 (request command 1 + 1). It returns a drop reason for
// verbose logging when ok is false.
func checkResponseHeader(pkt []byte) (string, bool) {
	if len(pkt) < 32 {
		return fmt.Sprintf("short packet (%d bytes)", len(pkt)), false
	}
	if string(pkt[24:28]) != "NSDP" {
		return fmt.Sprintf("bad magic % x", pkt[24:28]), false
	}
	if pkt[1] != 0x02 {
		return fmt.Sprintf("command byte 0x%02x != 0x02", pkt[1]), false
	}
	return "", true
}

// walkTLVs walks response TLVs starting at offset 32 (doc §4):
// [tag: 2 bytes BE][len: 2 bytes BE][value: len bytes], stopping at the
// 0xFFFF terminator tag. Values reference pkt.
func walkTLVs(pkt []byte) ([]tlv, bool) {
	var out []tlv
	off := 32
	for off+4 <= len(pkt) {
		tag := binary.BigEndian.Uint16(pkt[off : off+2])
		if tag == 0xFFFF { // terminator FF FF 00 00
			break
		}
		length := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if off+4+length > len(pkt) {
			return out, true // truncated mid-TLV
		}
		out = append(out, tlv{tag, pkt[off+4 : off+4+length]})
		off += 4 + length
	}
	return out, false
}

// collectResponses reads packets from conn until the timeout expires and
// prints every discovered switch. Returns the number of unique switches found.
func collectResponses(conn net.PacketConn, timeout time.Duration, wantSeq uint32, verbose bool) int {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		fmt.Fprintf(os.Stderr, "nsdp-probe: set read deadline: %v\n", err)
		os.Exit(2)
	}

	type switchInfo struct {
		srcIP    string
		mac      string
		model    string
		name     string
		ipTag    string
		fw1      string
		fw2      string
		active   int
		serial   string
		extraTLV []tlv
	}

	seen := make(map[string]bool)
	var order []string

	buf := make([]byte, 4096)
	for {
		n, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			fmt.Fprintf(os.Stderr, "nsdp-probe: read: %v\n", err)
			os.Exit(2)
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		srcIP := ""
		if ua, ok := raddr.(*net.UDPAddr); ok {
			srcIP = ua.IP.String()
		} else {
			srcIP = raddr.String()
		}

		// Header validation (doc §4).
		if reason, ok := checkResponseHeader(pkt); !ok {
			if verbose {
				fmt.Fprintf(os.Stderr, "drop packet from %s: %s\n", srcIP, reason)
			}
			continue
		}
		if gotSeq := binary.BigEndian.Uint32(pkt[20:24]); gotSeq != wantSeq {
			fmt.Fprintf(os.Stderr, "warning: %s echoed sequence %d, expected %d\n", srcIP, gotSeq, wantSeq)
		}
		if status := pkt[2]; status != 0 {
			failTag := binary.BigEndian.Uint16(pkt[4:6])
			fmt.Printf("%s: NSDP error status 0x%02x (%s)", srcIP, status, statusName(status))
			if failTag != 0 {
				fmt.Printf(", failing tag 0x%04x", failTag)
			}
			fmt.Println()
			continue
		}

		// Walk TLVs from offset 32 (doc §4).
		info := &switchInfo{srcIP: srcIP, mac: strings.ToLower(net.HardwareAddr(pkt[14:20]).String())}
		tlvs, truncated := walkTLVs(pkt)
		if truncated && verbose {
			fmt.Fprintf(os.Stderr, "warning: %s: TLV walk truncated\n", srcIP)
		}
		var others []tlv
		for _, t := range tlvs {
			switch t.tag {
			case 0x0004: // MAC address
				if len(t.val) >= 6 {
					info.mac = net.HardwareAddr(t.val[:6]).String()
				}
			case 0x0001: // model
				info.model = asciiTrim(t.val)
			case 0x0003: // device name
				info.name = asciiTrim(t.val)
			case 0x0007: // IP address
				if len(t.val) >= 4 {
					info.ipTag = net.IP(t.val[:4]).String()
				}
			case 0x000d: // firmware image 1
				info.fw1 = asciiTrim(t.val)
			case 0x000e: // firmware image 2
				info.fw2 = asciiTrim(t.val)
			case 0x000f: // active image: low nibble = image number
				if len(t.val) >= 1 {
					info.active = int(t.val[0] & 0x0f)
				}
			case 0x7800: // serial number block
				info.serial = asciiTrim(t.val)
			default:
				others = append(others, t)
			}
		}

		key := srcIP + "|" + info.mac
		if seen[key] {
			if verbose {
				fmt.Fprintf(os.Stderr, "duplicate response from %s (%s), ignoring\n", srcIP, info.mac)
			}
			continue
		}
		seen[key] = true
		order = append(order, key)
		if verbose {
			info.extraTLV = others
		}

		idx := len(order)
		fmt.Printf("switch #%d:\n", idx)
		fmt.Printf("  source IP : %s\n", info.srcIP)
		fmt.Printf("  MAC       : %s\n", info.mac)
		fmt.Printf("  model     : %s\n", info.model)
		fmt.Printf("  name      : %s\n", info.name)
		if info.ipTag != "" {
			note := ""
			if info.ipTag != info.srcIP {
				note = "  (differs from response source!)"
			}
			fmt.Printf("  IP        : %s%s\n", info.ipTag, note)
		}
		fmt.Printf("  fw1       : %s\n", info.fw1)
		fmt.Printf("  fw2       : %s\n", info.fw2)
		fmt.Printf("  active img: %d\n", info.active)
		fmt.Printf("  serial    : %s\n", info.serial)
		if verbose {
			for _, t := range info.extraTLV {
				fmt.Printf("  tlv 0x%04x len %d:\n%s", t.tag, len(t.val), hexDump(t.val))
			}
		}
	}
	return len(order)
}

// sweep outcome categories.
const (
	outSilent = iota
	outValue
	outError
)

type sweepItem struct {
	label string // e.g. "tag 0x0002" or "block 0x7400"
	entry [4]byte
}

// sweepItems builds the per-request item list for a sweep: attr tags become
// {tag,00,00,00} entries, block IDs become {14,00,00,id} entries with the
// {id,0} response tag form used as label.
func sweepItems(mode string, attrTags, blockIDs []byte) []sweepItem {
	var items []sweepItem
	switch mode {
	case "attrs":
		for _, tag := range attrTags {
			items = append(items, sweepItem{
				label: fmt.Sprintf("tag 0x%04x", tag),
				entry: [4]byte{tag, 0x00, 0x00, 0x00},
			})
		}
	case "blocks":
		for _, id := range blockIDs {
			items = append(items, sweepItem{
				label: fmt.Sprintf("block 0x%04x", uint16(id)<<8),
				entry: [4]byte{0x14, 0x00, 0x00, id},
			})
		}
	}
	return items
}

// runSweep probes each item with a dedicated request and a fresh sequence
// (base + item index, doc §6 anti-replay: repeated sequences are dropped).
// Returns the outcome counts.
func runSweep(conn net.PacketConn, dst net.Addr, mac, agentMAC net.HardwareAddr, baseSeq uint32, wait time.Duration, verbose bool, items []sweepItem) (values, errs, silent int) {
	for i, it := range items {
		itemSeq := baseSeq + uint32(i)
		req := buildSweepRequest(mac, agentMAC, itemSeq, it.entry)
		if verbose {
			fmt.Printf("request %s seq=%d (%d bytes):\n%s", it.label, itemSeq, len(req), hexDump(req))
		}
		if _, err := conn.WriteTo(req, dst); err != nil {
			fmt.Fprintf(os.Stderr, "nsdp-probe: send %s: %v\n", it.label, err)
			os.Exit(2)
		}
		outcome, lines := awaitSweepResponse(conn, it.label, itemSeq, wait, verbose)
		for _, l := range lines {
			fmt.Println(l)
		}
		switch outcome {
		case outValue:
			values++
		case outError:
			errs++
		default:
			silent++
		}
	}
	return values, errs, silent
}

// awaitSweepResponse waits up to wait for one valid response to the current
// sweep item (echoed sequence must equal the item's sequence). Packets with
// a stale sequence or bad header are dropped and the window keeps running.
func awaitSweepResponse(conn net.PacketConn, label string, wantSeq uint32, wait time.Duration, verbose bool) (int, []string) {
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		fmt.Fprintf(os.Stderr, "nsdp-probe: set read deadline: %v\n", err)
		os.Exit(2)
	}
	buf := make([]byte, 4096)
	for {
		n, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return outSilent, []string{label + " -> no response"}
			}
			fmt.Fprintf(os.Stderr, "nsdp-probe: read: %v\n", err)
			os.Exit(2)
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		srcIP := ""
		if ua, ok := raddr.(*net.UDPAddr); ok {
			srcIP = ua.IP.String()
		}
		if reason, ok := checkResponseHeader(pkt); !ok {
			if verbose {
				fmt.Fprintf(os.Stderr, "drop packet from %s: %s\n", srcIP, reason)
			}
			continue
		}
		if gotSeq := binary.BigEndian.Uint32(pkt[20:24]); gotSeq != wantSeq {
			if verbose {
				fmt.Fprintf(os.Stderr, "drop packet from %s: stale sequence %d (want %d for %s)\n", srcIP, gotSeq, wantSeq, label)
			}
			continue
		}
		if status := pkt[2]; status != 0 {
			line := fmt.Sprintf("%s -> error status 0x%02x (%s)", label, status, statusName(status))
			if failTag := binary.BigEndian.Uint16(pkt[4:6]); failTag != 0 {
				line += fmt.Sprintf(", failing tag 0x%04x", failTag)
			}
			return outError, []string{line}
		}
		tlvs, truncated := walkTLVs(pkt)
		if truncated && verbose {
			fmt.Fprintf(os.Stderr, "warning: %s: TLV walk truncated\n", label)
		}
		if len(tlvs) == 0 {
			return outValue, []string{label + " -> ok, no TLVs"}
		}
		lines := make([]string, len(tlvs))
		for i, t := range tlvs {
			lines[i] = tlvLine(label, t)
		}
		return outValue, lines
	}
}

// tlvLine renders one sweep result line, e.g.
//
//	tag 0x0002 -> len 4: 00 01 02 03  | ascii ".."
func tlvLine(label string, t tlv) string {
	hexParts := make([]string, len(t.val))
	for i, c := range t.val {
		hexParts[i] = fmt.Sprintf("%02x", c)
	}
	line := fmt.Sprintf("%s -> len %d: %s", label, len(t.val), strings.Join(hexParts, " "))
	if len(t.val) > 0 {
		if s, ok := printableASCII(t.val); ok {
			line += fmt.Sprintf(" | ascii %q", s)
		}
	}
	return line
}

// printableASCII reports whether every byte is printable ASCII (0x20..0x7e)
// and returns the string if so.
func printableASCII(b []byte) (string, bool) {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return string(b), true
}

// asciiTrim returns value as an ASCII string with trailing NUL/0xFF padding
// (and surrounding whitespace) removed.
func asciiTrim(b []byte) string {
	return strings.TrimSpace(strings.TrimRight(string(b), "\x00\xff"))
}

// hexDump renders a classic offset-annotated hex dump.
func hexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		fmt.Fprintf(&sb, "  %04x  ", i)
		for j := i; j < end; j++ {
			fmt.Fprintf(&sb, "%02x ", b[j])
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}
