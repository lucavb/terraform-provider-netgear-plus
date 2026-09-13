package nsdp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	// v2 port pair: the client binds 63321 and broadcasts to the switch
	// port 63322. (The legacy v1 pair is 63323/63324.)
	clientPort    = 63321
	serverPort    = 63322
	broadcastDest = "255.255.255.255:63322"

	// defaultWait is the client-faithful per-request response window.
	defaultWait = 800 * time.Millisecond

	// Login handshake GET attr tags: 0x14 capability word (BE32), 0x17
	// nonce (4 raw bytes), 0x03 system name (ASCII).
	attrCapability = 0x14
	attrNonce      = 0x17
	attrSystemName = 0x03

	// Client-faithful retry counts (nsdpmanager.exe nsdp_command_start,
	// FUN_00492b80): GET attr 0x14 → 5 attempts, other GETs → 14; each
	// attempt consumes a FRESH sequence number (the switch anti-replay
	// drops recycled sequences).
	capabilityAttempts = 5
	defaultAttempts    = 14

	// Session base sequence: random in [1000, 9999) at client
	// construction. The NETGEAR client picks a random base per session
	// (rand()%1000 + offset); fresh high sequences stay outside the
	// switch's anti-replay window — live-confirmed 2026-09-12, when
	// re-using base 258 for the third time went silent.
	seqBaseMin  = 1000
	seqBaseSpan = 8999
)

// Options configures NewClient.
type Options struct {
	// IfaceName selects the network interface whose hardware MAC becomes
	// the NSDP manager ID. Empty = first non-loopback interface with a
	// hardware address, lowest index.
	IfaceName string
	// AgentMAC is the target switch MAC ("8c:3b:ad:25:1b:88"). Empty means
	// broadcast GETs; login and SETs require it (the login token is
	// derived from the switch MAC).
	AgentMAC string
	// Password is the switch admin password, used by Login.
	Password []byte
	// Dest optionally targets a UNICAST NSDP destination instead of the
	// default limited-broadcast, so NSDP can cross routed subnets toward
	// the switch's routable IP. Empty = default limited-broadcast
	// 255.255.255.255:63322 (behavior unchanged); non-empty = "host" or
	// "host:port", with the port defaulting to 63322. The address must
	// resolve as udp4. (Whether a given firmware accepts unicast NSDP is
	// a device property; this option only sets the destination.)
	Dest string
	// Wait is the per-request response window. Zero = the 800ms default.
	Wait time.Duration
	// Verbose, when non-nil, receives the exchange log: retry notices,
	// dropped packets, request bytes, and the login capability/nonce/
	// token summary.
	Verbose io.Writer
}

// Client is an NSDP v2 UDP client bound to the v2 client port, broadcasting
// requests to the v2 switch port. Login performs the 3-exchange NSDP LOGIN
// handshake and caches the capability word and the derived auth token;
// every subsequent SET attaches that token as the auth TLV
// (nsdp_command_start). A Client is not safe for concurrent use.
type Client struct {
	conn     net.PacketConn
	dst      net.Addr
	iface    *net.Interface
	mac      net.HardwareAddr
	agentMAC net.HardwareAddr
	password []byte
	wait     time.Duration
	verbose  io.Writer

	seq uint32 // next sequence number to hand out

	capability uint32 // capability word V from the last successful Login
	token      []byte // auth TLV value from the last successful Login
	loggedIn   bool
}

// NewClient resolves the local interface (and with it the manager MAC),
// binds the local v2 client port (63321) and prepares the broadcast
// destination, then hands off to the shared construction core
// (newClientOver, also the base of NewClientWithConn). No traffic is sent
// until a request method is called.
func NewClient(opts Options) (*Client, error) {
	iface, err := pickInterface(opts.IfaceName)
	if err != nil {
		return nil, fmt.Errorf("nsdp: %w", err)
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("nsdp: interface %q has no usable 6-byte hardware address", iface.Name)
	}
	var agentMAC net.HardwareAddr
	if opts.AgentMAC != "" {
		if agentMAC, err = net.ParseMAC(opts.AgentMAC); err != nil {
			return nil, fmt.Errorf("nsdp: agent-mac %q: %w", opts.AgentMAC, err)
		}
	}
	conn, _, err := listenUDP4(iface, clientPort)
	if err != nil {
		return nil, fmt.Errorf("nsdp: %w", err)
	}
	dst, err := resolveDest(opts.Dest)
	if err != nil {
		conn.Close()
		return nil, err
	}
	c := newClientOver(conn, iface.HardwareAddr, agentMAC, dst, opts.Password, opts.Wait, opts.Verbose)
	c.iface = iface
	return c, nil
}

// resolveDest resolves the Options.Dest destination into a udp4 address:
// empty → the default limited-broadcast 255.255.255.255:63322, byte-for-byte
// today's behavior; a bare host → host:63322; host:port → as given. The
// result must resolve as udp4.
func resolveDest(dest string) (net.Addr, error) {
	if dest == "" {
		dst, err := net.ResolveUDPAddr("udp4", broadcastDest)
		if err != nil {
			return nil, fmt.Errorf("nsdp: resolve %s: %w", broadcastDest, err)
		}
		return dst, nil
	}
	if _, _, err := net.SplitHostPort(dest); err != nil {
		dest = net.JoinHostPort(dest, "63322")
	}
	dst, err := net.ResolveUDPAddr("udp4", dest)
	if err != nil {
		return nil, fmt.Errorf("nsdp: resolve destination %q: %w", dest, err)
	}
	return dst, nil
}

// NewClientWithConn returns a Client running over an injected connection
// instead of a bound broadcast socket — the test seam the nsdptest fake
// agent builds on. peer is the destination address every request is
// written to (e.g. a loopback UDP listener's Addr); agentMAC is the target
// switch MAC (nil = broadcast GETs; Login and SETs require it, the login
// token is derived from it); password is the switch admin password Login
// derives its token from. An injected conn carries no interface to take a
// manager MAC from, so a random locally administered unicast address is
// generated. The per-request response window is the 800ms default. The
// returned Client owns conn: Close closes it.
func NewClientWithConn(conn net.PacketConn, agentMAC net.HardwareAddr, peer net.Addr, password string) (*Client, error) {
	if conn == nil {
		return nil, errors.New("nsdp: NewClientWithConn: nil connection")
	}
	if peer == nil {
		return nil, errors.New("nsdp: NewClientWithConn: nil peer address")
	}
	return newClientOver(conn, randomManagerMAC(), agentMAC, peer, []byte(password), 0, nil), nil
}

// newClientOver is the shared construction core of NewClient and
// NewClientWithConn: it assembles the Client around an already-bound
// connection and destination address. agentMAC nil or any length other
// than 6 means broadcast (an all-zero Agent ID). No traffic is sent here.
func newClientOver(conn net.PacketConn, mac, agentMAC net.HardwareAddr, dst net.Addr, password []byte, wait time.Duration, verbose io.Writer) *Client {
	if wait <= 0 {
		wait = defaultWait
	}
	if len(agentMAC) == 6 {
		agentMAC = append(net.HardwareAddr(nil), agentMAC...)
	} else {
		agentMAC = nil
	}
	return &Client{
		conn:     conn,
		dst:      dst,
		mac:      append(net.HardwareAddr(nil), mac...),
		agentMAC: agentMAC,
		password: append([]byte(nil), password...),
		wait:     wait,
		verbose:  verbose,
		seq:      uint32(seqBaseMin + rand.IntN(seqBaseSpan)),
	}
}

// randomManagerMAC generates a random locally administered unicast MAC —
// the manager ID for clients running over an injected connection, where
// no interface hardware address exists to derive one from.
func randomManagerMAC() net.HardwareAddr {
	mac := make(net.HardwareAddr, 6)
	for i := range mac {
		mac[i] = byte(rand.IntN(256))
	}
	mac[0] = mac[0]&^0x01 | 0x02 // clear multicast bit, set locally administered
	return mac
}

// Close closes the underlying socket and marks the session logged out.
func (c *Client) Close() error {
	c.loggedIn = false
	return c.conn.Close()
}

// Login performs the NSDP LOGIN handshake against the agent MAC:
//
//  1. GET attr 0x14 → capability word V (BE32)
//  2. GET attr 0x17 → nonce (4 raw bytes)
//  3. SET the capability-selected password/auth TLV (tag 0x001A + 8-byte
//     V2 token when V&0x10, tag 0x0018 + 4-byte V1 token when V&0x08,
//     tag 0x000A + plaintext otherwise; the password is NtgrRock-XORed
//     first when V&0x01) → reply cmd 0x04, status 0x00 = accepted
//
// On success the capability word and the derived token are cached; every
// later SET attaches the token as its auth TLV. Both GET legs retry with
// client-faithful counts (5 for attr 0x14, 14 for 0x17), each attempt with
// a fresh sequence number; the login SET is sent once.
//
// WARNING: 3 failed logins lock ALL SET operations on the switch for
// ~30 minutes (see errors.go).
func (c *Client) Login() error {
	if c.agentMAC == nil {
		return errors.New("nsdp: login requires the switch (agent) MAC: the login token is derived from it")
	}
	capVal, err := c.GetAttr(attrCapability)
	if err != nil {
		return fmt.Errorf("login: get capability (attr 0x14): %w", err)
	}
	if len(capVal) != 4 {
		return &ErrMalformed{Reason: fmt.Sprintf("capability TLV 0x0014 has %d value bytes, want 4", len(capVal))}
	}
	v := uint32(capVal[0])<<24 | uint32(capVal[1])<<16 | uint32(capVal[2])<<8 | uint32(capVal[3])
	if c.verbose != nil {
		fmt.Fprintf(c.verbose, "capability: % x (V=0x%08x; %s)\n", capVal, v, capabilityBits(v))
	}

	nonce, err := c.GetAttr(attrNonce)
	if err != nil {
		return fmt.Errorf("login: get nonce (attr 0x17): %w", err)
	}
	if len(nonce) != 4 {
		return &ErrMalformed{Reason: fmt.Sprintf("nonce TLV 0x0017 has %d value bytes, want 4", len(nonce))}
	}

	// Derive and cache the auth token: every CMD_SET_REQUEST on this
	// session must attach it (nsdp_command_start), so keep the token
	// bound to THIS login's nonce.
	token := loginToken(v, nonce, c.agentMAC, c.password)
	tag := loginTagFor(v)
	if c.verbose != nil {
		fmt.Fprintf(c.verbose, "nonce: % x\n", nonce)
		fmt.Fprintf(c.verbose, "token: tag 0x%04x len %d value % x\n", tag, len(token), token)
	}

	seq := c.nextSeq()
	req := EncodeSetLoginRequest(c.mac, c.agentMAC, seq, v, nonce, c.password)
	if c.verbose != nil {
		fmt.Fprintf(c.verbose, "SET login request seq=%d (%d bytes):\n%s", seq, len(req), hexDump(req))
	}
	if err := c.send(req); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if _, err := c.readReply(seq, cmdSetReply, "SET login"); err != nil {
		if errors.Is(err, ErrNoReply) {
			return fmt.Errorf("login: no response to SET login request: %w", err)
		}
		return fmt.Errorf("login rejected: %w", err)
	}
	c.capability = v
	c.token = append([]byte(nil), token...)
	c.loggedIn = true
	return nil
}

// GetAttr performs a single-tag GET exchange for attr tag and returns the
// matching reply TLV value. Retries are client-faithful: 5 attempts for
// tag 0x14, 14 otherwise, each attempt with a fresh sequence number.
// ErrNoReply (wrapped) is returned when all attempts go unanswered.
func (c *Client) GetAttr(tag byte) ([]byte, error) {
	attempts := defaultAttempts
	if tag == attrCapability {
		attempts = capabilityAttempts
	}
	for i := 1; ; i++ {
		seq := c.nextSeq()
		req := EncodeGetRequest(c.mac, c.agentMAC, seq, tag)
		if c.verbose != nil {
			fmt.Fprintf(c.verbose, "GET attr 0x%02x seq=%d request (%d bytes):\n%s", tag, seq, len(req), hexDump(req))
		}
		if err := c.send(req); err != nil {
			return nil, fmt.Errorf("GET attr 0x%02x: %w", tag, err)
		}
		reply, err := c.readReply(seq, cmdGetReply, fmt.Sprintf("GET attr 0x%02x", tag))
		if err != nil {
			if !errors.Is(err, ErrNoReply) {
				return nil, fmt.Errorf("GET attr 0x%02x: %w", tag, err)
			}
			if i >= attempts {
				break
			}
			if c.verbose != nil {
				fmt.Fprintf(c.verbose, "GET attr 0x%02x: no response (attempt %d/%d), retrying\n", tag, i, attempts)
			}
			continue
		}
		for _, t := range reply.TLVs {
			if t.Tag == uint16(tag) {
				return t.Value, nil
			}
		}
		return nil, fmt.Errorf("GET attr 0x%02x: %w", tag, &ErrMalformed{Reason: fmt.Sprintf("reply carries no TLV 0x%04x", tag)})
	}
	return nil, fmt.Errorf("GET attr 0x%02x: no valid response after %d attempts: %w", tag, attempts, ErrNoReply)
}

// GetAttrs performs ONE multi-tag GET request for all tags and returns the
// requested tags the switch answered with, keyed by attr tag byte. Tags
// the reply omits are simply absent from the map — callers must check
// presence. If no requested tag is answered, *ErrMalformed is returned.
// The request is retried like other GETs (up to 14 attempts, fresh
// sequence each).
func (c *Client) GetAttrs(tags ...byte) (map[byte][]byte, error) {
	if len(tags) == 0 {
		return nil, errors.New("nsdp: GetAttrs requires at least one tag")
	}
	want := make(map[uint16]bool, len(tags))
	for _, tag := range tags {
		want[uint16(tag)] = true
	}
	for i := 1; ; i++ {
		seq := c.nextSeq()
		req := EncodeGetRequest(c.mac, c.agentMAC, seq, tags...)
		if c.verbose != nil {
			fmt.Fprintf(c.verbose, "GET attrs % x seq=%d request (%d bytes):\n%s", tags, seq, len(req), hexDump(req))
		}
		if err := c.send(req); err != nil {
			return nil, fmt.Errorf("GET attrs: %w", err)
		}
		reply, err := c.readReply(seq, cmdGetReply, "GET attrs")
		if err != nil {
			if !errors.Is(err, ErrNoReply) {
				return nil, fmt.Errorf("GET attrs: %w", err)
			}
			if i >= defaultAttempts {
				break
			}
			if c.verbose != nil {
				fmt.Fprintf(c.verbose, "GET attrs % x: no response (attempt %d/%d), retrying\n", tags, i, defaultAttempts)
			}
			continue
		}
		m := make(map[byte][]byte, len(tags))
		for _, t := range reply.TLVs {
			if want[t.Tag] {
				m[byte(t.Tag)] = t.Value
			}
		}
		if len(m) == 0 {
			return nil, fmt.Errorf("GET attrs: %w", &ErrMalformed{Reason: fmt.Sprintf("reply carries none of the requested TLVs % x", tags)})
		}
		return m, nil
	}
	return nil, fmt.Errorf("GET attrs % x: no valid response after %d attempts: %w", tags, defaultAttempts, ErrNoReply)
}

// GetSystemName reads the switch system name (GET attr 0x03, ASCII with
// trailing NUL/0xFF padding trimmed). No login required.
func (c *Client) GetSystemName() (string, error) {
	val, err := c.GetAttr(attrSystemName)
	if err != nil {
		return "", fmt.Errorf("get system name: %w", err)
	}
	return asciiTrim(val), nil
}

// refreshToken re-GETs the auth nonce (attr 0x17, the 14-attempt GET
// policy) and recomputes the cached auth token from it.
//
// The switch ROLLS its auth nonce after every authenticated SET —
// live-proven ROUND 8 (2026-09-12): a second SET carrying the login-time
// token failed with status 0x0d, failing tag 0x001A, and a {BE16 len,
// expected-token} mismatch payload whose XOR-delta vs the sent token
// matches the V2 token formula for a rolled nonce. Every authenticated
// SET therefore refreshes immediately before building its frame. Login's
// own fetch-nonce-then-SET-immediately chain already complies and is left
// untouched. A rejected SET costs no login-lockout strike, but repeated
// 0x0d auth mismatches count like failed logins against the 3-strike
// ~30-minute SET lockout — all the more reason to never send a stale
// token.
func (c *Client) refreshToken() error {
	nonce, err := c.GetAttr(attrNonce)
	if err != nil {
		return fmt.Errorf("refresh auth nonce: %w", err)
	}
	if len(nonce) != 4 {
		return &ErrMalformed{Reason: fmt.Sprintf("nonce TLV 0x0017 has %d value bytes, want 4", len(nonce))}
	}
	c.token = loginToken(c.capability, nonce, c.agentMAC, c.password)
	if c.verbose != nil {
		fmt.Fprintf(c.verbose, "nonce refreshed: % x\n", nonce)
		fmt.Fprintf(c.verbose, "token refreshed: % x\n", c.token)
	}
	return nil
}

// SetSystemName SETs the switch system name as a plaintext string TLV
// {0x0003, len, name}. It logs in first when the session is not yet
// authenticated, refreshes the auth token (the switch rolls its nonce
// after every authenticated SET, ROUND 8), and attaches the refreshed
// token as the auth TLV before the name TLV, as every CMD_SET_REQUEST
// must (nsdp_command_start). Like the NETGEAR client, the SET itself is
// sent once (no retries).
//
// WARNING: 3 failed logins lock ALL SET operations for ~30 minutes.
func (c *Client) SetSystemName(name string) error {
	if !c.loggedIn {
		if err := c.Login(); err != nil {
			return err
		}
	}
	if err := c.refreshToken(); err != nil {
		return fmt.Errorf("set system name: %w", err)
	}
	seq := c.nextSeq()
	req := EncodeSetNameRequest(c.mac, c.agentMAC, seq, c.capability, c.token, name)
	if c.verbose != nil {
		fmt.Fprintf(c.verbose, "SET name request seq=%d (%d bytes):\n%s", seq, len(req), hexDump(req))
	}
	if err := c.send(req); err != nil {
		return fmt.Errorf("set system name: %w", err)
	}
	if _, err := c.readReply(seq, cmdSetReply, "SET system name"); err != nil {
		if errors.Is(err, ErrNoReply) {
			return fmt.Errorf("set system name: no response to SET request: %w", err)
		}
		return fmt.Errorf("set system name rejected: %w", err)
	}
	return nil
}

// SetRaw writes ONE raw TLV value: the session auth TLV followed by the
// user TLV, exactly like every CMD_SET_REQUEST (nsdp_command_start). It
// logs in first when the session is not yet authenticated, and refreshes
// the auth token right before building the frame (the switch rolls its
// nonce after every authenticated SET, ROUND 8 — the cached login token
// would be rejected with status 0x0d / failing tag 0x001A). The SET
// itself is sent once, like the NETGEAR client.
//
// This is the live-lab escape hatch for layouts whose wire form is not yet
// verified (e.g. 0x8800 LA-group entries, or the per-port 0x2800 802.1Q
// forms still under investigation) — the
// ONLY raw write the client offers. WARNING: callers must print a warning
// before using it: wrong bytes can misconfigure a real switch.
func (c *Client) SetRaw(tag uint16, value []byte) error {
	if !c.loggedIn {
		if err := c.Login(); err != nil {
			return err
		}
	}
	if err := c.refreshToken(); err != nil {
		return fmt.Errorf("set raw tag 0x%04x: %w", tag, err)
	}
	seq := c.nextSeq()
	req := encodeSetTLVs(c.mac, c.agentMAC, seq,
		TLV{Tag: loginTagFor(c.capability), Value: c.token},
		TLV{Tag: tag, Value: append([]byte(nil), value...)})
	if c.verbose != nil {
		fmt.Fprintf(c.verbose, "SET raw tag 0x%04x request seq=%d (%d bytes):\n%s", tag, seq, len(req), hexDump(req))
	}
	if err := c.send(req); err != nil {
		return fmt.Errorf("set raw tag 0x%04x: %w", tag, err)
	}
	if _, err := c.readReply(seq, cmdSetReply, fmt.Sprintf("SET raw tag 0x%04x", tag)); err != nil {
		if errors.Is(err, ErrNoReply) {
			return fmt.Errorf("set raw tag 0x%04x: no response to SET request: %w", tag, err)
		}
		return fmt.Errorf("set raw tag 0x%04x rejected: %w", tag, err)
	}
	return nil
}

// nextSeq hands out the next sequence number. Every request consumes one,
// including each retry attempt — the switch anti-replay drops recycled
// sequences (live-confirmed).
func (c *Client) nextSeq() uint32 {
	s := c.seq
	c.seq++
	return s
}

// send writes one request to the broadcast destination.
func (c *Client) send(req []byte) error {
	if _, err := c.conn.WriteTo(req, c.dst); err != nil {
		return fmt.Errorf("send %d bytes: %w", len(req), err)
	}
	return nil
}

// readReply waits up to c.wait for a packet that matches the current
// exchange (expected echo command, sequence and MAC echoes), dropping
// non-matching packets until the window expires. Errors other than reply
// validation abort immediately; a window that expires with no matching
// reply yields ErrNoReply. On a reply carrying an error status, the
// returned *ErrStatus gets source as its Source.
func (c *Client) readReply(wantSeq uint32, expectCmd byte, source string) (*Reply, error) {
	if err := c.conn.SetReadDeadline(time.Now().Add(c.wait)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	buf := make([]byte, 4096)
	for {
		n, _, err := c.conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil, ErrNoReply
			}
			return nil, fmt.Errorf("read: %w", err)
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		reply, err := ParseReply(pkt, expectCmd, wantSeq, c.mac, c.agentMAC)
		if err != nil {
			var es *ErrStatus
			if errors.As(err, &es) {
				if es.Source == "" {
					es.Source = source
				}
				return reply, err
			}
			if c.verbose != nil {
				fmt.Fprintf(c.verbose, "nsdp: drop packet: %v\n", err)
			}
			continue
		}
		if reply.Truncated && c.verbose != nil {
			fmt.Fprintf(c.verbose, "nsdp: reply TLV region truncated mid-TLV; accepting %d TLV(s)\n", len(reply.TLVs))
		}
		return reply, nil
	}
}

// pickInterface returns the interface to use: by name when name is
// non-empty, otherwise the non-loopback interface with a hardware address
// that has the lowest index.
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
	return nil, errors.New("no non-loopback interface with a hardware address found")
}

// controlSockopts sets SO_REUSEADDR and SO_BROADCAST on the socket before
// it is bound. Uses only syscall constants that exist on both darwin and
// linux.
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

// listenUDP4 binds the given UDP4 port, trying the interface's IPv4 address
// first and falling back to the wildcard address 0.0.0.0:<port>.
func listenUDP4(iface *net.Interface, port int) (net.PacketConn, string, error) {
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
			conn, err := lc.ListenPacket(context.Background(), "udp4", addr)
			if err == nil {
				return conn, addr, nil
			}
		}
	}
	addr := fmt.Sprintf(":%d", port) // 0.0.0.0:<port>
	conn, err := lc.ListenPacket(context.Background(), "udp4", addr)
	if err != nil {
		return nil, "", fmt.Errorf("bind %s: %w", addr, err)
	}
	return conn, addr, nil
}

// capabilityBits renders the capability word V decoded into its known
// login branches.
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

// asciiTrim returns value as an ASCII string with trailing NUL/0xFF
// padding (and surrounding whitespace) removed.
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
