// Package nsdptest provides a fake NETGEAR Plus switch (GS108Ev3) agent
// speaking the NSDP v2 protocol over loopback UDP — the test double for
// exercising nsdp clients (login handshake, block GETs, authenticated
// SETs) without a physical switch.
//
// The fake mirrors the live-proven GS108Ev3 behaviors the nsdp package
// documents:
//
//   - the login handshake: GET attr 0x14 → capability {00 00 00 10},
//     GET attr 0x17 → a fresh 4-byte nonce, SET tag 0x001A → the 8-byte
//     V2 token verified with the REAL nsdp.V2LoginToken math over the
//     fake's own nonce, MAC and password; wrong tokens get the
//     auth-mismatch reply (status 0x0d, failing tag 0x001A, {BE16 len,
//     expected-token} payload)
//   - the nonce ROLL after every successful authenticated SET (the
//     client-faithful refreshToken discipline depends on it)
//   - block GETs served from scripted mutable state seeded with
//     factory-fresh values; authenticated SETs applied in the switch's
//     accepted wire forms
//
// Scenario knobs on FakeAgent reproduce the live quirks: SET reply loss,
// silent SET no-ops, and login rejection.
package nsdptest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"testing"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// Wire constants mirrored from the nsdp package (unexported there): the
// protocol version, the request command bytes and the 32-byte header
// length.
const (
	protoVersion = 0x01
	cmdGet       = 0x01
	cmdSet       = 0x03
	headerLen    = 32

	// loginTagV2 is the V2 auth TLV tag 0x001A of the GS108Ev3 capability
	// branch — the FIRST TLV of every CMD_SET_REQUEST (token.go).
	loginTagV2 uint16 = 0x001a

	// Reply status bytes the fake emits (nsdp errors.go): 0x03
	// invalid/unknown attribute, 0x05 SET-related failure, 0x0d
	// required-TLV missing / auth-token mismatch.
	statusBadAttr   = 0x03
	statusSetError  = 0x05
	statusAuthError = 0x0d
)

// magic is the protocol signature at header offset 24.
var magic = []byte{'N', 'S', 'D', 'P'}

// defaultAgentMAC is the live-lab GS108Ev3 switch address the fake claims
// when Options.MAC is nil.
var defaultAgentMAC = net.HardwareAddr{0x8c, 0x3b, 0xad, 0x25, 0x1b, 0x88}

// Options configures Start.
type Options struct {
	// MAC is the agent (switch) MAC clients must target; the login token
	// is derived from it. Nil = the live-lab GS108Ev3 address
	// 8c:3b:ad:25:1b:88.
	MAC net.HardwareAddr
	// Password is the switch admin password clients must present via the
	// V2 login token. Empty = "password" (the GS108Ev3 factory default).
	Password string
	// Attrs seeds scripted small-tag GET answers beyond the built-in
	// capability (0x14), nonce (0x17) and system-name (0x03) tags. The
	// map is copied.
	Attrs map[byte][]byte
}

// VLAN8021QEntry is one stored 802.1Q table entry: the verbatim 4-byte SET
// value {vlan u16 BE, A u8, B u8} (nsdp.Client.Set8021QVLAN sends A =
// tagged port bitmap, B = untagged port bitmap).
type VLAN8021QEntry struct {
	VLANID uint16
	A      byte
	B      byte
}

// FakeAgent is a scripted NSDP v2 switch: a UDP listener on a loopback
// address that speaks the GS108Ev3 wire protocol to any nsdp.Client
// dialed to it (see DialClient / nsdp.NewClientWithConn).
//
// Scenario knobs — plain bool fields read while a request is being
// handled; set them between exchanges (while no client call is in
// flight), like the state getters:
//
//	DropSetReplies: apply an authenticated SET but send NO reply —
//	    the live-proven reply-loss quirk; the client sees its wait
//	    window expire (ErrNoReply) even though the switch applied
//	    the change.
//	IgnoreSets: ACK an authenticated SET with status 0x00 but do NOT
//	    apply it — the silent no-op quirk.
//	AuthFail: reject the login/auth token with the auth-mismatch
//	    reply (status 0x0d) to simulate an authentication failure.
//
// All remaining state is guarded by an internal mutex; the exported
// getters are goroutine-safe and return copies.
type FakeAgent struct {
	DropSetReplies bool
	IgnoreSets     bool
	AuthFail       bool

	mu       sync.Mutex
	conn     net.PacketConn
	mac      net.HardwareAddr // immutable after construction
	password string
	nonce    []byte
	closed   bool

	// Scripted switch state, seeded with factory defaults (resetFactory).
	systemName string
	attrs      map[byte][]byte // scripted small-tag answers

	portAdmin  [8][2]byte                // 0x9400: {admin, flow} per 1-based port
	speedLink  [8][2]byte                // 0x0c00: {speed, flow} (flow mirrors the 0x9400 flow byte)
	portQoS    [8]byte                   // 0x3800: nsdp.QoSPriority per port
	pvid       [8]uint16                 // 0x3000
	ingress    [8]uint16                 // 0x4c00
	egress     [8]uint16                 // 0x5000
	storm      [8]uint16                 // 0x5800
	mirror     [3]byte                   // 0x5c00: {dst, reserved, src bitmap}
	qosMode    byte                      // 0x3400
	blockMcast byte                      // 0x6c00
	portVLANs  []nsdp.PortBasedVLANEntry // 0x2400
	vlan8021Q  []VLAN8021QEntry          // 0x2800
}

// Start launches the fake agent on an OS-chosen loopback UDP address and
// registers a t.Cleanup closing it. The Options zero value claims the
// live-lab GS108Ev3 MAC and the factory password "password".
func Start(t testing.TB, opts Options) *FakeAgent {
	t.Helper()
	a, err := newAgent(opts)
	if err != nil {
		t.Fatalf("nsdptest: start fake agent: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

// newAgent resolves the Options defaults, binds the loopback listener and
// starts the serve goroutine.
func newAgent(opts Options) (*FakeAgent, error) {
	mac := opts.MAC
	if mac == nil {
		mac = defaultAgentMAC
	}
	if len(mac) != 6 {
		return nil, fmt.Errorf("agent MAC %s: want 6 bytes", mac)
	}
	password := opts.Password
	if password == "" {
		password = "password"
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bind loopback UDP: %w", err)
	}
	a := newAgentOverConn(conn, mac, password, opts.Attrs)
	go a.serve()
	return a, nil
}

// newAgentOverConn assembles the agent around an already-bound connection
// and seeds the factory state. (Split from newAgent so in-package tests
// can drive the same protocol logic over an in-memory conn.)
func newAgentOverConn(conn net.PacketConn, mac net.HardwareAddr, password string, attrs map[byte][]byte) *FakeAgent {
	nonce := make([]byte, 4)
	for i := range nonce {
		nonce[i] = byte(rand.IntN(256))
	}
	a := &FakeAgent{
		conn:     conn,
		mac:      append(net.HardwareAddr(nil), mac...),
		password: password,
		nonce:    nonce,
		attrs:    make(map[byte][]byte, len(attrs)),
	}
	for tag, v := range attrs {
		a.attrs[tag] = append([]byte(nil), v...)
	}
	a.resetFactory()
	return a
}

// resetFactory seeds the scripted state with factory-fresh GS108Ev3 values.
func (a *FakeAgent) resetFactory() {
	a.systemName = "GS108Ev3"
	for p := 0; p < 8; p++ {
		a.portAdmin[p] = [2]byte{0x01, 0x00} // {admin=1, flow=0} (live factory GET)
		a.speedLink[p] = [2]byte{0x00, 0x00}
		a.portQoS[p] = 4 // QoSPriority Low
		a.pvid[p] = 1
		a.ingress[p], a.egress[p], a.storm[p] = 0, 0, 0
	}
	a.mirror = [3]byte{0, 0, 0}
	a.qosMode = byte(nsdp.QoSModePortBased)
	a.blockMcast = 0
	a.portVLANs = []nsdp.PortBasedVLANEntry{{VLANID: 1, Ports: 0xff}}
	a.vlan8021Q = []VLAN8021QEntry{{VLANID: 1, A: 0x00, B: 0xff}}
}

// Addr returns the loopback UDP address the agent listens on — the peer
// address for nsdp.NewClientWithConn.
func (a *FakeAgent) Addr() net.Addr {
	return a.conn.LocalAddr()
}

// MAC returns the agent (switch) MAC clients must target.
func (a *FakeAgent) MAC() net.HardwareAddr {
	return append(net.HardwareAddr(nil), a.mac...)
}

// Password returns the switch admin password clients must log in with.
func (a *FakeAgent) Password() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.password
}

// Close stops the serve loop and closes the listener. Idempotent.
func (a *FakeAgent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	return a.conn.Close()
}

// DialClient binds a loopback UDP socket and returns an nsdp.Client over
// the nsdp.NewClientWithConn seam, pointed at this agent and carrying the
// agent's own password. The client owns its socket: Close it when done
// (Start's cleanup closes only the agent).
func (a *FakeAgent) DialClient() (*nsdp.Client, error) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("nsdptest: bind client socket: %w", err)
	}
	c, err := nsdp.NewClientWithConn(conn, a.MAC(), a.Addr(), a.Password())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("nsdptest: %w", err)
	}
	return c, nil
}

// --- Serve loop ------------------------------------------------------------

func (a *FakeAgent) serve() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := a.conn.ReadFrom(buf)
		if err != nil {
			return // listener closed
		}
		a.handle(append([]byte(nil), buf[:n]...), addr)
	}
}

// handle validates the request header and dispatches by command byte.
// Garbage packets are dropped silently, like a real switch.
func (a *FakeAgent) handle(pkt []byte, addr net.Addr) {
	if len(pkt) < headerLen || pkt[0] != protoVersion || !bytes.Equal(pkt[24:28], magic) {
		return
	}
	switch pkt[1] {
	case cmdGet:
		a.handleGet(pkt, addr)
	case cmdSet:
		a.handleSet(pkt, addr)
	}
}

// handleGet answers GET requests. Attr GETs (EncodeGetRequest form: 4-byte
// {tag,0,0,0} entries) walk as {tag, len 0} TLVs with a truncated tail;
// block GETs (EncodeBlockGetRequest form) walk as the clean two-TLV pair
// {marker 0x0014, len 0} + {0xNN00, selector} — that is the discriminator.
func (a *FakeAgent) handleGet(req []byte, addr net.Addr) {
	tlvs, truncated := nsdp.WalkTLVs(req)
	a.mu.Lock()
	defer a.mu.Unlock()

	if !truncated && len(tlvs) >= 2 &&
		(tlvs[0].Tag == nsdp.BlockMarkerV2 || tlvs[0].Tag == nsdp.BlockMarkerV1) &&
		tlvs[1].Tag>>8 != 0 && tlvs[1].Tag&0xff == 0 {
		a.replyBlockGet(req, addr, byte(tlvs[1].Tag>>8))
		return
	}
	var out []nsdp.TLV
	for _, t := range tlvs {
		switch t.Tag {
		case nsdp.TagCapabilityTag:
			out = append(out, nsdp.TLV{Tag: nsdp.TagCapabilityTag, Value: []byte{0x00, 0x00, 0x00, 0x10}})
		case nsdp.TagNonceTag:
			out = append(out, nsdp.TLV{Tag: nsdp.TagNonceTag, Value: append([]byte(nil), a.nonce...)})
		case nsdp.TagSystemName:
			out = append(out, nsdp.TLV{Tag: nsdp.TagSystemName, Value: []byte(a.systemName)})
		default:
			if v, ok := a.attrs[byte(t.Tag)]; ok {
				out = append(out, nsdp.TLV{Tag: t.Tag, Value: append([]byte(nil), v...)})
			}
		}
	}
	if len(out) == 0 {
		// Unknown attr: the switch announces the first requested tag in
		// the failing-tag field.
		var failing uint16
		if len(tlvs) > 0 {
			failing = tlvs[0].Tag
		}
		a.write(addr, nsdp.EncodeReply(req, statusBadAttr, failing, nil))
		return
	}
	a.write(addr, nsdp.EncodeReply(req, 0x00, 0, nil, out...))
}

// replyBlockGet serves one scripted block. Bandwidth tables (0x4c00 /
// 0x5000 / 0x5800) come as one 5-byte TLV per port — the confirmed
// per-entry layout; the VLAN tables carry one entry per TLV (live-proven
// 0x2400 packing); the other per-port tables ride as one TLV of
// concatenated entries, which the nsdp decoders accept. Unknown blocks
// stay silent, like the real switch — the client's GET retry loop then
// exhausts.
func (a *FakeAgent) replyBlockGet(req []byte, addr net.Addr, blockID byte) {
	tag := uint16(blockID) << 8
	var tlvs []nsdp.TLV
	switch tag {
	case nsdp.TagPortAdminStatus:
		v := make([]byte, 0, 24)
		for p := 0; p < 8; p++ {
			v = append(v, byte(p+1), a.portAdmin[p][0], a.portAdmin[p][1])
		}
		tlvs = append(tlvs, nsdp.TLV{Tag: tag, Value: v})
	case nsdp.TagSpeedLinkStatus:
		v := make([]byte, 0, 24)
		for p := 0; p < 8; p++ {
			v = append(v, byte(p+1), a.speedLink[p][0], a.speedLink[p][1])
		}
		tlvs = append(tlvs, nsdp.TLV{Tag: tag, Value: v})
	case nsdp.TagPortBasedQoS:
		v := make([]byte, 0, 16)
		for p := 0; p < 8; p++ {
			v = append(v, byte(p+1), a.portQoS[p])
		}
		tlvs = append(tlvs, nsdp.TLV{Tag: tag, Value: v})
	case nsdp.TagPVID:
		v := make([]byte, 0, 24)
		for p := 0; p < 8; p++ {
			v = append(v, byte(p+1), byte(a.pvid[p]>>8), byte(a.pvid[p]))
		}
		tlvs = append(tlvs, nsdp.TLV{Tag: tag, Value: v})
	case nsdp.TagIngressRate, nsdp.TagEgressRate, nsdp.TagBroadcastStormRate:
		var table *[8]uint16
		switch tag {
		case nsdp.TagIngressRate:
			table = &a.ingress
		case nsdp.TagEgressRate:
			table = &a.egress
		case nsdp.TagBroadcastStormRate:
			table = &a.storm
		}
		for p := 0; p < 8; p++ {
			tlvs = append(tlvs, nsdp.TLV{Tag: tag, Value: []byte{
				byte(p + 1), 0x00, 0x00, byte(table[p] >> 8), byte(table[p]),
			}})
		}
	case nsdp.TagPortMirroring:
		tlvs = append(tlvs, nsdp.TLV{Tag: tag, Value: append([]byte(nil), a.mirror[:]...)})
	case nsdp.TagQoSMode:
		tlvs = append(tlvs, nsdp.TLV{Tag: tag, Value: []byte{a.qosMode}})
	case nsdp.TagBlockUnknownMulticast:
		tlvs = append(tlvs, nsdp.TLV{Tag: tag, Value: []byte{a.blockMcast}})
	case nsdp.TagPortBasedVLAN:
		for _, e := range a.portVLANs {
			tlvs = append(tlvs, nsdp.TLV{Tag: tag, Value: []byte{
				byte(e.VLANID >> 8), byte(e.VLANID), e.Ports,
			}})
		}
	case nsdp.Tag8021QVLAN:
		for _, e := range a.vlan8021Q {
			tlvs = append(tlvs, nsdp.TLV{Tag: tag, Value: []byte{
				byte(e.VLANID >> 8), byte(e.VLANID), e.A, e.B,
			}})
		}
	default:
		return // unknown block: silent
	}
	a.write(addr, nsdp.EncodeReply(req, 0x00, 0, nil, tlvs...))
}

// handleSet authenticates and applies a CMD_SET_REQUEST. The auth TLV
// (first TLV, tag 0x001A, the 8-byte V2 token) is validated against the
// token the real switch would derive: nsdp.V2LoginToken over the fake's
// current nonce, its own MAC and its password. A mismatch — and knob
// AuthFail — gets the live auth-mismatch reply (status 0x0d, failing tag
// 0x001A, {BE16 len, expected-token} payload). A successful SET applies
// its data TLVs to the scripted state and ROLLS the nonce (live-proven);
// the knobs then shape the outcome: IgnoreSets skips applying,
// DropSetReplies skips the ACK (the value still applies, the nonce still
// rolls).
func (a *FakeAgent) handleSet(req []byte, addr net.Addr) {
	tlvs, _ := nsdp.WalkTLVs(req) // SET request TLV regions are clean
	a.mu.Lock()
	defer a.mu.Unlock()

	var gotTag uint16
	var got []byte
	if len(tlvs) > 0 {
		gotTag, got = tlvs[0].Tag, tlvs[0].Value
	}
	expected := a.v2Token()
	if a.AuthFail || gotTag != loginTagV2 || !bytes.Equal(got, expected) {
		payload := append([]byte{byte(len(expected) >> 8), byte(len(expected))}, expected...)
		a.write(addr, nsdp.EncodeReply(req, statusAuthError, loginTagV2, payload))
		return
	}
	if !a.IgnoreSets {
		for _, t := range tlvs[1:] {
			if err := a.applyTLV(t); err != nil {
				a.write(addr, nsdp.EncodeReply(req, statusSetError, t.Tag, nil))
				return
			}
		}
	}
	a.rollNonce()
	if a.DropSetReplies {
		return // applied, but silent — the reply-loss quirk
	}
	a.write(addr, nsdp.EncodeReply(req, 0x00, 0, nil))
}

// write sends one reply packet to the request's source address.
func (a *FakeAgent) write(addr net.Addr, pkt []byte) {
	a.conn.WriteTo(pkt, addr) //nolint:errcheck — best effort, like a switch
}

// v2Token computes the 8-byte token the real GS108Ev3 derives for the
// fake's current nonce and password: the nsdp.V2LoginToken math over the
// 20-byte zero-padded password window (token.go padPassword).
func (a *FakeAgent) v2Token() []byte {
	pw := make([]byte, 20)
	copy(pw, a.password)
	return nsdp.V2LoginToken(a.nonce, a.mac, pw)
}

// rollNonce increments the auth nonce (big-endian), mirroring the
// live-proven nonce roll after every successful authenticated SET.
func (a *FakeAgent) rollNonce() {
	for i := len(a.nonce) - 1; i >= 0; i-- {
		a.nonce[i]++
		if a.nonce[i] != 0 {
			break
		}
	}
}

// applyTLV applies one SET data TLV to the scripted state, in the wire
// form the real switch accepts (methods.go layouts). A malformed value
// returns an error → the SET-related-failure reply (status 0x05, failing
// tag = the TLV's tag). Unknown tags are accepted as silent no-ops (the
// SetRaw escape hatch must not wedge the fake).
func (a *FakeAgent) applyTLV(t nsdp.TLV) error {
	v := t.Value
	switch t.Tag {
	case nsdp.TagSystemName:
		a.systemName = string(v)
		return nil
	case nsdp.TagSystemLocation, nsdp.TagIPAddress, nsdp.TagSubnetMask,
		nsdp.TagGatewayAddr, nsdp.TagDHCPMode, nsdp.TagVLANEngineMode,
		nsdp.TagIGMPSnooping:
		a.attrs[byte(t.Tag)] = append([]byte(nil), v...)
		return nil
	case nsdp.TagPortAdminStatus:
		if len(v) != 3 || v[0] < 1 || v[0] > 8 {
			return fmt.Errorf("0x%04x: want 3 bytes {port 1-8, admin, flow}, got %d", t.Tag, len(v))
		}
		a.portAdmin[v[0]-1] = [2]byte{v[1], v[2]}
		a.speedLink[v[0]-1][1] = v[2] // the 0x0c00 third byte mirrors the 0x9400 flow byte
		return nil
	case nsdp.TagPortBasedQoS:
		if len(v) != 2 || v[0] < 1 || v[0] > 8 {
			return fmt.Errorf("0x%04x: want 2 bytes {port 1-8, priority}, got %d", t.Tag, len(v))
		}
		a.portQoS[v[0]-1] = v[1]
		return nil
	case nsdp.TagPVID:
		if len(v) != 3 || v[0] < 1 || v[0] > 8 {
			return fmt.Errorf("0x%04x: want 3 bytes {port 1-8, vlan_id u16 BE}, got %d", t.Tag, len(v))
		}
		a.pvid[v[0]-1] = binary.BigEndian.Uint16(v[1:3])
		return nil
	case nsdp.TagIngressRate:
		return a.applyBandwidth(&a.ingress, t.Tag, v)
	case nsdp.TagEgressRate:
		return a.applyBandwidth(&a.egress, t.Tag, v)
	case nsdp.TagBroadcastStormRate:
		return a.applyBandwidth(&a.storm, t.Tag, v)
	case nsdp.TagPortMirroring:
		if len(v) != 3 {
			return fmt.Errorf("0x%04x: want 3 bytes {dst, reserved, src bitmap}, got %d", t.Tag, len(v))
		}
		copy(a.mirror[:], v)
		return nil
	case nsdp.TagQoSMode:
		if len(v) != 1 || v[0] < 1 || v[0] > 2 {
			// The firmware SET handler (bank1 0x7b98) accepts only 1-2.
			return fmt.Errorf("0x%04x: want 1 mode byte in [1,2], got %d bytes", t.Tag, len(v))
		}
		a.qosMode = v[0]
		return nil
	case nsdp.TagBlockUnknownMulticast:
		if len(v) != 1 {
			return fmt.Errorf("0x%04x: want 1 value byte, got %d", t.Tag, len(v))
		}
		a.blockMcast = v[0]
		return nil
	case nsdp.TagPortBasedVLAN:
		if len(v) != 3 {
			return fmt.Errorf("0x%04x: want 3 bytes {vlan_id u16 BE, port_bitmap}, got %d", t.Tag, len(v))
		}
		id := binary.BigEndian.Uint16(v[0:2])
		for i := range a.portVLANs {
			if a.portVLANs[i].VLANID == id {
				a.portVLANs[i].Ports = v[2]
				return nil
			}
		}
		a.portVLANs = append(a.portVLANs, nsdp.PortBasedVLANEntry{VLANID: id, Ports: v[2]})
		return nil
	case nsdp.Tag8021QVLAN:
		// Live-observed per-vlan entries {vlan u16 BE, A u8, B u8};
		// the SET value is stored verbatim, keyed by VLAN.
		if len(v) != 4 {
			return fmt.Errorf("0x%04x: want 4 bytes {vlan_id u16 BE, A, B}, got %d", t.Tag, len(v))
		}
		id := binary.BigEndian.Uint16(v[0:2])
		for i := range a.vlan8021Q {
			if a.vlan8021Q[i].VLANID == id {
				a.vlan8021Q[i].A, a.vlan8021Q[i].B = v[2], v[3]
				return nil
			}
		}
		a.vlan8021Q = append(a.vlan8021Q, VLAN8021QEntry{VLANID: id, A: v[2], B: v[3]})
		return nil
	case nsdp.TagDelete8021QVLAN:
		if len(v) != 2 {
			return fmt.Errorf("0x%04x: want 2 bytes {vlan_id u16 BE}, got %d", t.Tag, len(v))
		}
		id := binary.BigEndian.Uint16(v)
		for i := range a.vlan8021Q {
			if a.vlan8021Q[i].VLANID == id {
				a.vlan8021Q = append(a.vlan8021Q[:i], a.vlan8021Q[i+1:]...)
				return nil // idempotent delete (live-proven)
			}
		}
		return nil
	case nsdp.TagFactoryDefaults:
		a.resetFactory()
		return nil
	case nsdp.TagReboot, nsdp.TagResetPortStats:
		return nil // action SETs: no modeled state
	default:
		return nil // unknown tag: accepted, silently not applied
	}
}

// applyBandwidth applies a 5-byte bandwidth entry {port u8, 00 00
// reserved, limit u16 BE} (tags 0x4c00/0x5000/0x5800).
func (a *FakeAgent) applyBandwidth(table *[8]uint16, tag uint16, v []byte) error {
	if len(v) != 5 || v[0] < 1 || v[0] > 8 || v[1] != 0 || v[2] != 0 {
		return fmt.Errorf("0x%04x: want 5 bytes {port 1-8, 00 00, limit u16 BE}, got %d bytes", tag, len(v))
	}
	table[v[0]-1] = binary.BigEndian.Uint16(v[3:5])
	return nil
}

// --- State getters for assertions ------------------------------------------

// SystemName returns the scripted system name (attr 0x03).
func (a *FakeAgent) SystemName() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.systemName
}

// Nonce returns a copy of the current auth nonce (attr 0x17). It rolls
// after every successful authenticated SET.
func (a *FakeAgent) Nonce() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.nonce...)
}

// Attr returns a copy of the scripted small-tag answer for tag, or nil.
func (a *FakeAgent) Attr(tag byte) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if v, ok := a.attrs[tag]; ok {
		return append([]byte(nil), v...)
	}
	return nil
}

// PortAdminStatus returns the 0x9400 table: one {port, admin, flow} entry
// per 1-based port.
func (a *FakeAgent) PortAdminStatus() []nsdp.PortAdminStatusEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]nsdp.PortAdminStatusEntry, 8)
	for p := 0; p < 8; p++ {
		out[p] = nsdp.PortAdminStatusEntry{Port: byte(p + 1), Admin: a.portAdmin[p][0], Flow: a.portAdmin[p][1]}
	}
	return out
}

// SpeedLinkStatus returns the 0x0c00 table: one {port, speed, flow} entry
// per 1-based port (flow mirrors the 0x9400 flow byte).
func (a *FakeAgent) SpeedLinkStatus() []nsdp.SpeedLinkStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]nsdp.SpeedLinkStatus, 8)
	for p := 0; p < 8; p++ {
		out[p] = nsdp.SpeedLinkStatus{Port: byte(p + 1), Speed: a.speedLink[p][0], Flow: a.speedLink[p][1]}
	}
	return out
}

// PortQoS returns the 0x3800 table: one {port, priority} entry per
// 1-based port.
func (a *FakeAgent) PortQoS() []nsdp.PortQoSEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]nsdp.PortQoSEntry, 8)
	for p := 0; p < 8; p++ {
		out[p] = nsdp.PortQoSEntry{Port: byte(p + 1), Priority: nsdp.QoSPriority(a.portQoS[p])}
	}
	return out
}

// PVIDs returns the 0x3000 table: one {port, vlan} entry per 1-based port.
func (a *FakeAgent) PVIDs() []nsdp.PVIDEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]nsdp.PVIDEntry, 8)
	for p := 0; p < 8; p++ {
		out[p] = nsdp.PVIDEntry{Port: byte(p + 1), VLANID: a.pvid[p]}
	}
	return out
}

// IngressRates returns the 0x4c00 table: one {port, limit} entry per
// 1-based port. EgressRates (0x5000) and BroadcastStormRates (0x5800)
// share the layout.
func (a *FakeAgent) IngressRates() []nsdp.BandwidthEntry        { return a.bandwidth(&a.ingress) }
func (a *FakeAgent) EgressRates() []nsdp.BandwidthEntry         { return a.bandwidth(&a.egress) }
func (a *FakeAgent) BroadcastStormRates() []nsdp.BandwidthEntry { return a.bandwidth(&a.storm) }

func (a *FakeAgent) bandwidth(table *[8]uint16) []nsdp.BandwidthEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]nsdp.BandwidthEntry, 8)
	for p := 0; p < 8; p++ {
		out[p] = nsdp.BandwidthEntry{Port: byte(p + 1), Limit: table[p]}
	}
	return out
}

// PortMirroring returns the 0x5c00 value {dst, reserved, src bitmap}.
func (a *FakeAgent) PortMirroring() nsdp.PortMirrorConfig {
	a.mu.Lock()
	defer a.mu.Unlock()
	return nsdp.PortMirrorConfig{DstPort: a.mirror[0], Reserved: a.mirror[1], SrcPorts: a.mirror[2]}
}

// QoSMode returns the global 0x3400 mode.
func (a *FakeAgent) QoSMode() nsdp.QoSMode {
	a.mu.Lock()
	defer a.mu.Unlock()
	return nsdp.QoSMode(a.qosMode)
}

// BlockUnknownMulticast returns the global 0x6c00 byte (0=off, 1=on).
func (a *FakeAgent) BlockUnknownMulticast() byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.blockMcast
}

// PortBasedVLANs returns a copy of the 0x2400 table {vlan, port bitmap}.
func (a *FakeAgent) PortBasedVLANs() []nsdp.PortBasedVLANEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]nsdp.PortBasedVLANEntry(nil), a.portVLANs...)
}

// VLAN8021Q returns a copy of the stored 802.1Q table entries (0x2800),
// each the verbatim {vlan u16 BE, A, B} SET value.
func (a *FakeAgent) VLAN8021Q() []VLAN8021QEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]VLAN8021QEntry(nil), a.vlan8021Q...)
}
