package nsdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// broadcastUDP is a stand-in destination address for the fake conns.
func broadcastUDP() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(255, 255, 255, 255), Port: serverPort}
}

// buildGetReplyFor builds a GET reply (cmd 0x02, status 0) echoing the
// request's manager MAC, agent MAC and sequence, carrying the given TLVs
// and the terminator.
func buildGetReplyFor(req []byte, tlvs ...TLV) []byte {
	pkt := make([]byte, 0, 64)
	pkt = append(pkt, protoVersion, cmdGetReply, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	pkt = append(pkt, req[8:14]...)
	pkt = append(pkt, req[14:20]...)
	pkt = append(pkt, req[20:24]...)
	pkt = append(pkt, magic[:]...)
	pkt = append(pkt, 0, 0, 0, 0)
	for _, t := range tlvs {
		pkt = append(pkt, byte(t.Tag>>8), byte(t.Tag), byte(len(t.Value)>>8), byte(len(t.Value)))
		pkt = append(pkt, t.Value...)
	}
	pkt = append(pkt, 0xff, 0xff, 0x00, 0x00)
	return pkt
}

// buildSetReplyFor builds a SET reply (cmd 0x04) echoing the request
// header fields, with the given status byte.
func buildSetReplyFor(req []byte, status byte) []byte {
	pkt := make([]byte, 0, 64)
	pkt = append(pkt, protoVersion, cmdSetReply, status, 0x00, 0x00, 0x00, 0x00, 0x00)
	pkt = append(pkt, req[8:14]...)
	pkt = append(pkt, req[14:20]...)
	pkt = append(pkt, req[20:24]...)
	pkt = append(pkt, magic[:]...)
	pkt = append(pkt, 0, 0, 0, 0)
	pkt = append(pkt, 0xff, 0xff, 0x00, 0x00)
	return pkt
}

// buildAuthMismatchReply builds the ROUND 8 auth-mismatch reply: status
// 0x0d, failing tag 0x001A, the payload {BE16 len, expected token} right
// after the 32-byte header (NOT a TLV — WalkTLVs truncates on it), then
// the terminator — 46 bytes for an 8-byte V2 token, matching the live
// capture.
func buildAuthMismatchReply(req []byte, failingTag uint16, expected []byte) []byte {
	pkt := make([]byte, 0, 48+len(expected))
	pkt = append(pkt, protoVersion, cmdSetReply, 0x0d, 0x00, byte(failingTag>>8), byte(failingTag), 0x00, 0x00)
	pkt = append(pkt, req[8:14]...)
	pkt = append(pkt, req[14:20]...)
	pkt = append(pkt, req[20:24]...)
	pkt = append(pkt, magic[:]...)
	pkt = append(pkt, 0, 0, 0, 0)
	pkt = append(pkt, byte(len(expected)>>8), byte(len(expected)))
	pkt = append(pkt, expected...)
	pkt = append(pkt, 0xff, 0xff, 0x00, 0x00)
	return pkt
}

// incBE returns a copy of a 4-byte big-endian nonce incremented by one —
// the fake switch's deterministic nonce-roll rule.
func incBE(n []byte) []byte {
	out := append([]byte(nil), n...)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// blackholeConn is a fake net.PacketConn that swallows the first two
// reads (deadline-exceeded black holes) and answers the third read with a
// valid reply to the most recently written request.
type blackholeConn struct {
	mu      sync.Mutex
	written [][]byte
	reads   int
}

func (c *blackholeConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, append([]byte(nil), b...))
	return len(b), nil
}

func (c *blackholeConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if c.reads <= 2 {
		return 0, nil, os.ErrDeadlineExceeded // black hole: window expires
	}
	req := c.written[len(c.written)-1]
	pkt := buildGetReplyFor(req, TLV{Tag: 0x0003, Value: []byte("GS108Ev3")})
	n := copy(b, pkt)
	return n, &net.UDPAddr{IP: net.IPv4(192, 168, 0, 2), Port: serverPort}, nil
}

func (c *blackholeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blackholeConn) SetWriteDeadline(time.Time) error { return nil }
func (c *blackholeConn) SetDeadline(time.Time) error      { return nil }
func (c *blackholeConn) Close() error                     { return nil }
func (c *blackholeConn) LocalAddr() net.Addr              { return nil }
func (c *blackholeConn) requests() [][]byte               { return c.written }

// switchSim is a fake switch: it answers multi-tag GETs (attrs from the
// attrs map plus the capability/nonce/name fields) and block GETs (from
// the blocks map, silent when absent). Every SET is authenticated: the
// sim derives the expected token from ITS current nonce and its own
// password via the real loginToken and compares it with the request's
// auth TLV (first TLV of every CMD_SET_REQUEST). A mismatch gets the
// ROUND 8 auth-mismatch reply (status 0x0d, failing tag, expected-token
// payload); a SUCCESSFUL authenticated SET applies any system-name TLV
// and ROLLS the nonce (the live-proven ROUND 8 behavior).
type switchSim struct {
	mu         sync.Mutex
	written    [][]byte
	capability uint32
	nonce      []byte
	name       []byte
	password   []byte          // the switch's own admin password (auth checks)
	attrs      map[byte][]byte // extra small-tag answers (beyond the fields above)
	blocks     map[byte][]TLV  // block answers, keyed by block id (tag high byte)
}

// rollNonce models the ROUND 8 nonce roll: every SUCCESSFUL authenticated
// SET invalidates the current nonce.
func (s *switchSim) rollNonce() {
	s.nonce = incBE(s.nonce)
}

func (s *switchSim) WriteTo(b []byte, _ net.Addr) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.written = append(s.written, append([]byte(nil), b...))
	return len(b), nil
}

func (s *switchSim) ReadFrom(b []byte) (int, net.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req := s.written[len(s.written)-1]
	var pkt []byte
	switch req[1] {
	case cmdGet:
		pkt = s.replyGet(req)
		if pkt == nil {
			return 0, nil, os.ErrDeadlineExceeded // silent: unknown block
		}
	case cmdSet:
		tlvs, _ := WalkTLVs(req)
		var gotAuth []byte
		if len(tlvs) > 0 {
			gotAuth = tlvs[0].Value // auth TLV is first in every CMD_SET_REQUEST
		}
		// The sim knows its own password: derive the expected token from
		// ITS current nonce and compare with the request's auth TLV.
		expected := loginToken(s.capability, s.nonce, req[14:20], s.password)
		if !bytes.Equal(gotAuth, expected) {
			pkt = buildAuthMismatchReply(req, loginTagFor(s.capability), expected)
		} else {
			for _, t := range tlvs {
				if t.Tag == systemNameTag {
					s.name = append([]byte(nil), t.Value...)
				}
			}
			s.rollNonce() // ROUND 8: every successful authenticated SET rolls the nonce
			pkt = buildSetReplyFor(req, 0x00)
		}
	default:
		return 0, nil, os.ErrDeadlineExceeded
	}
	n := copy(b, pkt)
	return n, &net.UDPAddr{IP: net.IPv4(192, 168, 0, 2), Port: serverPort}, nil
}

func (s *switchSim) SetReadDeadline(time.Time) error  { return nil }
func (s *switchSim) SetWriteDeadline(time.Time) error { return nil }
func (s *switchSim) SetDeadline(time.Time) error      { return nil }
func (s *switchSim) Close() error                     { return nil }
func (s *switchSim) LocalAddr() net.Addr              { return nil }

// replyGet answers a GET request: block reads (TLV{0x0014, len 0} +
// TLV{0xNN00, ...}, block id = second TLV's tag high byte at wire offset
// 36) from the blocks map — nil = silent — and small-tag GETs (4-byte
// entries {tag,0,0,0} from wire offset 33 until the terminator's leading
// 0x00 byte) with the capability/nonce/name fields plus the attrs map.
func (s *switchSim) replyGet(req []byte) []byte {
	if req[33] == attrCapability && req[36] != 0 { // block GET (block id at [36])
		if tlvs, ok := s.blocks[req[36]]; ok {
			return buildGetReplyFor(req, tlvs...)
		}
		return nil
	}
	var tlvs []TLV
	for off := 33; off < len(req) && req[off] != 0; off += 4 {
		switch tag := req[off]; tag {
		case attrCapability:
			tlvs = append(tlvs, TLV{Tag: uint16(attrCapability), Value: []byte{
				byte(s.capability >> 24), byte(s.capability >> 16), byte(s.capability >> 8), byte(s.capability),
			}})
		case attrNonce:
			tlvs = append(tlvs, TLV{Tag: uint16(attrNonce), Value: s.nonce})
		case attrSystemName:
			tlvs = append(tlvs, TLV{Tag: uint16(attrSystemName), Value: s.name})
		default:
			if v, ok := s.attrs[tag]; ok {
				tlvs = append(tlvs, TLV{Tag: uint16(tag), Value: v})
			}
		}
	}
	return buildGetReplyFor(req, tlvs...)
}

// TestClientRetryLoop drives GetAttr against a black-holed first two
// attempts: the third attempt must succeed, each attempt must consume a
// fresh sequence number (anti-replay), and the counter must advance by
// exactly the number of attempts made.
func TestClientRetryLoop(t *testing.T) {
	fc := &blackholeConn{}
	c := &Client{
		conn:     fc,
		dst:      broadcastUDP(),
		mac:      goldenMAC,
		agentMAC: goldenAgentMAC,
		wait:     time.Millisecond,
		seq:      5000,
	}
	val, err := c.GetAttr(0x03)
	if err != nil {
		t.Fatalf("GetAttr: %v", err)
	}
	if string(val) != "GS108Ev3" {
		t.Fatalf("value = %q, want %q", val, "GS108Ev3")
	}
	reqs := fc.requests()
	if len(reqs) != 3 {
		t.Fatalf("sent %d requests, want 3", len(reqs))
	}
	for i, req := range reqs {
		if req[1] != cmdGet || req[33] != 0x03 {
			t.Fatalf("request %d is not a GET attr 0x03: % x", i, req)
		}
		if seq := binary.BigEndian.Uint32(req[20:24]); seq != uint32(5000+i) {
			t.Fatalf("request %d sequence = %d, want %d (fresh sequence per attempt)", i, seq, 5000+i)
		}
	}
	if c.seq != 5003 {
		t.Fatalf("client seq = %d, want 5003 (advanced by one per attempt)", c.seq)
	}
}

// TestSeqMonotonic pins the sequence discipline: nextSeq hands out strictly
// increasing numbers, one per request (retries included).
func TestSeqMonotonic(t *testing.T) {
	c := &Client{seq: 1000}
	for i, want := range []uint32{1000, 1001, 1002} {
		if got := c.nextSeq(); got != want {
			t.Fatalf("nextSeq() #%d = %d, want %d", i, got, want)
		}
	}
	if c.seq != 1003 {
		t.Fatalf("client seq = %d, want 1003", c.seq)
	}
}

// TestSetSystemNameAttachesAuthTLV drives the full auto-login + nonce
// refresh + config SET flow against the switch simulator and pins the
// wire discipline: every CMD_SET_REQUEST must carry the auth TLV BEFORE
// the type-specific name TLV (nsdp_command_start), and — ROUND 8 — the
// token must be REFRESHED (GET attr 0x17 after the login SET rolled the
// nonce) so the config SET carries the token for the rolled nonce.
func TestSetSystemNameAttachesAuthTLV(t *testing.T) {
	nonce := []byte{0x91, 0x6e, 0x11, 0x22}
	password := []byte("hunter2")
	sim := &switchSim{
		capability: goldenCapability,
		nonce:      append([]byte(nil), nonce...),
		name:       []byte("old-name"),
		password:   append([]byte(nil), password...),
	}
	c := &Client{
		conn:     sim,
		dst:      broadcastUDP(),
		mac:      goldenMAC,
		agentMAC: goldenAgentMAC,
		password: password,
		wait:     time.Millisecond,
		seq:      5000,
	}
	if err := c.SetSystemName("lab-sw"); err != nil {
		t.Fatalf("SetSystemName: %v", err)
	}
	reqs := sim.written
	if len(reqs) != 5 {
		t.Fatalf("sent %d requests, want 5 (GET 0x14, GET 0x17, SET login, GET 0x17 refresh, SET name)", len(reqs))
	}
	// Requests 0-2: the login chain, ending in a login SET byte-identical
	// to the public encoder for seq 5002.
	wantLogin := EncodeSetLoginRequest(goldenMAC, goldenAgentMAC, 5002, goldenCapability, nonce, password)
	if !bytes.Equal(reqs[2], wantLogin) {
		t.Fatalf("login SET = % x\nwant           % x", reqs[2], wantLogin)
	}
	// Request 3: the ROUND 8 nonce refresh — a GET attr 0x17 between the
	// login SET and the config SET.
	if reqs[3][1] != cmdGet || reqs[3][33] != attrNonce {
		t.Fatalf("request 3 is not a GET attr 0x17 nonce refresh: % x", reqs[3])
	}
	// Request 4: the config SET. The successful login SET rolled the sim's
	// nonce, so the auth TLV must carry the token for the ROLLED nonce —
	// the login-time token would fail with status 0x0d / tag 0x001A.
	rolled := incBE(nonce)
	wantToken := loginToken(goldenCapability, rolled, goldenAgentMAC, password)
	nameReq := reqs[4]
	if len(nameReq) != 58 {
		t.Fatalf("SET name request = %d bytes, want 58 (header 32 + auth TLV 12 + name TLV 10 + terminator 4)", len(nameReq))
	}
	authTLV := append([]byte{0x00, byte(loginTagV2), 0x00, 0x08}, wantToken...)
	if !bytes.Equal(nameReq[32:44], authTLV) {
		t.Fatalf("auth TLV = % x, want tag 0x001a len 8 + refreshed token % x", nameReq[32:44], wantToken)
	}
	if !bytes.Equal(nameReq[44:54], []byte{0x00, 0x03, 0x00, 0x06, 'l', 'a', 'b', '-', 's', 'w'}) {
		t.Fatalf("name TLV = % x", nameReq[44:54])
	}
	if !bytes.Equal(nameReq[54:58], []byte{0xff, 0xff, 0x00, 0x00}) {
		t.Fatalf("terminator = % x", nameReq[54:58])
	}
	// The cached token must be the refreshed one (rolled nonce).
	if !bytes.Equal(c.token, wantToken) {
		t.Fatalf("cached token = % x, want refreshed % x", c.token, wantToken)
	}
	if !c.loggedIn || c.capability != goldenCapability {
		t.Fatalf("post-login state: loggedIn=%v capability=0x%08x", c.loggedIn, c.capability)
	}
	// Read-back through the simulated switch state.
	name, err := c.GetSystemName()
	if err != nil {
		t.Fatalf("GetSystemName: %v", err)
	}
	if name != "lab-sw" {
		t.Fatalf("read-back name = %q, want %q", name, "lab-sw")
	}
}

// TestStaleTokenAuthMismatch replays the ROUND 8 live failure: after a
// successful Login (whose SET rolls the sim's nonce), a config SET built
// with the now-STALE cached token — the pre-fix client behavior, built
// here by hand to bypass the refresh — must be rejected with *ErrStatus
// status 0x0d, failing tag 0x001A, and ExpectedAuth carrying the token
// the switch wanted under the rolled nonce. A rejected SET must not roll
// the nonce further or apply the name TLV.
func TestStaleTokenAuthMismatch(t *testing.T) {
	nonce := []byte{0x91, 0x6e, 0x11, 0x22}
	password := []byte("hunter2")
	sim := &switchSim{
		capability: goldenCapability,
		nonce:      append([]byte(nil), nonce...),
		name:       []byte("old-name"),
		password:   append([]byte(nil), password...),
	}
	c := &Client{
		conn:     sim,
		dst:      broadcastUDP(),
		mac:      goldenMAC,
		agentMAC: goldenAgentMAC,
		password: password,
		wait:     time.Millisecond,
		seq:      7000,
	}
	// Login succeeds; its SET rolls the sim's nonce.
	if err := c.Login(); err != nil {
		t.Fatalf("Login: %v", err)
	}
	// Pre-fix behavior replay: build the config SET with the stale cached
	// token, bypassing Client.refreshToken.
	seq := c.nextSeq()
	req := encodeSetTLVs(goldenMAC, goldenAgentMAC, seq,
		TLV{Tag: loginTagFor(c.capability), Value: c.token},
		TLV{Tag: systemNameTag, Value: []byte("lab-test")})
	if err := c.send(req); err != nil {
		t.Fatalf("send stale-token SET: %v", err)
	}
	_, err := c.readReply(seq, cmdSetReply, "SET name (stale token replay)")
	var es *ErrStatus
	if !errors.As(err, &es) {
		t.Fatalf("stale-token SET error = %T (%v), want *ErrStatus", err, err)
	}
	if es.Status != 0x0d || es.FailingTag != loginTagV2 {
		t.Fatalf("ErrStatus = status 0x%02x failing tag 0x%04x, want status 0x0d failing tag 0x%04x", es.Status, es.FailingTag, loginTagV2)
	}
	// ExpectedAuth = the token for the once-rolled nonce (login rolled,
	// the rejected SET must NOT roll again): exactly what a refreshed
	// client would have sent.
	rolledOnce := incBE(nonce)
	wantAuth := loginToken(goldenCapability, rolledOnce, goldenAgentMAC, password)
	if !bytes.Equal(es.ExpectedAuth, wantAuth) {
		t.Fatalf("ExpectedAuth = % x, want token for the rolled nonce % x (nonce % x)", es.ExpectedAuth, wantAuth, rolledOnce)
	}
	if bytes.Equal(es.ExpectedAuth, c.token) {
		t.Fatal("roll simulation broken: ExpectedAuth equals the stale sent token")
	}
	if string(sim.name) != "old-name" {
		t.Fatalf("rejected SET must not apply: sim name = %q, want %q", sim.name, "old-name")
	}
	if !bytes.Equal(sim.nonce, rolledOnce) {
		t.Fatalf("rejected SET must not roll the nonce: sim nonce = % x, want % x", sim.nonce, rolledOnce)
	}
}

// TestSetSystemNameRejectedNoAuth pins the error surface: a wrong
// password makes the sim reject the login SET with the ROUND 8
// auth-mismatch reply (status 0x0d, failing tag 0x001A, expected-token
// payload), which must surface as *ErrStatus with ExpectedAuth carrying
// the token the switch wanted (for ITS password and current nonce).
func TestSetSystemNameRejectedNoAuth(t *testing.T) {
	nonce := []byte{0x91, 0x6e, 0x11, 0x22}
	sim := &switchSim{
		capability: goldenCapability,
		nonce:      nonce,
		name:       []byte("old-name"),
		password:   []byte("right-pw"),
	}
	c := &Client{
		conn:     sim,
		dst:      broadcastUDP(),
		mac:      goldenMAC,
		agentMAC: goldenAgentMAC,
		password: []byte("wrong"),
		wait:     time.Millisecond,
		seq:      5000,
	}
	err := c.SetSystemName("lab-sw")
	var es *ErrStatus
	if !errors.As(err, &es) {
		t.Fatalf("SetSystemName error = %T (%v), want *ErrStatus", err, err)
	}
	if es.Status != 0x0d || es.FailingTag != loginTagV2 {
		t.Fatalf("ErrStatus = status 0x%02x failing tag 0x%04x, want status 0x0d failing tag 0x%04x", es.Status, es.FailingTag, loginTagV2)
	}
	wantAuth := loginToken(goldenCapability, nonce, goldenAgentMAC, []byte("right-pw"))
	if !bytes.Equal(es.ExpectedAuth, wantAuth) {
		t.Fatalf("ExpectedAuth = % x, want token for the switch's own password % x", es.ExpectedAuth, wantAuth)
	}
	if c.loggedIn {
		t.Fatal("client must not be logged in after a rejected login")
	}
	if string(sim.name) != "old-name" {
		t.Fatalf("rejected login must not apply the name: sim name = %q", sim.name)
	}
}
