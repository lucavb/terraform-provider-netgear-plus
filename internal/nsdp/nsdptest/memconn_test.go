package nsdptest

import (
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// In-memory transport: a net.PacketConn pair with no OS networking. The
// scenario assertions above run against BOTH transports — loopback UDP
// (agent_test.go) and this one — so the FakeAgent's protocol logic is
// verified even on machines whose sandbox denies loopback sends, and the
// real socket path is verified where loopback is permitted.

var memAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 63322}

// memConn is one end of an in-memory PacketConn pair: WriteTo queues into
// the peer's inbox (unbuffered — both ends always park in ReadFrom between
// exchanges, matching the serial NSDP client), ReadFrom honors the read
// deadline with os.ErrDeadlineExceeded (a net.Error the nsdp client treats
// as the wait-window expiry → ErrNoReply).
type memConn struct {
	mu       sync.Mutex
	peer     *memConn
	inbox    chan []byte
	closed   chan struct{}
	deadline time.Time
}

func memConnPair() (a, b *memConn) {
	a = &memConn{inbox: make(chan []byte), closed: make(chan struct{})}
	b = &memConn{inbox: make(chan []byte), closed: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}

func (c *memConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.peer.closed:
		return 0, net.ErrClosed
	default:
	}
	select {
	case c.peer.inbox <- append([]byte(nil), b...):
		return len(b), nil
	case <-c.peer.closed:
		return 0, net.ErrClosed
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *memConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	dl := c.deadline
	c.mu.Unlock()
	var timeout <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		timeout = time.After(d)
	}
	select {
	case pkt := <-c.inbox:
		return copy(b, pkt), memAddr, nil
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *memConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *memConn) SetWriteDeadline(time.Time) error { return nil }
func (c *memConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }

func (c *memConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return nil
	default:
		close(c.closed)
	}
	return nil
}

func (c *memConn) LocalAddr() net.Addr { return memAddr }

// startMemSession starts the fake agent over one end of an in-memory conn
// pair and returns it with a client dialed to it over the other end.
func startMemSession(t *testing.T, opts Options) (*FakeAgent, *nsdp.Client) {
	t.Helper()
	mac := opts.MAC
	if mac == nil {
		mac = defaultAgentMAC
	}
	password := opts.Password
	if password == "" {
		password = "password"
	}
	agentConn, clientConn := memConnPair()
	agent := newAgentOverConn(agentConn, mac, password, opts.Attrs)
	go agent.serve()
	t.Cleanup(func() {
		agent.Close()
		clientConn.Close()
	})
	c, err := nsdp.NewClientWithConn(clientConn, agent.MAC(), agent.Addr(), password)
	if err != nil {
		t.Fatalf("nsdptest: NewClientWithConn: %v", err)
	}
	return agent, c
}

// TestFakeAgentProtocolInMemory walks the full scenario surface over the
// in-memory transport: login + token refresh, the AuthFail rejection with
// the honest ExpectedAuth, every scripted factory block, the port-status
// SET→read-back, the reply-loss and silent-no-op quirks, and the VLAN
// tables. (Mirrors the UDP suite; see agent_test.go for the per-scenario
// docs.)
func TestFakeAgentProtocolInMemory(t *testing.T) {
	agent, c := startMemSession(t, Options{Password: "hunter2"})

	assertLoginFlow(t, agent, c)
	assertAuthFailKnob(t, agent, c)
	assertFactoryBlocks(t, agent, c)
	assertPortConfigReadBack(t, agent, c)
	assertReplyLossScenario(t, agent, c)
	assertSilentNoOpScenario(t, agent, c)
	assertVLANTables(t, agent, c)
}
