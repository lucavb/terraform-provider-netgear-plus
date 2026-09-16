// In-memory transport: a net.PacketConn pair with no OS networking.
// The package's in-package scenario tests run their assertions over
// BOTH transports — loopback UDP (agent_test.go) and this one — so the
// FakeAgent's protocol logic is verified even on machines whose sandbox
// denies loopback sends, and the real socket path is verified where
// loopback is permitted. Exported MemConnPair/StartOverConn extend the
// same transport to out-of-package harnesses (the metrics exporter's
// collector tests) for the same reason.

package nsdptest

import (
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

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

// MemConnPair returns the two ends of an in-memory net.PacketConn pair:
// WriteTo on one end queues into the other end's ReadFrom, and a read
// deadline that expires mid-read surfaces as os.ErrDeadlineExceeded —
// the nsdp client's wait-window expiry (ErrNoReply). The transport
// performs no OS networking, so harnesses built on it run even on
// machines whose sandbox denies loopback UDP sends. The inbox is
// unbuffered: the peer end must be reading (a serving agent — see
// StartOverConn) while the client writes, matching the serial NSDP
// client; a written-to end nobody reads WEDGES the writer.
func MemConnPair() (agent, client net.PacketConn) {
	a, b := memConnPair()
	return a, b
}

// StartOverConn starts the fake agent serving an already-bound
// connection — the transport-agnostic counterpart of Start (which binds
// a loopback UDP socket): pair it with MemConnPair for a no-OS-network
// session, or with any other net.PacketConn transport. opts seed exactly
// like Start's. A t.Cleanup closes the agent; the caller owns conn.
func StartOverConn(t testing.TB, conn net.PacketConn, opts Options) *FakeAgent {
	t.Helper()
	if conn == nil {
		t.Fatalf("nsdptest: StartOverConn: nil connection")
	}
	mac := opts.MAC
	if mac == nil {
		mac = defaultAgentMAC
	}
	if len(mac) != 6 {
		t.Fatalf("nsdptest: StartOverConn: agent MAC %s: want 6 bytes", mac)
	}
	password := opts.Password
	if password == "" {
		password = "password"
	}
	a := newAgentOverConn(conn, mac, password, opts)
	go a.serve()
	t.Cleanup(func() { a.Close() })
	return a
}
