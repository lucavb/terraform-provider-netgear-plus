package fastpath

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Minimal RFC1350 TFTP *server* (octet mode, lockstep) — the FASTPATH
// switch's own TFTP client contacts the SERVER at the address given in
// the web UI's file transfer form (system/file_download.html fields
// `server_addr`, `filepath`, `filename`, `start`). To let the switch
// save or restore its text configuration, the provider must run this
// server on a routable address and UDP port 69 (the switch's client
// targets the well-known port; the web form has no port field).
//
// Files served for RRQ come from a TFTPFileStore (used for restore,
// where the switch pulls the text config INTO nvram); WRQs land as
// events on the same store (used for save, where the switch pushes its
// startup-config to us).
// ---------------------------------------------------------------------------

// TFTPEvent is one completed switch-initiated transfer.
type TFTPEvent struct {
	// Kind is "put" (the switch pushed file bytes: save direction) or
	// "get" (the switch pulled a served file: restore direction).
	Kind string
	// File is the filename field of the request as the switch spelt it.
	File string
	// Data is the transferred bytes (put) or served bytes (get).
	Data []byte
	// Addr is the switch's source address.
	Addr net.Addr
}

// TFTPFileStore is the storage hooks for the server. Serving (RRQ) and
// receiving (WRQ) are both per-file; the concrete store decides what
// the fact means (e.g. when saving a config only one event is expected).
type TFTPFileStore interface {
	// Get serves bytes for named file (the switch wants to pull it).
	Get(file string) ([]byte, error)
	// Put stores transferred bytes under the named file.
	Put(file string, data []byte) error
}

// TFTPError describes protocol-level reject messages; use in stores to
// surface errors as TFTP ERROR packets (RFC1350 code 2 = access
// violation, 3 = disk full, etc.).
type TFTPError struct {
	Code    uint16
	Message string
}

func (e *TFTPError) Error() string { return fmt.Sprintf("tftp error %d: %s", e.Code, e.Message) }

// MapStore is a trivial in-memory TFTPFileStore.
type MapStore struct {
	mu    sync.RWMutex
	files map[string][]byte
}

func NewMapStore() *MapStore { return &MapStore{files: map[string][]byte{}} }

func (m *MapStore) Get(file string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if b, ok := m.files[file]; ok {
		return b, nil
	}
	return nil, &TFTPError{Code: 1, Message: "file not found"}
}

func (m *MapStore) Put(file string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.files == nil {
		m.files = map[string][]byte{}
	}
	m.files[file] = append([]byte(nil), data...)
	return nil
}

// TFTPHandler receives one completed event per transfer.
type TFTPHandler func(ev TFTPEvent)

// TFTPServer is a UDP TFTP server: one well-known socket at
// TFTPListen, each exchange served Hop-per-connection on an ephemeral
// source port with per-exchange timeouts and retransmit budgets.
type TFTPServer struct {
	timeout    time.Duration
	retries    int
	store      TFTPFileStore
	onTransfer TFTPHandler
	conn       *net.UDPConn
	wg         sync.WaitGroup
}

// NewTFTPServer builds a server. timeout<=0 → 1s; retries<=0 → 5.
func NewTFTPServer(store TFTPFileStore, onTransfer TFTPHandler, timeout time.Duration, retries int) *TFTPServer {
	if timeout <= 0 {
		timeout = time.Second
	}
	if retries <= 0 {
		retries = 5
	}
	return &TFTPServer{timeout: timeout, retries: retries, store: store, onTransfer: onTransfer}
}

// Listen binds the server to the wire form "<host>:port" (e.g.
// "0.0.0.0:69") and starts serving in the background.
func (s *TFTPServer) ListenAndServe(bind string) error {
	raddr, err := net.ResolveUDPAddr("udp4", bind)
	if err != nil {
		return fmt.Errorf("tftp server: resolve %s: %w", bind, err)
	}
	conn, err := net.ListenUDP("udp4", raddr)
	if err != nil {
		return fmt.Errorf("tftp server: bind %s: %w (privileged: port 69 normally requires root or a cap_net_bind_service grant)", bind, err)
	}
	s.conn = conn
	s.wg.Add(1)
	go s.serveLoop()
	return nil
}

// Addr returns the bound address (after ListenAndServe).
func (s *TFTPServer) Addr() net.Addr {
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

// Close stops accepting exchanges; in-flight sessions terminate on
// their own deadlines.
func (s *TFTPServer) Close() error {
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

// Wait blocks until all in-flight sessions have returned.
func (s *TFTPServer) Wait() { s.wg.Wait() }

func (s *TFTPServer) serveLoop() {
	defer s.wg.Done()
	for {
		buf := make([]byte, 4096)
		n, raddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 2 {
			continue
		}
		op := binary.BigEndian.Uint16(buf[:2])
		if op != tftpOpRRQ && op != tftpOpWRQ {
			continue // only classic transfer starts here
		}
		session := s.newSession(*raddr)
		s.wg.Add(1)
		go func(op uint16, pkt []byte) {
			defer s.wg.Done()
			session.run(op, pkt)
		}(op, append([]byte(nil), buf[:n]...))
	}
}

// tftpSession is the per-request lockstep loop against one peer socket.
type tftpSession struct {
	srv     *TFTPServer
	raddr   *net.UDPAddr
	conn    *net.UDPConn
	evtKind string
	file    string
}

func (s *TFTPServer) newSession(raddr net.UDPAddr) *tftpSession {
	conn, err := net.DialUDP("udp4", nil, &raddr)
	if err != nil {
		return &tftpSession{srv: s, raddr: &raddr}
	}
	return &tftpSession{srv: s, raddr: &raddr, conn: conn}
}

func (t *tftpSession) run(op uint16, pkt []byte) {
	if t.conn == nil {
		return
	}
	defer t.conn.Close()
	name, ok := tftpFileName(pkt)
	if !ok || name == "" {
		t.sendError(0, "malformed filename")
		return
	}
	t.file = name
	switch op {
	case tftpOpWRQ:
		t.kindWRQ()
	case tftpOpRRQ:
		t.kindRRQ()
	}
}

func (t *tftpSession) kindRRQ() {
	data, err := t.srv.store.Get(t.file)
	if err != nil {
		if te, ok := err.(*TFTPError); ok {
			t.sendError(te.Code, te.Message)
		} else {
			t.sendError(1, "file not found")
		}
		return
	}
	var block uint16 = 1
	for offset := 0; ; offset += tftpBlockSize {
		var chunk []byte
		if end := offset + tftpBlockSize; end < len(data) {
			chunk = data[offset:end]
		} else {
			chunk = data[minInt2(offset, len(data)):]
		}
		sent := false
		for attempt := 0; attempt < t.srv.retries; attempt++ {
			pkt := binary.BigEndian.AppendUint16(nil, tftpOpDATA)
			pkt = binary.BigEndian.AppendUint16(pkt, block)
			pkt = append(pkt, chunk...)
			if err := t.send(pkt); err != nil {
				break
			}
			reply, rerr := t.recv()
			if rerr == nil && len(reply) >= 4 &&
				binary.BigEndian.Uint16(reply[:2]) == tftpOpACK &&
				binary.BigEndian.Uint16(reply[2:4]) == block {
				sent = true
				break
			}
		}
		if !sent {
			return
		}
		if len(chunk) < tftpBlockSize {
			break
		}
		block++
	}
	if t.srv.onTransfer != nil {
		t.srv.onTransfer(TFTPEvent{Kind: "get", File: t.file, Data: data, Addr: t.raddr})
	}
}

func (t *tftpSession) kindWRQ() {
	// WRQ is acknowledged with ACK{block 0} before DATA 1 may flow.
	pkt0 := binary.BigEndian.AppendUint16(nil, tftpOpACK)
	pkt0 = binary.BigEndian.AppendUint16(pkt0, 0)
	if err := t.send(pkt0); err != nil {
		return
	}

	var block uint16 = 1
	var acc []byte
	for {
		var reply []byte
		var ok bool
		for attempt := 0; attempt < t.srv.retries; attempt++ {
			var rerr error
			reply, rerr = t.recv()
			if rerr == nil {
				ok = true
				break
			}
			// re-ACK the last block so the client goes on
			ack := binary.BigEndian.AppendUint16(nil, tftpOpACK)
			ack = binary.BigEndian.AppendUint16(ack, block-1)
			_ = t.send(ack)
		}
		if !ok {
			return
		}
		if len(reply) >= 4 && binary.BigEndian.Uint16(reply[:2]) == tftpOpError {
			return
		}
		if len(reply) < 4 || binary.BigEndian.Uint16(reply[:2]) != tftpOpDATA ||
			binary.BigEndian.Uint16(reply[2:4]) != block {
			// duplicate or junk: re-ACK what we last acked
			ack := binary.BigEndian.AppendUint16(nil, tftpOpACK)
			ack = binary.BigEndian.AppendUint16(ack, block-1)
			_ = t.send(ack)
			continue
		}
		acc = append(acc, reply[4:]...)
		ack := binary.BigEndian.AppendUint16(nil, tftpOpACK)
		ack = binary.BigEndian.AppendUint16(ack, block)
		if err := t.send(ack); err != nil {
			return
		}
		if len(reply) < 4+tftpBlockSize {
			break
		}
		block++
	}

	if err := t.srv.store.Put(t.file, acc); err != nil {
		return
	}
	if t.srv.onTransfer != nil {
		t.srv.onTransfer(TFTPEvent{Kind: "put", File: t.file, Data: acc, Addr: t.raddr})
	}
}

func (t *tftpSession) send(pkt []byte) error {
	if err := t.conn.SetWriteDeadline(time.Now().Add(t.srv.timeout)); err != nil {
		return err
	}
	_, err := t.conn.Write(pkt)
	return err
}

func (t *tftpSession) recv() ([]byte, error) {
	if err := t.conn.SetReadDeadline(time.Now().Add(t.srv.timeout)); err != nil {
		return nil, err
	}
	buf := make([]byte, tftpBlockSize+64)
	n, rerr := t.conn.Read(buf)
	if rerr != nil {
		if netErr, ok := rerr.(net.Error); ok && netErr.Timeout() {
			return nil, rerr
		}
		return nil, rerr
	}
	return buf[:n], nil
}

func (t *tftpSession) sendError(code uint16, msg string) {
	pkt := binary.BigEndian.AppendUint16(nil, tftpOpError)
	pkt = binary.BigEndian.AppendUint16(pkt, code)
	pkt = append(pkt, msg...)
	pkt = append(pkt, 0x00)
	_ = t.send(pkt)
	_, _ = t.recv()
}

// tftpFileName extracts the filename field of an RRQ/WRQ.
func tftpFileName(pkt []byte) (string, bool) {
	if len(pkt) < 2 {
		return "", false
	}
	rest := pkt[2:]
	end := -1
	for i, b := range rest {
		if b == 0 {
			end = i
			break
		}
	}
	if end < 0 {
		return "", false
	}
	return string(rest[:end]), true
}

func minInt2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
