package fastpath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Minimal RFC1350 TFTP client (octet mode only, netascii-agnostic since
// the switch's config files are plain ASCII either way).
//
// This exists for the FASTPATH/Smart-Managed switch family
// (GS108Tv2/GS110TPv2-class firmware, port 69), NOT for the Plus line:
// the firmware serves nvram files over TFTP ("copy <url>
// nvram:startup-config", nvram read/write machinery at `tftp_server.c`,
// `/tmp/tftp` in switchdrvr.bin), which is the config-file channel for
// saving and restoring model configuration.
//
// Wire notes (RFC1350):
//   opcode 1 RRQ: {01, filename, 00, mode, 00}
//   opcode 2 WRQ: {02, filename, 00, mode, 00}
//   opcode 3 DATA: {03, block# (1-based), up to 512 bytes}
//   opcode 4 ACK:  {04, block#}
//   opcode 5 ERROR: {05, code, msg, 00}
// A DATA block shorter than 512 bytes ends the transfer; a zero-length
// final block is still required when the file size is a multiple of
// 512 (the server sends the empty terminator).
// ---------------------------------------------------------------------------

const (
	tftpOpRRQ   uint16 = 1
	tftpOpWRQ   uint16 = 2
	tftpOpDATA  uint16 = 3
	tftpOpACK   uint16 = 4
	tftpOpError uint16 = 5

	tftpBlockSize = 512
)

// TFTPConfig tunes the client. Zero values are usable.
type TFTPConfig struct {
	// Timeout is the per-packet response window. Zero = 1s.
	Timeout time.Duration
	// Retries is the per-block retransmission budget. Zero = 5.
	Retries int
}

// ErrTFTPRemoteError wraps a TFTP ERROR packet from the peer.
type ErrTFTPRemoteError struct {
	Code    uint16
	Message string
}

func (e *ErrTFTPRemoteError) Error() string {
	return fmt.Sprintf("tftp: remote error %d: %s", e.Code, e.Message)
}

// TFTPGet fetches file from a TFTP server at addr ("10.0.2.8:69") and
// returns its bytes. It binds an ephemeral UDP port (bidirectional
// windows are NOT used: the classic lockstep protocol ports are spoken,
// which the FASTPATH server implements).
func TFTPGet(addr, file string, cfg TFTPConfig) ([]byte, error) {
	conn, err := tftpDialTuned(addr, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := tftpSend(conn, tftpPacket(tftpOpRRQ, file)); err != nil {
		return nil, err
	}

	var out []byte
	var nextBlock uint16 = 1
	for {
		pkt, err := tftpRecv(conn, cfg)
		if err != nil {
			return nil, err
		}
		op, block, payload, err := tftpParseData(pkt, nextBlock)
		if err != nil {
			return nil, err
		}
		_ = op
		// ACK whatever arrived — including a re-sent earlier block
		// (duplicate) or the promised next block; the server resumes
		// per the ACK's block number.
		if err := tftpSend(conn, tftpPacketACK(block)); err != nil {
			return nil, err
		}
		if block != nextBlock {
			continue // duplicate of an already-acknowledged block
		}
		out = append(out, payload...)
		if len(payload) < tftpBlockSize {
			return out, nil
		}
		nextBlock++
	}
}

// TFTPFileNameGet is TFTPGet with the default port applied so callers
// can pass a bare switch IP.
func TFTPFileNameGet(serverHost, file string, cfg TFTPConfig) ([]byte, error) {
	if _, _, err := net.SplitHostPort(serverHost); err != nil {
		serverHost = net.JoinHostPort(serverHost, "69")
	}
	return TFTPGet(serverHost, file, cfg)
}

// TFTPPut uploads file to the TFTP server at addr. The config-file
// upload path (writing a text config to the switch) uses this; the
// firmware's cliTxtCfg machinery validates the file content when the
// copy is committed.
func TFTPPut(addr, file string, data []byte, cfg TFTPConfig) error {
	conn, err := tftpDialTuned(addr, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := tftpSend(conn, tftpPacket(tftpOpWRQ, file)); err != nil {
		return err
	}

	// WRQ is acknowledged with ACK{block 0} before DATA 1 flows.
	ack0, err := tftpRecv(conn, cfg)
	if err != nil {
		return err
	}
	if op, blk := tftpParseACK(ack0); op == tftpOpError {
		return decodeError(ack0)
	} else if op != tftpOpACK || blk != 0 {
		return fmt.Errorf("tftp: want ACK 0 for WRQ, got opcode %d block %d", op, blk)
	}

	var blockIdx uint16 = 1
	for offset := 0; ; offset += tftpBlockSize {
		end := offset + tftpBlockSize
		var chunk []byte
		if end >= len(data) {
			chunk = data[offset:]
		} else {
			chunk = data[offset:end]
		}
		for attempt := 0; attempt < retries(cfg); attempt++ {
			pkt := binary.BigEndian.AppendUint16(nil, tftpOpDATA)
			pkt = binary.BigEndian.AppendUint16(pkt, blockIdx)
			pkt = append(pkt, chunk...)
			if err := tftpSend(conn, pkt); err != nil {
				return err
			}
			// The FASTPATH server ACKs the FINAL, possibly empty
			// block — keep the lockstep regardless of size.
			reply, err := tftpRecv(conn, cfg)
			if err != nil {
				if attempt+1 < retries(cfg) {
					continue
				}
				return err
			}
			op, blk := tftpParseACK(reply)
			if op == tftpOpError {
				return decodeError(reply)
			}
			if op == tftpOpACK && blk == blockIdx {
				goto accepted
			}
			continue
		}
		return fmt.Errorf("tftp: no ACK for block %d after %d retries", blockIdx, retries(cfg))
	accepted:
		if len(chunk) < tftpBlockSize {
			return nil
		}
		blockIdx++
	}
}

func retries(cfg TFTPConfig) int {
	if cfg.Retries <= 0 {
		return 5
	}
	return cfg.Retries
}

func tftpDialTuned(addr string, cfg TFTPConfig) (*net.UDPConn, error) {
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("tftp: resolve %s: %w", addr, err)
	}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("tftp: connect %s: %w", addr, err)
	}
	return conn, nil
}

// tftpWait is the per-packet response window: cfg.Timeout or 1s.
func tftpWait(cfg TFTPConfig) time.Duration {
	if cfg.Timeout <= 0 {
		return time.Second
	}
	return cfg.Timeout
}

func tftpSend(conn *net.UDPConn, pkt []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(tftpWait(TFTPConfig{}))); err != nil {
		return fmt.Errorf("tftp: set write deadline: %w", err)
	}
	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("tftp: send: %w", err)
	}
	return nil
}

func tftpRecv(conn *net.UDPConn, cfg TFTPConfig) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(tftpWait(cfg))); err != nil {
		return nil, fmt.Errorf("tftp: set read deadline: %w", err)
	}
	buf := make([]byte, tftpBlockSize+32)
	n, err := conn.Read(buf)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, errors.New("tftp: no reply within the per-request window")
		}
		return nil, fmt.Errorf("tftp: recv: %w", err)
	}
	return buf[:n], nil
}

// tftpPacket builds an RRQ/WRQ: {op, name, 00, "octet", 00}.
func tftpPacket(op uint16, file string) []byte {
	pkt := binary.BigEndian.AppendUint16(nil, op)
	pkt = append(pkt, file...)
	pkt = append(pkt, 0x00)
	pkt = append(pkt, "octet"...)
	pkt = append(pkt, 0x00)
	return pkt
}

func tftpPacketACK(block uint16) []byte {
	pkt := binary.BigEndian.AppendUint16(nil, tftpOpACK)
	return binary.BigEndian.AppendUint16(pkt, block)
}

func tftpParseData(pkt []byte, wantBlock uint16) (uint16, uint16, []byte, error) {
	if len(pkt) < 4 {
		return 0, 0, nil, &ErrTFTPRemoteError{Code: 0, Message: "short packet"}
	}
	op := binary.BigEndian.Uint16(pkt[:2])
	if op == tftpOpError {
		return 0, 0, nil, decodeError(pkt)
	}
	if op != tftpOpDATA {
		return op, 0, nil, fmt.Errorf("tftp: want DATA, got opcode %d", op)
	}
	block := binary.BigEndian.Uint16(pkt[2:4])
	if block != wantBlock {
		// Caller decides what a duplicate means; report faithfully.
		return op, block, pkt[4:], nil
	}
	return op, block, pkt[4:], nil
}

func tftpParseACK(pkt []byte) (uint16, uint16) {
	if len(pkt) < 4 {
		return 0, 0
	}
	return binary.BigEndian.Uint16(pkt[:2]), binary.BigEndian.Uint16(pkt[2:4])
}

func decodeError(pkt []byte) error {
	if len(pkt) < 4 {
		return &ErrTFTPRemoteError{Code: 0, Message: "short error packet"}
	}
	code := binary.BigEndian.Uint16(pkt[2:4])
	msg := ""
	if len(pkt) > 4 {
		// Trimmed at the first NUL; ASCII message per RFC1350.
		msg = strings.TrimRight(string(pkt[4:]), "\x00")
	}
	return &ErrTFTPRemoteError{Code: code, Message: msg}
}
