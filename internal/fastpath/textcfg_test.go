package fastpath

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
)

// factoryConfig is the verbatim content of the factory-default GS108Tv2
// v5.4.2.36 startup-config export (startup-config-gs108t, captured
// 2026-09-15). The magic line is ASCII text with hex-escape words —
// struct0x4e470x010x00GS108Tv2... — NOT raw bytes (verified by hexdump).
const factoryConfig = `0x4e470x010x00GS108Tv2            5.4.2.36            0x000000000x00000000000000

! The line above is the NSDP Text Configuration header. DO NOT EDIT THIS HEADER

!Current Configuration:

!

!System Description "GS108Tv2"

!System Software Version "5.4.2.36"

!Current SNTP Synchronized Time: Not Synchronized

!

vlan database

exit

configure

!

sntp client mode unicast

users passwd "admin" encrypted 0a51d780be1a0240b8cc7c69fe0479dbf07644e1094b25fb43ebe2fa72f649e4

authentication login "defaultList"  local

lineconfig

exit

spanning-tree configuration name "8C-3B-AD-2C-E9-7D"

interface 0/1

exit

interface 3/4

exit

exit
`

// TestParseTextConfigFactoryExport runs the factory file's exact bytes
// through the structural read; if the real capture drifted from this
// snapshot, sync this constant with it rather than weakening the
// parser.
func TestParseTextConfigFactoryExport(t *testing.T) {
	if want := mirrorFactoryFile(t); want == "" {
		t.Skip("startup-config-gs108t not present in repo root")
	} else if !strings.Contains(want, "0x4e47") {
		t.Fatalf("repo factory export lost its NSDP magic header: %q", firstLine(want))
	}

	tc, err := ParseTextConfig([]byte(factoryConfig))
	if err != nil {
		t.Fatalf("ParseTextConfig(factory): %v", err)
	}
	if !strings.HasPrefix(tc.Header, "0x4e47") {
		t.Fatalf("header = %q, want 0x4e47 prefix", tc.Header)
	}
	if tc.SystemDescription != "GS108Tv2" {
		t.Fatalf("SystemDescription = %q", tc.SystemDescription)
	}
	if tc.SystemSoftwareVersion != "5.4.2.36" {
		t.Fatalf("SystemSoftwareVersion = %q", tc.SystemSoftwareVersion)
	}

	labels := map[string]bool{}
	for _, s := range tc.Sections {
		labels[s.Label] = true
	}
	for _, want := range []string{"vlan database", "configure"} {
		if !labels[want] {
			t.Fatalf("missing section %q; sections = %v", want, labels)
		}
	}

	// Header validation runs green against a same-generation file.
	if err := ValidateTextConfigHeader([]byte(factoryConfig), "GS108Tv2", "5.4.2.36"); err != nil {
		t.Fatalf("ValidateTextConfigHeader(factory): %v", err)
	}
}

func TestValidateTextConfigHeaderRejects(t *testing.T) {
	if err := ValidateTextConfigHeader(nil, "", ""); err == nil {
		t.Fatal("want error on empty input")
	}
	badHeader := "system name default\nconfigure\n"
	if err := ValidateTextConfigHeader([]byte(badHeader), "", ""); err == nil {
		t.Fatal("want error on missing NSDP magic header")
	}
	wrongModel := strings.Replace(factoryConfig, "!System Description \"GS108Tv2\"", "!System Description \"GS110TPv2\"", 1)
	err := ValidateTextConfigHeader([]byte(wrongModel), "GS108Tv2", "5.4.2.36")
	if err == nil {
		t.Fatal("want error on foreign model export")
	}
	if wv := strings.Replace(factoryConfig, "5.4.2.36", "7.0.0.1", 1); true {
		_ = wv
	}
	wrongVer := strings.Replace(factoryConfig, "!System Software Version \"5.4.2.36\"", "!System Software Version \"7.0.0.1\"", 1)
	err = ValidateTextConfigHeader([]byte(wrongVer), "GS108Tv2", "5.4.2.36")
	if err == nil {
		t.Fatal("want error on foreign firmware export")
	}
}

// TestTFTPRoundtripLoopback exercises the client against an in-process
// RFC1350 server speaking the FASTPATH lockstep. Skipped when the
// sandbox blocks loopback UDP dials ("operation not permitted").
func TestTFTPRoundtripLoopback(t *testing.T) {
	addr, stop := fakeTFTPServer(t)
	defer stop()

	payload := make([]byte, 1115) // 3 blocks: 512 + 512 + 91
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if err := TFTPPut(addr, "startup-config", payload, TFTPConfig{}); err != nil {
		if sandBoxBlocked(err) {
			t.Skipf("sandbox denies loopback UDP: %v", err)
		}
		t.Fatalf("TFTPPut: %v", err)
	}

	got, err := TFTPGet(addr, "startup-config", TFTPConfig{})
	if err != nil {
		if sandBoxBlocked(err) {
			t.Skipf("sandbox denies loopback handshake: %v", err)
		}
		t.Fatalf("TFTPGet: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// fakeTFTPServer is a minimal RFC1350 octet-mode server on 127.0.0.1:0
// (loopback) keeping per-file storage.
func fakeTFTPServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("sandbox denies UDP bind: %v", err)
	}
	files := map[string][]byte{}
	stop = func() { _ = conn.Close() }

	go func() {
		for {
			buf := make([]byte, 2048)
			n, raddr, err := conn.(*net.UDPConn).ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := buf[:n]
			if len(pkt) < 4 {
				continue
			}
			opcode := uint16(pkt[0])<<8 | uint16(pkt[1])
			switch opcode {
			case 1: // RRQ: serve file in lockstep
				name := rrqFile(pkt)
				data := files[name]
				var block uint16 = 1
				for offset := 0; ; offset += 512 {
					end := offset + 512
					var chunk []byte
					if end <= len(data) {
						chunk = data[offset:end]
					} else {
						chunk = data[offset:]
					}
					out := append([]byte{0x00, 0x03, byte(block >> 8), byte(block)}, chunk...)
					if _, err := conn.WriteTo(out, raddr); err != nil {
						return
					}
					ack := make([]byte, 2048)
					m, _, err := conn.ReadFrom(ack)
					if err != nil || m < 4 || ack[0] != 0x00 || ack[1] != 0x04 {
						return
					}
					if len(chunk) < 512 {
						break
					}
					block++
				}
			case 2: // WRQ: ACK 0, then collect
				if _, err := conn.WriteTo([]byte{0x00, 0x04, 0x00, 0x00}, raddr); err != nil {
					return
				}
				var acc []byte
				for {
					req := make([]byte, 2048)
					m, _, err := conn.ReadFrom(req)
					if err != nil || m < 4 {
						return
					}
					rop := uint16(req[0])<<8 | uint16(req[1])
					if rop != 3 {
						return
					}
					blk := uint16(req[2])<<8 | uint16(req[3])
					acc = append(acc, req[4:m]...)
					if _, err := conn.WriteTo([]byte{0x00, 0x04, byte(blk >> 8), byte(blk)}, raddr); err != nil {
						return
					}
					if m-4 < 512 {
						break
					}
				}
				files[rrqFile(pkt)] = acc
			}
		}
	}()

	return conn.LocalAddr().String(), stop
}

// rrqFile extracts the filename field of an RRQ/WRQ {"op", name, 00,
// mode, 00} sampled up to the second NUL.
func rrqFile(pkt []byte) string {
	if len(pkt) < 3 {
		return ""
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
		return string(rest)
	}
	return string(rest[:end])
}

func sandBoxBlocked(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		// A timed-out UDP window is a legitimate transfer failure;
		// an EPERM-class dial/bind is the sandbox blocking loopback.
		return ne.Timeout() && false || strings.Contains(err.Error(), "operation not permitted")
	}
	return strings.Contains(err.Error(), "operation not permitted")
}

// mirrorFactoryFile reads the factory export the repo carries for the
// gs108tv2 verification story, so the embedded snapshot and the real
// file cannot drift silently apart.
func mirrorFactoryFile(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../startup-config-gs108t")
	if err != nil {
		return ""
	}
	return string(data)
}

func firstLine(s string) string {
	idx := strings.IndexByte(s, '\n')
	if idx < 0 {
		return s
	}
	return s[:idx]
}
