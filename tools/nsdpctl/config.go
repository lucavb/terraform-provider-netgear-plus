package main

// The read/dump subcommands (dump/get/block) and the raw write escape
// hatch (set-raw), built on the internal/nsdp typed read layer. Read-only
// paths use GETs exclusively; set-raw is the ONLY write and prints a
// warning before sending anything.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// cmdDump prints a typed config dump: small tags (one multi-tag GET batch)
// plus one block request each for the default block list. Failing blocks
// print a warning and the dump continues. GETs only — no login.
func cmdDump(iface, agent string, verbose bool) error {
	var v io.Writer
	if verbose {
		v = os.Stderr
	}
	c, err := newClient(iface, agent, "", v)
	if err != nil {
		return err
	}
	defer c.Close()
	if agent == "" {
		fmt.Fprintln(os.Stderr, "note: no -agent-mac set — broadcasting; replies from multiple switches may interleave. Use -agent-mac for reliable single-switch results.")
	}
	res, err := c.Dump()
	if err != nil {
		return err
	}
	fmt.Println("small tags:")
	for _, a := range res.Attrs {
		fmt.Println("  " + attrLine(a))
	}
	for _, b := range res.Blocks {
		if b.Err != nil {
			fmt.Fprintf(os.Stderr, "warning: block 0x%02x00: %v (dump continues)\n", b.BlockID, b.Err)
			continue
		}
		fmt.Printf("block 0x%02x00:\n", b.BlockID)
		for _, a := range b.Attrs {
			fmt.Println("  " + attrLine(a))
		}
	}
	return nil
}

// cmdGet performs a raw multi-tag GET and prints the parsed TLVs: small
// tags (<0x100) go out as ONE multi-tag request; family tags (0xNN00) are
// read as one block request each — the block form is the only live-proven
// read form for them (ROUND 6 block↔tag unification).
func cmdGet(iface, agent string, verbose bool, args []string) error {
	var small []byte
	var family []uint16
	for _, s := range args {
		t, err := parseHexUint16(s)
		if err != nil {
			return fmt.Errorf("bad tag %q: %w", s, err)
		}
		switch {
		case t < 0x100:
			small = append(small, byte(t))
		case t&0xff == 0:
			family = append(family, t)
		default:
			return fmt.Errorf("tag 0x%04x: want a small tag (<0x100) or a family tag 0xNN00", t)
		}
	}
	var v io.Writer
	if verbose {
		v = os.Stderr
	}
	c, err := newClient(iface, agent, "", v)
	if err != nil {
		return err
	}
	defer c.Close()
	if len(small) > 0 {
		m, err := c.GetAttrs(small...)
		if err != nil {
			return fmt.Errorf("GET small tags: %w", err)
		}
		for _, t := range small {
			if val, ok := m[t]; ok {
				fmt.Println(attrLine(nsdp.DecodeTLV(nsdp.TLV{Tag: uint16(t), Value: val})))
			} else {
				fmt.Printf("0x%02x    %-34s (no reply TLV)\n", t, "?")
			}
		}
	}
	for _, t := range family {
		attrs, err := c.GetBlock(byte(t>>8), nil)
		if err != nil {
			return fmt.Errorf("GET 0x%04x: %w", t, err)
		}
		fmt.Printf("block 0x%04x:\n", t)
		printAttrs(attrs)
	}
	return nil
}

// cmdBlock performs one raw block GET: block <idhex> [selhexbytes], with
// the optional selector riding as the block TLV's value (e.g. ff ff for
// "all groups" style selectors).
func cmdBlock(iface, agent string, verbose bool, args []string) error {
	id, err := parseHexUint16(args[0])
	if err != nil || id > 0xff {
		return fmt.Errorf("bad block id %q: want a hex byte like 78", args[0])
	}
	var selector []byte
	if len(args) > 1 {
		if selector, err = parseHexBytes(args[1:]); err != nil {
			return fmt.Errorf("bad selector: %w", err)
		}
	}
	var v io.Writer
	if verbose {
		v = os.Stderr
	}
	c, err := newClient(iface, agent, "", v)
	if err != nil {
		return err
	}
	defer c.Close()
	attrs, err := c.GetBlock(byte(id), selector)
	if err != nil {
		return fmt.Errorf("GET block 0x%02x00: %w", id, err)
	}
	fmt.Printf("block 0x%02x00:\n", id)
	printAttrs(attrs)
	return nil
}

// cmdSetRaw is the live-lab escape hatch: auto-Login, then ONE SET with
// the session auth TLV followed by the user TLV, print the reply status,
// then read the tag back via GET and compare.
func cmdSetRaw(iface, agent, password, tagHex string, valueHex string, verbose bool) error {
	if agent == "" {
		return errors.New("set-raw requires -agent-mac: the login token is derived from the switch MAC")
	}
	if password == "" {
		return errors.New("set-raw requires -password: every CMD_SET_REQUEST must follow the NSDP LOGIN handshake")
	}
	tag, err := parseHexUint16(tagHex)
	if err != nil {
		return fmt.Errorf("bad tag %q: %w", tagHex, err)
	}
	value, err := parseHexBytes([]string{valueHex})
	if err != nil {
		return fmt.Errorf("bad value %q: %w", valueHex, err)
	}
	warnLockout()
	fmt.Fprintln(os.Stderr, "WARNING: set-raw WRITES to the switch (auth TLV + raw TLV); wrong bytes can misconfigure it — layouts like 0x8800 and the per-port 0x2800 forms remain UNVERIFIED.")
	var v io.Writer
	if verbose {
		v = os.Stdout
	}
	c, err := newClient(iface, agent, password, v)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := c.SetRaw(tag, value); err != nil {
		return err
	}
	fmt.Printf("SET raw 0x%04x: reply status 0x00 (ok)\n", tag)

	// Read the tag back and compare against what we sent.
	fmt.Println("read-back:")
	readBack, err := readBackValue(c, tag)
	switch {
	case err != nil:
		return fmt.Errorf("read back 0x%04x: %w", tag, err)
	case readBack == nil:
		fmt.Printf("  (reply carries no TLV 0x%04x)\n", tag)
	case bytes.Equal(readBack, value):
		fmt.Printf("  %s\n  read-back matches the written value\n", attrLine(nsdp.DecodeTLV(nsdp.TLV{Tag: tag, Value: readBack})))
	default:
		fmt.Printf("  %s\n  note: read-back differs from the written value (% x)\n", attrLine(nsdp.DecodeTLV(nsdp.TLV{Tag: tag, Value: readBack})), value)
	}
	return nil
}

// readBackValue GETs one tag's current value: small tags via a direct
// GET, family tags via their block read. A nil, nil return means the
// switch replied without the TLV.
func readBackValue(c *nsdp.Client, tag uint16) ([]byte, error) {
	if tag < 0x100 {
		return c.GetAttr(byte(tag))
	}
	attrs, err := c.GetBlock(byte(tag>>8), nil)
	if err != nil {
		return nil, err
	}
	for _, t := range attrs {
		if t.Tag == tag {
			return t.Value, nil
		}
	}
	return nil, nil
}

// printAttrs prints decoded attrs, or an explicit empty notice.
func printAttrs(attrs []nsdp.Attr) {
	if len(attrs) == 0 {
		fmt.Println("  (reply carries no TLVs)")
		return
	}
	for _, a := range attrs {
		fmt.Println("  " + attrLine(a))
	}
}

// attrLine renders one decoded attr as a table row: tag, name, length,
// typed value (hex fallback), and a bracketed decode note when present.
func attrLine(a nsdp.Attr) string {
	name := a.Name
	if name == "" {
		name = "?"
	}
	line := fmt.Sprintf("0x%04x  %-34s len %-3d  %s", a.Tag, name, len(a.Value), renderValue(a))
	if a.Note != "" {
		line += "  [" + a.Note + "]"
	}
	return line
}

// renderValue renders the typed decode, falling back to hex for raw or
// unknown values. Three tags get bespoke blob renders keyed on the tag
// itself (the library only decodes them as best-effort strings): 0x0011
// is a nested-TLV login blob, 0x0012 carries the same composite without
// its {0x0014} envelope (or is empty), 0x7800 is a serial-number blob.
func renderValue(a nsdp.Attr) string {
	switch a.Tag {
	case nsdp.TagString0011:
		if s, ok := renderLoginBlob(a.Value); ok {
			return s
		}
	case nsdp.TagScalar0012:
		// Live replies carry 0x0012 either empty (a bare dangling tag
		// the firmware never fills — ROUND 13) or as the same nested
		// capability+nonce composite seen inside 0x0011, minus its
		// leading {0x0014} envelope. Synthesize the envelope and reuse
		// the 0x0011 blob renderer; anything shorter than the minimal
		// composite ({0x0014 len 4 + 4B} + {0x0017 len 4 + 4B} = 16
		// bytes) falls through to the typed decode (an empty value
		// renders as "").
		if len(a.Value) >= 16 {
			if s, ok := renderLoginBlob(append([]byte{0x00, 0x14}, a.Value...)); ok {
				return s
			}
		}
	case nsdp.TagSerialNumber:
		if s, ok := renderSerialBlob(a.Value); ok {
			return s
		}
		return fmt.Sprintf("% x", a.Value) // no printable run — raw hex
	}
	switch d := a.Decoded.(type) {
	case string:
		return strconv.Quote(d)
	case uint8:
		return fmt.Sprintf("%d", d)
	case uint16:
		return fmt.Sprintf("%d (0x%04x)", d, d)
	case uint32:
		return fmt.Sprintf("%d (0x%08x)", d, d)
	case net.IP:
		return d.String()
	case net.HardwareAddr:
		return d.String()
	case nsdp.BE16Array:
		return fmt.Sprintf("prefix=%d entries=%v", d.Prefix, d.Entries)
	case nsdp.BE16Pair:
		return fmt.Sprintf("(%d, %d)", d.First, d.Second)
	case nsdp.BE32PlusU8:
		return fmt.Sprintf("%d (0x%08x) +0x%02x", d.Value, d.Value, d.Extra)
	case nsdp.DHCPMode:
		return d.String()
	case nsdp.VLANEngineMode:
		return d.String()
	case nsdp.QoSMode:
		return d.String()
	case nsdp.BandwidthEntry:
		return fmt.Sprintf("port %d: limit=%d", d.Port, d.Limit)
	case nsdp.IGMPConfig:
		return fmt.Sprintf("enabled=%v vlan=%d", d.Enabled, d.VLANID)
	case nsdp.PortMirrorConfig:
		return fmt.Sprintf("dst=%d src-ports=0x%02x reserved=0x%02x", d.DstPort, d.SrcPorts, d.Reserved)
	case []nsdp.PortEntry:
		parts := make([]string, len(d))
		for i, e := range d {
			parts[i] = fmt.Sprintf("port %d: %d", e.Port, e.Value)
		}
		return strings.Join(parts, ", ")
	case []nsdp.SpeedLinkStatus:
		parts := make([]string, len(d))
		for i, e := range d {
			parts[i] = fmt.Sprintf("port %d: speed=%d flow=%d", e.Port, e.Speed, e.Flow)
		}
		return strings.Join(parts, ", ")
	case []nsdp.PortAdminStatusEntry:
		parts := make([]string, len(d))
		for i, e := range d {
			parts[i] = fmt.Sprintf("port %d: admin=%d flow=%d", e.Port, e.Admin, e.Flow)
		}
		return strings.Join(parts, ", ")
	case []nsdp.PortBasedVLANEntry:
		parts := make([]string, len(d))
		for i, e := range d {
			parts[i] = fmt.Sprintf("vlan %d: ports=0x%02x", e.VLANID, e.Ports)
		}
		return strings.Join(parts, ", ")
	case []nsdp.PVIDEntry:
		parts := make([]string, len(d))
		for i, e := range d {
			parts[i] = fmt.Sprintf("port %d: pvid=%d", e.Port, e.VLANID)
		}
		return strings.Join(parts, ", ")
	case []nsdp.PortQoSEntry:
		parts := make([]string, len(d))
		for i, e := range d {
			parts[i] = fmt.Sprintf("port %d: priority=%s", e.Port, e.Priority)
		}
		return strings.Join(parts, ", ")
	case []nsdp.PortTrafficStats:
		parts := make([]string, len(d))
		for i, e := range d {
			parts[i] = fmt.Sprintf("port %d: rx=%d tx=%d pkt=%d bcst=%d mcst=%d err=%d",
				e.Port, e.Received, e.Sent, e.Packets, e.Broadcast, e.Multicast, e.Errors)
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprintf("% x", a.Value) // raw hex fallback
}

// renderLoginBlob renders a tag-0x0011 value: a NESTED TLV stream in the
// same {tag BE16, len BE16, value} wire form as the reply TLV region. The
// walk is inline because nsdp.WalkTLVs expects a full NSDP packet and starts
// 32 bytes in, so it cannot walk a bare TLV blob. The live GS108Ev3 sends
// {0x0014: BE32 capability, 0x0017: current login nonce} plus trailing
// bytes (ROUND 12b suspects {00 12}) — unknown nested TLVs and any bytes
// left after the walk are printed so live protocol oddities stay visible.
// ok=false when the value does not parse as that blob (the caller falls
// back to the plain string decode).
func renderLoginBlob(v []byte) (s string, ok bool) {
	var capability, nonce []byte
	var extra []string
	off := 0
	for off+4 <= len(v) {
		tag := binary.BigEndian.Uint16(v[off : off+2])
		if tag == 0xFFFF { // terminator — mirror WalkTLVs
			break
		}
		length := int(binary.BigEndian.Uint16(v[off+2 : off+4]))
		if off+4+length > len(v) {
			break // truncated mid-TLV: show the rest as trailing bytes
		}
		switch tag {
		case nsdp.TagCapabilityTag:
			capability = v[off+4 : off+4+length]
		case nsdp.TagNonceTag:
			nonce = v[off+4 : off+4+length]
		default:
			extra = append(extra, fmt.Sprintf("tlv 0x%04x=% x", tag, v[off+4:off+4+length]))
		}
		off += 4 + length
	}
	if len(capability) != 4 || len(nonce) != 4 {
		return "", false
	}
	s = fmt.Sprintf("login blob: capability=0x%08x nonce=% x",
		binary.BigEndian.Uint32(capability), nonce)
	for _, e := range extra {
		s += " [" + e + "]"
	}
	if rest := v[off:]; len(rest) > 0 {
		s += fmt.Sprintf(" trailing=% x", rest)
	}
	return s, true
}

// renderSerialBlob renders a tag-0x7800 serial-number blob: the live
// GS108Ev3 returns 21 bytes of {prefix bytes + ASCII serial + trailing
// garbage + NUL padding}. It extracts the longest printable-ASCII run
// (>= 8 bytes) and reports how many bytes remain after it. ok=false when
// no such run exists (the caller falls back to raw hex).
func renderSerialBlob(v []byte) (s string, ok bool) {
	// Live GS108Ev3 layout (ROUND 11): {0x01, 0x33, 12-char ASCII
	// serial, 0x00, trailing RAM garbage} — 21 bytes. Pin the serial to
	// v[2:14]; the printable-run fallback below would otherwise grab
	// the 0x33 prefix byte (ASCII '3') into the serial.
	if len(v) >= 14 && isPrintableASCII(v[2:14]) {
		s = fmt.Sprintf("serial %s", v[2:14])
		if rest := len(v) - 14; rest > 0 {
			s += fmt.Sprintf(" (+%d trailing bytes)", rest)
		}
		return s, true
	}
	bestStart, bestLen, runStart := -1, 0, -1
	for i, b := range v {
		if b >= 0x20 && b <= 0x7e {
			if runStart < 0 {
				runStart = i
			}
			if l := i - runStart + 1; l > bestLen {
				bestStart, bestLen = runStart, l
			}
		} else {
			runStart = -1
		}
	}
	if bestLen < 8 {
		return "", false
	}
	end := bestStart + bestLen
	s = fmt.Sprintf("serial %s", v[bestStart:end])
	if rest := len(v) - end; rest > 0 {
		s += fmt.Sprintf(" (+%d trailing bytes)", rest)
	}
	return s, true
}

// isPrintableASCII reports whether every byte is printable ASCII (0x20-0x7e).
func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// parseHexUint16 parses a hex tag/block id, tolerating a 0x prefix.
func parseHexUint16(s string) (uint16, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0X"), "0x")
	v, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return 0, fmt.Errorf("want hex like 03 or 7800, got %q", s)
	}
	return uint16(v), nil
}

// parseHexBytes joins hex tokens ("ff" "01" or "ff01") and decodes them to
// bytes; empty input yields nil.
func parseHexBytes(args []string) ([]byte, error) {
	var b strings.Builder
	for _, a := range args {
		t := strings.TrimPrefix(strings.TrimPrefix(a, "0X"), "0x")
		if t == "" {
			return nil, fmt.Errorf("empty hex token %q", a)
		}
		b.WriteString(t)
	}
	s := b.String()
	if s == "" {
		return nil, nil
	}
	if len(s)%2 != 0 {
		return nil, errors.New("odd hex digit count")
	}
	out, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return out, nil
}
