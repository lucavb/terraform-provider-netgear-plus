package nsdp

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// SwitchIdentity is the identity surface for the switch data source —
// everything the provider needs to describe a switch over pure NSDP, no
// HTTP session. All fields come from GETs only (no login required).
//
// Bootloader version has NO NSDP source: no known tag carries it (the
// web UI reads it from its own firmware page). It is expected absent; a
// data source must leave it empty rather than fail the read.
type SwitchIdentity struct {
	// ProductName is the model string (tag 0x0001), e.g. "GS108Ev3".
	ProductName string
	// ModelCode is the BE16 model code (tag 0x0002).
	ModelCode uint16
	// FirmwareVersion is the firmware string: tag 0x000d (primary) with
	// tag 0x000e as the fallback when 0x000d is absent or empty.
	FirmwareVersion string
	// SerialNumber is the switch serial (block 0x78, tag 0x7800): a
	// 21-byte blob whose embedded ASCII serial is extracted with
	// trailing NULs and spaces trimmed.
	SerialNumber string
	// SystemName is the configured system name (tag 0x0003).
	SystemName string
}

// GetIdentity reads the switch identity: one multi-tag GET for the small
// tags (product name 0x0001, model code 0x0002, system name 0x0003,
// firmware 0x000d/0x000e) plus one block read for the serial number
// (block 0x78, tag 0x7800). Absent reply TLVs decode as zero values
// (the switch decides what it answers); transport failures return an
// error.
func (c *Client) GetIdentity() (SwitchIdentity, error) {
	attrs, err := c.GetAttrs(
		byte(TagProductName),
		byte(TagModelCode),
		byte(TagSystemName),
		byte(TagFirmware1),
		byte(TagFirmware2),
	)
	if err != nil {
		return SwitchIdentity{}, fmt.Errorf("nsdp: read identity tags: %w", err)
	}
	var id SwitchIdentity
	if v, ok := attrs[byte(TagProductName)]; ok {
		id.ProductName = asciiTrim(v)
	}
	if v, ok := attrs[byte(TagModelCode)]; ok && len(v) == 2 {
		id.ModelCode = binary.BigEndian.Uint16(v)
	}
	if v, ok := attrs[byte(TagSystemName)]; ok {
		id.SystemName = asciiTrim(v)
	}
	if fw, ok := attrs[byte(TagFirmware1)]; ok && asciiTrim(fw) != "" {
		id.FirmwareVersion = asciiTrim(fw)
	} else if fw, ok := attrs[byte(TagFirmware2)]; ok && asciiTrim(fw) != "" {
		id.FirmwareVersion = asciiTrim(fw)
	}
	serial, err := c.GetBlock(0x78, nil)
	if err != nil {
		return SwitchIdentity{}, fmt.Errorf("nsdp: read serial number (block 0x78): %w", err)
	}
	for _, a := range serial {
		if a.Tag == TagSerialNumber {
			id.SerialNumber = serialFromBlob(a.Value)
		}
	}
	return id, nil
}

// serialFromBlob extracts the serial number from a tag-0x7800 value.
//
// Live GS108Ev3 layout (ROUND 11, 21 bytes): {0x01, 0x33, 12-char ASCII
// serial, 0x00, trailing RAM garbage} — the serial is pinned at
// v[2:14], with trailing NULs/spaces inside the window trimmed (the
// 0x33 prefix byte is ASCII '3', so a naive whole-blob parse would
// swallow it into the serial). Values that do not fit that layout fall
// back to the longest printable-ASCII run of at least 8 bytes
// (mirroring the nsdpctl serial renderer). Both paths trim trailing
// NULs and spaces.
func serialFromBlob(v []byte) string {
	if len(v) >= 14 {
		if s := trimSerial(v[2:14]); s != "" && isPrintableASCII([]byte(s)) {
			return s
		}
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
		return ""
	}
	return trimSerial(v[bestStart : bestStart+bestLen])
}

// trimSerial renders the extracted serial with trailing NULs and spaces
// removed.
func trimSerial(b []byte) string {
	return strings.TrimRight(string(b), "\x00 ")
}

// isPrintableASCII reports whether every byte is printable ASCII
// (0x20-0x7e).
func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
