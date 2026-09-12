// Package cfg implements the parser for the FMv2 full-configuration backup
// format served by the GS108Ev3 web UI at /config_data.bin.
//
// The format is a reverse-engineered binary layout: an 8-byte header
// ("FMv2", big-endian payload length, big-endian checksum) followed by a
// sequence of tagged sections, each holding a NUL-terminated ASCII name and
// an opaque payload. The parser carries every section it finds and does not
// require any specific section names to be present.
package cfg

import (
	"encoding/binary"
	"fmt"
)

const (
	magic            = "FMv2"
	headerSize       = 8
	sectionHeader    = 4
	sectionTag       = 1
	checksumMod      = 65535
	sectionPVID      = "pvid"
	sectionVLAN      = "vlan"
	sectionEthConfig = "ethconfig"
	pvidDataLen      = 16
	pvidPortCount    = 8
	ethConfigDataLen = 13
	vlanHeaderLen    = 4
	vlanEntryLen     = 4
	portCount        = 8
)

// Section is a single named record from a configuration backup.
// Raw holds the complete name+NUL+data payload (the section's len bytes).
type Section struct {
	Name string
	Data []byte
	Raw  []byte
}

// Config is a parsed FMv2 configuration backup.
type Config struct {
	Checksum uint16
	Sections []Section
	Raw      []byte
}

// ParseConfig decodes an FMv2 configuration backup. It fails closed on any
// structural deviation: truncated input, bad magic, payload length mismatch,
// odd payload length, checksum mismatch, unexpected section tags, section
// length overruns, missing section name terminators, and trailing garbage.
func ParseConfig(data []byte) (*Config, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("cfg: truncated file: got %d bytes, need at least %d", len(data), headerSize)
	}

	if string(data[:len(magic)]) != magic {
		return nil, fmt.Errorf("cfg: bad magic %q, want %q", data[:len(magic)], magic)
	}

	payloadLen := int(binary.BigEndian.Uint16(data[4:6]))
	if payloadLen != len(data)-headerSize {
		return nil, fmt.Errorf("cfg: payload length %d does not match remaining file size %d", payloadLen, len(data)-headerSize)
	}

	payload := data[headerSize:]
	if len(payload)%2 != 0 {
		return nil, fmt.Errorf("cfg: odd payload length %d", len(payload))
	}

	stored := binary.BigEndian.Uint16(data[6:8])
	computed, err := Checksum(payload)
	if err != nil {
		return nil, fmt.Errorf("cfg: checksum: %w", err)
	}
	if computed != stored {
		return nil, fmt.Errorf("cfg: checksum mismatch: computed 0x%04X, stored 0x%04X", computed, stored)
	}

	sections, err := parseSections(payload)
	if err != nil {
		return nil, err
	}

	return &Config{
		Checksum: stored,
		Sections: sections,
		Raw:      data,
	}, nil
}

// Checksum computes the FMv2 payload checksum: the sum of 16-bit big-endian
// words over the payload, taken mod 65535. Odd-length payloads are rejected.
func Checksum(payload []byte) (uint16, error) {
	if len(payload)%2 != 0 {
		return 0, fmt.Errorf("odd payload length %d", len(payload))
	}

	var sum uint32
	for offset := 0; offset < len(payload); offset += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[offset:]))
	}

	return uint16(sum % checksumMod), nil
}

func parseSections(payload []byte) ([]Section, error) {
	var sections []Section

	for len(payload) > 0 {
		if len(payload) < sectionHeader {
			return nil, fmt.Errorf("cfg: trailing garbage: %d byte(s) after last section", len(payload))
		}

		tag := binary.BigEndian.Uint16(payload[0:2])
		if tag != sectionTag {
			return nil, fmt.Errorf("cfg: unexpected section tag %d, want %d", tag, sectionTag)
		}

		length := int(binary.BigEndian.Uint16(payload[2:4]))
		if length > len(payload)-sectionHeader {
			return nil, fmt.Errorf("cfg: section length %d overruns payload by %d byte(s)", length, length-(len(payload)-sectionHeader))
		}

		body := payload[sectionHeader : sectionHeader+length]
		name, data, err := splitSectionBody(body)
		if err != nil {
			return nil, err
		}

		sections = append(sections, Section{
			Name: name,
			Data: data,
			Raw:  body,
		})

		payload = payload[sectionHeader+length:]
	}

	return sections, nil
}

func splitSectionBody(body []byte) (string, []byte, error) {
	for idx, b := range body {
		if b != 0 {
			continue
		}

		name := string(body[:idx])
		rest := make([]byte, len(body)-idx-1)
		copy(rest, body[idx+1:])

		return name, rest, nil
	}

	return "", nil, fmt.Errorf("cfg: section payload %d byte(s) has no NUL-terminated name", len(body))
}

// Section returns the first section with the given name.
func (c *Config) Section(name string) (Section, bool) {
	for _, section := range c.Sections {
		if section.Name == name {
			return section, true
		}
	}
	return Section{}, false
}

// RawSection returns the raw bytes of the first section with the given name,
// as an opaque passthrough for byte-preserving synthesis.
func (c *Config) RawSection(name string) ([]byte, bool) {
	section, ok := c.Section(name)
	if !ok {
		return nil, false
	}
	return section.Raw, true
}

// PVIDs decodes the pvid section: exactly 16 bytes of 8 uint16 LE values,
// one PVID per port, ports 1..8 in order.
func (c *Config) PVIDs() ([]int, error) {
	section, ok := c.Section(sectionPVID)
	if !ok {
		return nil, fmt.Errorf("cfg: no %q section", sectionPVID)
	}

	if len(section.Data) != pvidDataLen {
		return nil, fmt.Errorf("cfg: %q section data length %d, want %d", sectionPVID, len(section.Data), pvidDataLen)
	}

	pvids := make([]int, pvidPortCount)
	for port := 0; port < pvidPortCount; port++ {
		pvids[port] = int(binary.LittleEndian.Uint16(section.Data[port*2:]))
	}

	return pvids, nil
}

// EthernetConfig is the decoded ethconfig section: one mode byte
// (semantics unconfirmed) followed by three big-endian IPv4 values.
type EthernetConfig struct {
	Mode    byte
	IP      [4]byte
	Netmask [4]byte
	Gateway [4]byte
}

// EthernetConfig decodes the ethconfig section. It returns (nil, nil) when
// the section is absent so callers can treat inference as optional; it
// errors when the section exists but does not carry the expected 13 bytes.
func (c *Config) EthernetConfig() (*EthernetConfig, error) {
	section, ok := c.Section(sectionEthConfig)
	if !ok {
		return nil, nil
	}

	if len(section.Data) != ethConfigDataLen {
		return nil, fmt.Errorf("cfg: %q section data length %d, want %d", sectionEthConfig, len(section.Data), ethConfigDataLen)
	}

	decoded := &EthernetConfig{Mode: section.Data[0]}
	copy(decoded.IP[:], section.Data[1:5])
	copy(decoded.Netmask[:], section.Data[5:9])
	copy(decoded.Gateway[:], section.Data[9:13])

	return decoded, nil
}

// VLAN is a decoded 802.1Q VLAN entry with 1-based port numbers.
type VLAN struct {
	ID       int
	Members  []int
	Untagged []int
	Tagged   []int
}

// VLANs decodes the vlan section: uint16 LE mode, uint16 LE count, then
// count entries of (uint16 LE vid, uint16 LE mask). In each mask the low
// byte is the member port bitmap and the high byte the tagged port bitmap
// (bit n = port n+1). Untagged ports are members that are not tagged.
// The firmware pads the section past the count entries (a real backup
// carries 132 bytes of data for 6 entries); trailing bytes are tolerated
// and preserved in Section.Data/Raw.
func (c *Config) VLANs() ([]VLAN, error) {
	section, ok := c.Section(sectionVLAN)
	if !ok {
		return nil, fmt.Errorf("cfg: no %q section", sectionVLAN)
	}

	data := section.Data
	if len(data) < vlanHeaderLen {
		return nil, fmt.Errorf("cfg: %q section data length %d, want at least %d", sectionVLAN, len(data), vlanHeaderLen)
	}

	count := int(binary.LittleEndian.Uint16(data[2:4]))
	if want := vlanHeaderLen + count*vlanEntryLen; len(data) < want {
		return nil, fmt.Errorf("cfg: %q section count %d needs at least %d bytes of data, got %d", sectionVLAN, count, want, len(data))
	}

	vlans := make([]VLAN, 0, count)
	for entry := 0; entry < count; entry++ {
		offset := vlanHeaderLen + entry*vlanEntryLen
		vid := int(binary.LittleEndian.Uint16(data[offset:]))
		mask := binary.LittleEndian.Uint16(data[offset+2:])

		members := portsFromBitmap(byte(mask))
		tagged := portsFromBitmap(byte(mask >> 8))

		taggedSet := make(map[int]struct{}, len(tagged))
		for _, port := range tagged {
			taggedSet[port] = struct{}{}
		}

		untagged := make([]int, 0, len(members))
		for _, port := range members {
			if _, ok := taggedSet[port]; !ok {
				untagged = append(untagged, port)
			}
		}

		vlans = append(vlans, VLAN{
			ID:       vid,
			Members:  members,
			Untagged: untagged,
			Tagged:   tagged,
		})
	}

	return vlans, nil
}

func portsFromBitmap(bitmap byte) []int {
	ports := make([]int, 0, portCount)
	for bit := 0; bit < portCount; bit++ {
		if bitmap&(1<<bit) != 0 {
			ports = append(ports, bit+1)
		}
	}
	return ports
}

// Fingerprint returns the 4-hex-digit checksum string of the configuration,
// for cheap drift detection between reads.
func (c *Config) Fingerprint() string {
	return fmt.Sprintf("%04x", c.Checksum)
}
