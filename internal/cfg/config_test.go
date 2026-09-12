package cfg

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// All fixtures below are assembled synthetically in test code; real backups
// contain password material and must never be used as test input.

const (
	testTag = 1
)

// fixtureBuilder assembles synthetic FMv2 backups for tests.
type fixtureBuilder struct {
	magic      string
	checksum   uint16 // 0 means compute from the assembled payload.
	sections   [][]byte
	trailer    []byte // appended to the payload (still covered by length/checksum).
	manualLens bool   // keep the derived payload length even with a trailer.
}

func newFixture(sections ...[]byte) *fixtureBuilder {
	return &fixtureBuilder{magic: "FMv2", sections: sections}
}

func (f *fixtureBuilder) bytes(t *testing.T) []byte {
	t.Helper()

	var payload []byte
	for _, section := range f.sections {
		payload = append(payload, section...)
	}

	full := payload
	if len(f.trailer) > 0 {
		full = append(append([]byte{}, payload...), f.trailer...)
	}

	payloadLen := len(full)
	if f.manualLens {
		payloadLen = len(payload)
	}

	checksum := f.checksum
	if checksum == 0 {
		computed, err := Checksum(full[:payloadLen])
		if err != nil {
			t.Fatalf("Checksum() error = %v", err)
		}
		checksum = computed
	}

	data := make([]byte, headerSize, headerSize+len(full))
	copy(data[0:4], f.magic)
	binary.BigEndian.PutUint16(data[4:6], uint16(payloadLen))
	binary.BigEndian.PutUint16(data[6:8], checksum)

	return append(append(data, payload...), f.trailer...)
}

// writeSection builds one section record: uint16 BE tag, uint16 BE length,
// then name + NUL + data.
func writeSection(tag uint16, name string, data []byte) []byte {
	body := make([]byte, 0, len(name)+1+len(data))
	body = append(body, name...)
	body = append(body, 0)
	body = append(body, data...)

	section := make([]byte, sectionHeader, sectionHeader+len(body))
	binary.BigEndian.PutUint16(section[0:2], tag)
	binary.BigEndian.PutUint16(section[2:4], uint16(len(body)))

	return append(section, body...)
}

// writeUnnamedSection builds a section record whose payload has no NUL byte.
func writeUnnamedSection(tag uint16, body []byte) []byte {
	section := make([]byte, sectionHeader, sectionHeader+len(body))
	binary.BigEndian.PutUint16(section[0:2], tag)
	binary.BigEndian.PutUint16(section[2:4], uint16(len(body)))
	return append(section, body...)
}

func vlanSectionData(mode uint16, entries ...[2]uint16) []byte {
	data := make([]byte, vlanHeaderLen, vlanHeaderLen+len(entries)*vlanEntryLen)
	binary.LittleEndian.PutUint16(data[0:2], mode)
	binary.LittleEndian.PutUint16(data[2:4], uint16(len(entries)))
	for _, entry := range entries {
		var encoded [vlanEntryLen]byte
		binary.LittleEndian.PutUint16(encoded[0:2], entry[0])
		binary.LittleEndian.PutUint16(encoded[2:4], entry[1])
		data = append(data, encoded[:]...)
	}
	return data
}

func pvidSectionData(pvids ...int) []byte {
	data := make([]byte, pvidDataLen)
	for port, pvid := range pvids {
		binary.LittleEndian.PutUint16(data[port*2:], uint16(pvid))
	}
	return data
}

func happyFixture() *fixtureBuilder {
	return newFixture(
		writeSection(testTag, "qos", []byte{0x01, 0x02}),
		writeSection(testTag, "vlan", vlanSectionData(4, [2]uint16{10, 0xEFFF}, [2]uint16{1001, 0xF7FF})),
		writeSection(testTag, "pvid", pvidSectionData(1, 1, 1, 1, 1001, 10, 1, 1)),
	)
}

func TestParseConfig(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		fixture func(t *testing.T) []byte
		wantErr string // empty means the parse must succeed.
	}{
		"happy path": {
			fixture: func(t *testing.T) []byte { return happyFixture().bytes(t) },
		},
		"bad magic": {
			fixture: func(t *testing.T) []byte {
				builder := happyFixture()
				builder.magic = "FMv3"
				return builder.bytes(t)
			},
			wantErr: "bad magic",
		},
		"truncated file": {
			fixture: func(t *testing.T) []byte {
				return happyFixture().bytes(t)[:4]
			},
			wantErr: "truncated file",
		},
		"payload length mismatch": {
			fixture: func(t *testing.T) []byte {
				builder := happyFixture()
				builder.trailer = []byte{0x00} // covered by checksum, excluded from length.
				builder.manualLens = true
				return builder.bytes(t)
			},
			wantErr: "does not match remaining file size",
		},
		"trailing bytes after file": {
			fixture: func(t *testing.T) []byte {
				data := happyFixture().bytes(t)
				return append(data, 0x00)
			},
			wantErr: "does not match remaining file size",
		},
		"trailing garbage inside payload": {
			fixture: func(t *testing.T) []byte {
				builder := happyFixture()
				builder.trailer = []byte{0x00, 0x00} // even-length stub, valid length + checksum.
				return builder.bytes(t)
			},
			wantErr: "trailing garbage",
		},
		"odd payload": {
			fixture: func(t *testing.T) []byte {
				builder := happyFixture()
				builder.trailer = []byte{0x00}
				builder.checksum = 0xFFFF // Checksum() would reject the odd payload; store any value.
				return builder.bytes(t)
			},
			wantErr: "odd payload length",
		},
		"bad checksum": {
			fixture: func(t *testing.T) []byte {
				builder := happyFixture()
				builder.checksum = 0xBEEF
				return builder.bytes(t)
			},
			wantErr: "checksum mismatch",
		},
		"unexpected tag": {
			fixture: func(t *testing.T) []byte {
				builder := happyFixture()
				builder.sections[0] = writeSection(2, "qos", []byte{0x01, 0x02})
				return builder.bytes(t)
			},
			wantErr: "unexpected section tag",
		},
		"length overrun": {
			fixture: func(t *testing.T) []byte {
				overrun := make([]byte, sectionHeader)
				binary.BigEndian.PutUint16(overrun[0:2], testTag)
				binary.BigEndian.PutUint16(overrun[2:4], 200)
				return newFixture(overrun).bytes(t)
			},
			wantErr: "overruns payload",
		},
		"missing NUL": {
			fixture: func(t *testing.T) []byte {
				return newFixture(writeUnnamedSection(testTag, []byte("qosA"))).bytes(t)
			},
			wantErr: "no NUL-terminated name",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config, err := ParseConfig(test.fixture(t))
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("ParseConfig() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseConfig() = %+v, want error containing %q", config, test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ParseConfig() error = %v, want error containing %q", err, test.wantErr)
			}
		})
	}
}

func TestParseConfigHappyPathDecodes(t *testing.T) {
	t.Parallel()

	config, err := ParseConfig(happyFixture().bytes(t))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	names := make([]string, 0, len(config.Sections))
	for _, section := range config.Sections {
		names = append(names, section.Name)
	}
	if !slices.Equal(names, []string{"qos", "vlan", "pvid"}) {
		t.Fatalf("section names = %v, want [qos vlan pvid]", names)
	}

	qos, ok := config.Section("qos")
	if !ok {
		t.Fatal("Section(qos) not found")
	}
	if !slices.Equal(qos.Data, []byte{0x01, 0x02}) {
		t.Fatalf("qos data = %v, want [1 2]", qos.Data)
	}
	wantRaw := append(append([]byte("qos"), 0), 0x01, 0x02)
	if !slices.Equal(qos.Raw, wantRaw) {
		t.Fatalf("qos raw = %v, want %v", qos.Raw, wantRaw)
	}

	if _, ok := config.Section("missing"); ok {
		t.Fatal("Section(missing) should not be found")
	}

	rawVLAN, ok := config.RawSection("vlan")
	if !ok {
		t.Fatal("RawSection(vlan) not found")
	}
	if !slices.Equal(rawVLAN, config.Sections[1].Raw) {
		t.Fatalf("RawSection(vlan) = %v, want section raw %v", rawVLAN, config.Sections[1].Raw)
	}

	pvids, err := config.PVIDs()
	if err != nil {
		t.Fatalf("PVIDs() error = %v", err)
	}
	if !slices.Equal(pvids, []int{1, 1, 1, 1, 1001, 10, 1, 1}) {
		t.Fatalf("PVIDs() = %v, want [1 1 1 1 1001 10 1 1]", pvids)
	}

	vlans, err := config.VLANs()
	if err != nil {
		t.Fatalf("VLANs() error = %v", err)
	}
	if len(vlans) != 2 {
		t.Fatalf("VLAN count = %d, want 2", len(vlans))
	}

	if got, want := vlans[0].ID, 10; got != want {
		t.Fatalf("vlan[0] ID = %d, want %d", got, want)
	}
	if !slices.Equal(vlans[0].Members, []int{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("vlan 10 members = %v", vlans[0].Members)
	}
	if !slices.Equal(vlans[0].Untagged, []int{1, 2, 3, 4, 6, 7, 8}) {
		t.Fatalf("vlan 10 untagged = %v, want [1 2 3 4 6 7 8]", vlans[0].Untagged)
	}
	if !slices.Equal(vlans[0].Tagged, []int{5}) {
		t.Fatalf("vlan 10 tagged = %v, want [5]", vlans[0].Tagged)
	}

	if got, want := vlans[1].ID, 1001; got != want {
		t.Fatalf("vlan[1] ID = %d, want %d", got, want)
	}
	if !slices.Equal(vlans[1].Members, []int{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("vlan 1001 members = %v", vlans[1].Members)
	}
	if !slices.Equal(vlans[1].Untagged, []int{1, 2, 3, 5, 6, 7, 8}) {
		t.Fatalf("vlan 1001 untagged = %v, want [1 2 3 5 6 7 8]", vlans[1].Untagged)
	}
	if !slices.Equal(vlans[1].Tagged, []int{4}) {
		t.Fatalf("vlan 1001 tagged = %v, want [4]", vlans[1].Tagged)
	}
}

func TestVLANsTolerateTrailingPadding(t *testing.T) {
	t.Parallel()

	// The firmware pads the vlan section well past the count entries (a
	// real backup carries 132 bytes of data for 6 entries). 105 padding
	// bytes keep the total section payload even, as the format requires.
	data := vlanSectionData(4, [2]uint16{10, 0xEFFF})
	data = append(data, make([]byte, 105)...) // zero padding, as written by the switch

	config, err := ParseConfig(newFixture(writeSection(testTag, "vlan", data)).bytes(t))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	vlans, err := config.VLANs()
	if err != nil {
		t.Fatalf("VLANs() error = %v", err)
	}
	if len(vlans) != 1 {
		t.Fatalf("VLAN count = %d, want 1", len(vlans))
	}
	if got, want := vlans[0].ID, 10; got != want {
		t.Fatalf("vlan ID = %d, want %d", got, want)
	}
	if !slices.Equal(vlans[0].Members, []int{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("vlan 10 members = %v", vlans[0].Members)
	}
}

func TestParseConfigRejectsMalformedPVIDAndVLAN(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		sections [][]byte
		decode   func(*Config) error
		wantErr  string
	}{
		"pvid too short": {
			sections: [][]byte{writeSection(testTag, "pvid", make([]byte, 15))},
			decode:   func(c *Config) error { _, err := c.PVIDs(); return err },
			wantErr:  `"pvid" section data length 15, want 16`,
		},
		"pvid too long": {
			sections: [][]byte{writeSection(testTag, "pvid", make([]byte, 17))},
			decode:   func(c *Config) error { _, err := c.PVIDs(); return err },
			wantErr:  `"pvid" section data length 17, want 16`,
		},
		"vlan data below header": {
			sections: [][]byte{writeSection(testTag, "vlan", []byte{0x04, 0x00, 0x00})},
			decode:   func(c *Config) error { _, err := c.VLANs(); return err },
			wantErr:  `"vlan" section data length 3, want at least 4`,
		},
		"vlan count inconsistent": {
			sections: [][]byte{
				// count claims 2 entries but only 1 is present.
				writeSection(testTag, "vlan", []byte{0x04, 0x00, 0x02, 0x00, 0x0A, 0x00, 0xFF, 0xFF}),
				// Even-length padding section so the total payload stays even.
				writeSection(testTag, "misc", []byte{0x00, 0x01}),
			},
			decode:  func(c *Config) error { _, err := c.VLANs(); return err },
			wantErr: `count 2 needs at least 12 bytes of data, got 8`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config, err := ParseConfig(newFixture(test.sections...).bytes(t))
			if err != nil {
				t.Fatalf("ParseConfig() error = %v", err)
			}

			err = test.decode(config)
			if err == nil {
				t.Fatalf("decode succeeded, want error containing %q", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("decode error = %v, want error containing %q", err, test.wantErr)
			}
		})
	}
}

func TestConfigDecodeFailsWithoutSections(t *testing.T) {
	t.Parallel()

	config, err := ParseConfig(newFixture(writeSection(testTag, "name", []byte("lab"))).bytes(t))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	if _, err := config.PVIDs(); err == nil {
		t.Fatal("PVIDs() should fail without pvid section")
	}
	if _, err := config.VLANs(); err == nil {
		t.Fatal("VLANs() should fail without vlan section")
	}
	if _, ok := config.RawSection("pvid"); ok {
		t.Fatal("RawSection(pvid) should not be found")
	}
}

func TestEthernetConfig(t *testing.T) {
	t.Parallel()

	t.Run("decodes identity fields", func(t *testing.T) {
		t.Parallel()

		// 1 mode byte + IPv4 10.0.2.2 + netmask 255.255.0.0 + gateway
		// 10.0.0.1. A padding section keeps the total payload even, as
		// the format requires.
		data := newFixture(
			writeSection(testTag, "ethconfig", []byte{0x01, 0x0A, 0x00, 0x02, 0x02, 0xFF, 0xFF, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01}),
			writeSection(testTag, "misc", []byte{0x00, 0x01}),
		).bytes(t)

		config, err := ParseConfig(data)
		if err != nil {
			t.Fatalf("ParseConfig() error = %v", err)
		}

		eth, err := config.EthernetConfig()
		if err != nil {
			t.Fatalf("EthernetConfig() error = %v", err)
		}
		if eth == nil {
			t.Fatal("EthernetConfig() = nil, want decoded fields")
		}
		if got, want := eth.Mode, byte(1); got != want {
			t.Fatalf("Mode = %d, want %d", got, want)
		}
		if got, want := eth.IP, [4]byte{10, 0, 2, 2}; got != want {
			t.Fatalf("IP = %v, want %v", got, want)
		}
		if got, want := eth.Netmask, [4]byte{255, 255, 0, 0}; got != want {
			t.Fatalf("Netmask = %v, want %v", got, want)
		}
		if got, want := eth.Gateway, [4]byte{10, 0, 0, 1}; got != want {
			t.Fatalf("Gateway = %v, want %v", got, want)
		}
	})

	t.Run("absent section is optional", func(t *testing.T) {
		t.Parallel()

		config, err := ParseConfig(newFixture(writeSection(testTag, "name", []byte("lab"))).bytes(t))
		if err != nil {
			t.Fatalf("ParseConfig() error = %v", err)
		}

		eth, err := config.EthernetConfig()
		if err != nil {
			t.Fatalf("EthernetConfig() error = %v, want nil", err)
		}
		if eth != nil {
			t.Fatalf("EthernetConfig() = %+v, want nil", eth)
		}
	})

	t.Run("wrong length errors", func(t *testing.T) {
		t.Parallel()

		config, err := ParseConfig(newFixture(writeSection(testTag, "ethconfig", make([]byte, 12))).bytes(t))
		if err != nil {
			t.Fatalf("ParseConfig() error = %v", err)
		}

		eth, err := config.EthernetConfig()
		if err == nil {
			t.Fatalf("EthernetConfig() = %+v, want error", eth)
		}
		if !strings.Contains(err.Error(), `"ethconfig" section data length 12, want 13`) {
			t.Fatalf("EthernetConfig() error = %v, want length mismatch", err)
		}
	})
}

func TestChecksumRoundTripFingerprint(t *testing.T) {
	t.Parallel()

	sections := [][]byte{
		writeSection(testTag, "name", []byte("lab-switch")),
		writeSection(testTag, "pvid", pvidSectionData(1, 1, 1, 1, 20, 20, 20, 20)),
	}

	var payload []byte
	for _, section := range sections {
		payload = append(payload, section...)
	}

	expected, err := Checksum(payload)
	if err != nil {
		t.Fatalf("Checksum() error = %v", err)
	}

	config, err := ParseConfig(newFixture(sections...).bytes(t))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	if config.Checksum != expected {
		t.Fatalf("Checksum = 0x%04X, want 0x%04X", config.Checksum, expected)
	}
	if got, want := config.Fingerprint(), fmt.Sprintf("%04x", expected); got != want {
		t.Fatalf("Fingerprint() = %q, want %q", got, want)
	}
}

func TestChecksumRejectsOddPayload(t *testing.T) {
	t.Parallel()

	if _, err := Checksum([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Fatal("Checksum() should reject odd-length payloads")
	}
}
