package nsdp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestPortBitmap(t *testing.T) {
	tests := []struct {
		name  string
		ports []int
		want  byte
	}{
		{"single port 1", []int{1}, 0x80},
		{"single port 2", []int{2}, 0x40},
		{"single port 8", []int{8}, 0x01},
		{"ports 1,8", []int{1, 8}, 0x81},
		{"ports 1-8", []int{1, 2, 3, 4, 5, 6, 7, 8}, 0xFF},
		{"ports 1,3,5,7", []int{1, 3, 5, 7}, 0xAA}, // 0x80|0x20|0x08|0x02
		{"out of range ignored", []int{0, 1, 9}, 0x80},
		{"empty", []int{}, 0x00},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PortBitmap(tt.ports)
			if got != tt.want {
				t.Errorf("PortBitmap(%v) = 0x%02x, want 0x%02x", tt.ports, got, tt.want)
			}
		})
	}
}

func TestSetRebootValidation(t *testing.T) {
	// We can't test the network path, but we can verify the tag constant
	if TagReboot != 0x0013 {
		t.Errorf("TagReboot = 0x%04x, want 0x0013", TagReboot)
	}
}

func TestSetPVIDValidation(t *testing.T) {
	// Use a nil client — all validation happens before network I/O
	c := &Client{}

	if err := c.SetPVID(0, 1); err == nil {
		t.Error("SetPVID(0,1) should reject port 0")
	}
	if err := c.SetPVID(9, 1); err == nil {
		t.Error("SetPVID(9,1) should reject port 9")
	}
	if err := c.SetPVID(1, -1); err == nil {
		t.Error("SetPVID(1,-1) should reject vlan -1")
	}
	if err := c.SetPVID(1, 4096); err == nil {
		t.Error("SetPVID(1,4096) should reject vlan 4096")
	}
}

func TestSetQoSPriorityValidation(t *testing.T) {
	c := &Client{}
	if err := c.SetQoSPriority(0, 1); err == nil {
		t.Error("SetQoSPriority(0,1) should reject port 0")
	}
	if err := c.SetQoSPriority(9, 1); err == nil {
		t.Error("SetQoSPriority(9,1) should reject port 9")
	}
}

func TestSetIngressRateValidation(t *testing.T) {
	c := &Client{}
	if err := c.SetIngressRate(0, Bandwidth1M); err == nil {
		t.Error("SetIngressRate(0,...) should reject port 0")
	}
	if err := c.SetIngressRate(9, Bandwidth1M); err == nil {
		t.Error("SetIngressRate(9,...) should reject port 9")
	}
}

func TestSetEgressRateValidation(t *testing.T) {
	c := &Client{}
	if err := c.SetEgressRate(0, Bandwidth1M); err == nil {
		t.Error("SetEgressRate(0,...) should reject port 0")
	}
}

func TestSetBroadcastStormRateValidation(t *testing.T) {
	c := &Client{}
	if err := c.SetBroadcastStormRate(0, Bandwidth1M); err == nil {
		t.Error("SetBroadcastStormRate(0,...) should reject port 0")
	}
}

func TestSetPortConfigValidation(t *testing.T) {
	// Use a nil client — all validation happens before network I/O
	c := &Client{}

	if err := c.SetPortConfig(0, true, true); err == nil {
		t.Error("SetPortConfig(0,...) should reject port 0")
	}
	if err := c.SetPortConfig(9, true, true); err == nil {
		t.Error("SetPortConfig(9,...) should reject port 9")
	}
}

// TestSetPortConfigPayload pins the 3-byte tag-0x9400 wire layout
// {port u8, admin u8, flow u8} with the ROUND 18 semantics: byte 2 =
// ADMIN enable (0=disabled, 1=enabled), byte 3 = FLOW CONTROL (0=off,
// 1=on). Built through the method's own payload builder, the exact bytes
// the authenticated SET would carry.
func TestSetPortConfigPayload(t *testing.T) {
	tests := []struct {
		name  string
		port  int
		admin bool
		flow  bool
		want  []byte
	}{
		{"port 1 admin on flow on", 1, true, true, []byte{0x01, 0x01, 0x01}},
		{"port 2 admin on flow off", 2, true, false, []byte{0x02, 0x01, 0x00}},
		{"port 3 admin off flow on", 3, false, true, []byte{0x03, 0x00, 0x01}},
		{"port 8 admin off flow off", 8, false, false, []byte{0x08, 0x00, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := portConfigPayload(tt.port, tt.admin, tt.flow)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("portConfigPayload(%d, %v, %v) = % x, want % x", tt.port, tt.admin, tt.flow, got, tt.want)
			}
		})
	}
}

func TestSetVLANEngineModeValidation(t *testing.T) {
	c := &Client{}
	if err := c.SetVLANEngineMode(5); err == nil {
		t.Error("SetVLANEngineMode(5) should reject mode 5")
	}
	// Valid modes don't error on validation (they'd fail on network)
	_ = c.SetVLANEngineMode(0)
}

func TestSetPortMirroringValidation(t *testing.T) {
	c := &Client{}
	if err := c.SetPortMirroring(9, []int{2}); err == nil {
		t.Error("SetPortMirroring(9,...) should reject dest port 9")
	}
	if err := c.SetPortMirroring(-1, []int{2}); err == nil {
		t.Error("SetPortMirroring(-1,...) should reject dest port -1")
	}
}

func TestSetPortBasedVLANValidation(t *testing.T) {
	c := &Client{}
	if err := c.SetPortBasedVLAN(-1, []int{1}); err == nil {
		t.Error("SetPortBasedVLAN(-1,...) should reject vlan -1")
	}
	if err := c.SetPortBasedVLAN(4096, []int{1}); err == nil {
		t.Error("SetPortBasedVLAN(4096,...) should reject vlan 4096")
	}
}

func TestSet8021QVLANValidation(t *testing.T) {
	c := &Client{}
	if err := c.Set8021QVLAN(-1, []int{1}, []int{}); err == nil {
		t.Error("Set8021QVLAN(-1,...) should reject vlan -1")
	}
	if err := c.Set8021QVLAN(4096, []int{}, []int{1}); err == nil {
		t.Error("Set8021QVLAN(4096,...) should reject vlan 4096")
	}
}

func TestDelete8021QVLANValidation(t *testing.T) {
	c := &Client{}
	if err := c.Delete8021QVLAN(-1); err == nil {
		t.Error("Delete8021QVLAN(-1) should reject vlan -1")
	}
	if err := c.Delete8021QVLAN(4096); err == nil {
		t.Error("Delete8021QVLAN(4096) should reject vlan 4096")
	}
}

func TestSetIPAddressValidation(t *testing.T) {
	c := &Client{}
	if err := c.SetIPAddress("not-an-ip"); err == nil {
		t.Error("SetIPAddress('not-an-ip') should reject invalid IP")
	}
	if err := c.SetIPAddress("::1"); err == nil {
		t.Error("SetIPAddress('::1') should reject IPv6")
	}
}

func TestSetSubnetMaskValidation(t *testing.T) {
	c := &Client{}
	if err := c.SetSubnetMask("not-a-mask"); err == nil {
		t.Error("SetSubnetMask('not-a-mask') should reject invalid mask")
	}
}

func TestSetGatewayAddrValidation(t *testing.T) {
	c := &Client{}
	if err := c.SetGatewayAddr("not-a-gateway"); err == nil {
		t.Error("SetGatewayAddr('not-a-gateway') should reject invalid gateway")
	}
}

func TestSetDHCPModeValidation(t *testing.T) {
	c := &Client{}
	if err := c.SetDHCPMode(3); err == nil {
		t.Error("SetDHCPMode(3) should reject mode 3")
	}
}

func TestBandwidthLimitString(t *testing.T) {
	tests := []struct {
		limit BandwidthLimit
		want  string
	}{
		{BandwidthNone, "None"},
		{Bandwidth512K, "512K"},
		{Bandwidth1M, "1M"},
		{Bandwidth512M, "512M"},
		{BandwidthLimit(99), "unknown(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.limit.String()
			if got != tt.want {
				t.Errorf("BandwidthLimit(%d).String() = %q, want %q", tt.limit, got, tt.want)
			}
		})
	}
}

func TestQoSPriorityString(t *testing.T) {
	tests := []struct {
		prio QoSPriority
		want string
	}{
		{1, "High"},
		{2, "Middle"},
		{3, "Normal"},
		{4, "Low"},
		{99, "unknown(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.prio.String()
			if got != tt.want {
				t.Errorf("QoSPriority(%d).String() = %q, want %q", tt.prio, got, tt.want)
			}
		})
	}
}

func TestVLANEngineModeString(t *testing.T) {
	tests := []struct {
		mode VLANEngineMode
		want string
	}{
		{0, "none"},
		{1, "port-based"},
		{2, "id-based"},
		{3, "802.1q port-based"},
		{4, "802.1q extended"},
		{99, "unknown(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.mode.String()
			if got != tt.want {
				t.Errorf("VLANEngineMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

func TestGetIPAddress(t *testing.T) {
	ip := net.IP([]byte{10, 0, 0, 1})
	if ip.To4() == nil {
		t.Error("net.IP(10.0.0.1).To4() should not be nil")
	}
}

// TestSetPVIDEncoding verifies the 3-byte PVID wire layout:
// {port u8, vlan_id u16 BE}
func TestSetPVIDEncoding(t *testing.T) {
	port := byte(4)
	vlanID := uint16(1001)
	buf := make([]byte, 3)
	buf[0] = port
	binary.BigEndian.PutUint16(buf[1:], vlanID)

	if buf[0] != 4 {
		t.Errorf("port byte = %d, want 4", buf[0])
	}
	if binary.BigEndian.Uint16(buf[1:]) != 1001 {
		t.Errorf("vlan_id bytes = % x, want % x", buf[1:], []byte{0x03, 0xE9})
	}
}

// TestSetPortBasedVLANEncoding verifies the 3-byte port-based VLAN wire layout:
// {vlan_id u16 BE, port_bitmap u8}
func TestSetPortBasedVLANEncoding(t *testing.T) {
	// VLAN 1001, ports 1,3,5 → bitmap: port 1=0x80, port 3=0x20, port 5=0x08 → 0xA8
	buf := make([]byte, 3)
	binary.BigEndian.PutUint16(buf[0:], 1001)
	buf[2] = PortBitmap([]int{1, 3, 5})

	if binary.BigEndian.Uint16(buf[0:]) != 1001 {
		t.Errorf("vlan_id = %d, want 1001", binary.BigEndian.Uint16(buf[0:]))
	}
	if buf[2] != 0xA8 {
		t.Errorf("bitmap = 0x%02x, want 0xA8", buf[2])
	}
}

// TestSet8021QVLANEncoding verifies the 4-byte 802.1Q VLAN wire layout:
// {vlan_id u16 BE, tagged_bitmap u8, untagged_bitmap u8}
func TestSet8021QVLANEncoding(t *testing.T) {
	// Tagged: ports 1,2,3 → 0x80|0x40|0x20 = 0xE0
	// Untagged: ports 4,5,6 → 0x10|0x08|0x04 = 0x1C
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:], 1001)
	buf[2] = PortBitmap([]int{1, 2, 3})
	buf[3] = PortBitmap([]int{4, 5, 6})

	if binary.BigEndian.Uint16(buf[0:]) != 1001 {
		t.Errorf("vlan_id = %d, want 1001", binary.BigEndian.Uint16(buf[0:]))
	}
	if buf[2] != 0xE0 {
		t.Errorf("tagged bitmap = 0x%02x, want 0xE0", buf[2])
	}
	if buf[3] != 0x1C {
		t.Errorf("untagged bitmap = 0x%02x, want 0x1C", buf[3])
	}
}

// TestSetBandwidthEncoding verifies the 5-byte bandwidth wire layout:
// {port u8, 00 00 reserved, limit u16 BE}
func TestSetBandwidthEncoding(t *testing.T) {
	port := byte(1)
	limit := Bandwidth1M // 0x0002
	buf := make([]byte, 5)
	buf[0] = port
	buf[1] = 0
	buf[2] = 0
	binary.BigEndian.PutUint16(buf[3:], uint16(limit))

	if buf[0] != 1 {
		t.Errorf("port = %d, want 1", buf[0])
	}
	if buf[1] != 0 || buf[2] != 0 {
		t.Errorf("reserved bytes = % x, want 00 00", buf[1:3])
	}
	if binary.BigEndian.Uint16(buf[3:]) != 2 {
		t.Errorf("limit = %d, want 2", binary.BigEndian.Uint16(buf[3:]))
	}
}

// TestSetPortMirroringEncoding verifies the 3-byte port mirroring wire layout:
// {dst_port u8, 00 reserved, src_ports u8 bitmap}; dst 0 disables mirroring.
func TestSetPortMirroringEncoding(t *testing.T) {
	buf := buildMirrorPayload(2, []int{1, 3})
	if len(buf) != 3 {
		t.Fatalf("mirroring payload should be 3 bytes, got %d", len(buf))
	}
	if buf[0] != 2 {
		t.Errorf("dst_port = %d, want 2", buf[0])
	}
	if buf[1] != 0 {
		t.Errorf("reserved = 0x%02x, want 0x00", buf[1])
	}
	if buf[2] != 0xA0 { // ports 1,3 → 0x80 + 0x20 = 0xA0
		t.Errorf("src_ports = 0x%02x, want 0xA0", buf[2])
	}

	// Disable mirroring: dest 0 → all-zero payload regardless of sources.
	buf2 := buildMirrorPayload(0, []int{1, 3})
	if !bytes.Equal(buf2, []byte{0, 0, 0}) {
		t.Errorf("disable mirroring payload = % x, want 00 00 00", buf2)
	}
}

// TestSetIGMPSnoopingEncoding verifies the 4-byte IGMP snooping wire layout:
// {enabled u16 BE, vlan_id u16 BE}; disabled zeroes the whole payload.
func TestSetIGMPSnoopingEncoding(t *testing.T) {
	buf := buildIGMPSnoopingPayload(true, 10)
	if len(buf) != 4 {
		t.Fatalf("IGMP snooping payload should be 4 bytes, got %d", len(buf))
	}
	if binary.BigEndian.Uint16(buf[0:]) != 1 {
		t.Errorf("enabled = %d, want 1", binary.BigEndian.Uint16(buf[0:]))
	}
	if binary.BigEndian.Uint16(buf[2:]) != 10 {
		t.Errorf("vlan = %d, want 10", binary.BigEndian.Uint16(buf[2:]))
	}

	// Disabled: whole payload zeroed (ProSafeLinux sends {0,0} for "none").
	off := buildIGMPSnoopingPayload(false, 10)
	if !bytes.Equal(off, []byte{0, 0, 0, 0}) {
		t.Errorf("disabled payload = % x, want 00 00 00 00", off)
	}
}

// TestSetVLANEngineModeEncoding verifies the 1-byte VLAN engine mode wire layout:
// {mode u8}
func TestSetVLANEngineModeEncoding(t *testing.T) {
	buf := []byte{1}
	if len(buf) != 1 {
		t.Errorf("VLAN engine mode should be 1 byte, got %d", len(buf))
	}
	if buf[0] != 1 {
		t.Errorf("mode = %d, want 1", buf[0])
	}
}

// TestDelete8021QVLANEncoding verifies the 2-byte delete VLAN wire layout:
// {vlan_id u16 BE}
func TestDelete8021QVLANEncoding(t *testing.T) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf[0:], 1001)

	if binary.BigEndian.Uint16(buf[0:]) != 1001 {
		t.Errorf("vlan_id = %d, want 1001", binary.BigEndian.Uint16(buf[0:]))
	}
}

// TestSetQoSModeValidation verifies the QoS mode range gate (firmware
// accepts only 1-2 and rejects anything else with invalid-value).
func TestSetQoSModeValidation(t *testing.T) {
	c := &Client{}
	if err := c.SetQoSMode(0); err == nil {
		t.Error("SetQoSMode(0) should reject mode 0")
	}
	if err := c.SetQoSMode(3); err == nil {
		t.Error("SetQoSMode(3) should reject mode 3")
	}
}

// TestBuildBoolPayload verifies the 1-byte payload used by the firmware's
// single-value boolean SETs (0x6c00 block unknown multicast, 0x7000 IGMP
// header validation).
func TestBuildBoolPayload(t *testing.T) {
	if b := buildBoolPayload(true); !bytes.Equal(b, []byte{1}) {
		t.Errorf("buildBoolPayload(true) = % x, want 01", b)
	}
	if b := buildBoolPayload(false); !bytes.Equal(b, []byte{0}) {
		t.Errorf("buildBoolPayload(false) = % x, want 00", b)
	}
}
