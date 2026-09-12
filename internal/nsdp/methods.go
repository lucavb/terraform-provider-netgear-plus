package nsdp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ---------------------------------------------------------------------------
// Typed SET methods for the NETGEAR Plus NSDP protocol.
//
// Each method logs in and refreshes the auth token automatically (like
// SetSystemName / SetRaw), sends ONE authenticated SET, and returns an error
// if the switch rejects it. Every SET carries the session's auth TLV before
// the type-specific TLV (nsdp_command_start / FUN_0048edc0).
//
// WARNING: 3 failed login attempts lock ALL SET operations on the switch
// for ~30 minutes (see errors.go). Callers must verify the password before
// invoking these methods.
//
// PORT NUMBERING: port numbers are 1-based everywhere (port 1 is the first
// physical port). Bitmap helpers use the same convention as ProSafeLinux:
// port N → bit position 9-N (port 1 = 0x80, port 8 = 0x01).
// ---------------------------------------------------------------------------

// --- Simple action SETs ---------------------------------------------------

// SetReboot instructs the switch to reboot. The payload is a single byte 0x01.
// This is a destructive operation — the switch will restart and all sessions
// will be dropped.
func (c *Client) SetReboot() error {
	return c.SetAction(TagReboot, 0x01)
}

// SetFactoryDefaults instructs the switch to restore factory defaults.
// The payload is a single byte 0x01. This is destructive — all
// configuration will be lost.
func (c *Client) SetFactoryDefaults() error {
	return c.SetAction(TagFactoryDefaults, 0x01)
}

// ResetPortStats resets all per-port traffic statistics on the switch.
// The payload is a single byte 0x01 (tag 0x1400).
func (c *Client) ResetPortStats() error {
	return c.SetAction(TagResetPortStats, 0x01)
}

// SetAction is a thin wrapper: sends ONE authenticated SET with tag and a
// single-byte action value. Used by SetReboot, SetFactoryDefaults,
// ResetPortStats.
func (c *Client) SetAction(tag uint16, value byte) error {
	return c.SetRaw(tag, []byte{value})
}

// --- Per-port configuration SETs ------------------------------------------

// PortBitmap converts a slice of 1-based port numbers to a byte bitmap
// where port N sets bit (1 << (8 - N)): port 1 → 0x80, port 8 → 0x01.
// This matches ProSafeLinux BIN_PORTS exactly.
func PortBitmap(ports []int) byte {
	b := byte(0)
	for _, p := range ports {
		if p >= 1 && p <= 8 {
			b |= 1 << (8 - p)
		}
	}
	return b
}

// SetPVID sets the Port-based VLAN ID (PVID) for a single port.
//
// Port is 1-based (1–8). VLANID is the 12-bit VLAN identifier (1–4094).
// Payload layout: {port u8, vlan_id u16 BE} = 3 bytes.
// LIVE-PROVEN both directions (casalta probe, 2026-09-12,
// gaps-20260912-163538.log stage 3): port 3 PVID 1 -> 999 read back
// correct, then restored to 1 and re-verified, all other PVID entries
// untouched. CONFIRMED layout (live probe + ProSafeLinux
// psl_typ.py:595-612).
func (c *Client) SetPVID(port, vlanID int) error {
	if port < 1 || port > 8 {
		return fmt.Errorf("nsdp: port %d out of range [1,8]", port)
	}
	if vlanID < 0 || vlanID > 4095 {
		return fmt.Errorf("nsdp: vlan id %d out of range [0,4095]", vlanID)
	}
	buf := make([]byte, 3)
	buf[0] = byte(port)
	binary.BigEndian.PutUint16(buf[1:], uint16(vlanID))
	return c.SetRaw(TagPVID, buf)
}

// SetQoSPriority sets the per-port QoS priority on the switch.
//
// Port is 1-based (1–8). Priority is 1=High, 2=Middle, 3=Normal, 4=Low.
// Payload layout: {port u8, priority u8} = 2 bytes.
// CONFIRMED layout (ProSafeLinux psl_typ.py:680-734).
func (c *Client) SetQoSPriority(port int, priority QoSPriority) error {
	if port < 1 || port > 8 {
		return fmt.Errorf("nsdp: port %d out of range [1,8]", port)
	}
	return c.SetRaw(TagPortBasedQoS, []byte{byte(port), byte(priority)})
}

// QoSMode selects the switch's global QoS scheduling mode.
type QoSMode byte

const (
	// QoSModePortBased schedules by the per-port priority (SetQoSPriority).
	QoSModePortBased QoSMode = 1
	// QoSMode8021p schedules by the 802.1p priority carried in tagged frames.
	QoSMode8021p QoSMode = 2
)

// String renders the QoS mode.
func (m QoSMode) String() string {
	switch m {
	case QoSModePortBased:
		return "port-based"
	case QoSMode8021p:
		return "802.1p"
	default:
		return fmt.Sprintf("unknown(%d)", byte(m))
	}
}

// SetQoSMode selects the global QoS scheduling mode (tag 0x3400).
//
// Mode is 1=port-based (per-port priorities via SetQoSPriority) or 2=802.1p
// (frame priority). Payload layout: {mode u8} = 1 byte.
// CONFIRMED: the firmware SET handler (bank1 0x7b98) accepts only modes
// 1-2 and rejects anything else with the invalid-value error; ProSafeLinux
// PslTypQos pins the same two values.
func (c *Client) SetQoSMode(mode QoSMode) error {
	if mode != QoSModePortBased && mode != QoSMode8021p {
		return fmt.Errorf("nsdp: qos mode %d out of range [1,2]", byte(mode))
	}
	return c.SetRaw(TagQoSMode, []byte{byte(mode)})
}

// BandwidthLimit is the rate-limit enum used by ingress/egress/storm rate
// limit SETs (tag 0x4c00/0x5000/0x5800).
type BandwidthLimit byte

// String renders the bandwidth limit enum value.
func (l BandwidthLimit) String() string {
	switch l {
	case BandwidthNone:
		return "None"
	case Bandwidth512K:
		return "512K"
	case Bandwidth1M:
		return "1M"
	case Bandwidth2M:
		return "2M"
	case Bandwidth4M:
		return "4M"
	case Bandwidth8M:
		return "8M"
	case Bandwidth16M:
		return "16M"
	case Bandwidth32M:
		return "32M"
	case Bandwidth64M:
		return "64M"
	case Bandwidth128M:
		return "128M"
	case Bandwidth256M:
		return "256M"
	case Bandwidth512M:
		return "512M"
	default:
		return fmt.Sprintf("unknown(%d)", byte(l))
	}
}

const (
	BandwidthNone BandwidthLimit = 0x0000
	Bandwidth512K BandwidthLimit = 0x0001
	Bandwidth1M   BandwidthLimit = 0x0002
	Bandwidth2M   BandwidthLimit = 0x0003
	Bandwidth4M   BandwidthLimit = 0x0004
	Bandwidth8M   BandwidthLimit = 0x0005
	Bandwidth16M  BandwidthLimit = 0x0006
	Bandwidth32M  BandwidthLimit = 0x0007
	Bandwidth64M  BandwidthLimit = 0x0008
	Bandwidth128M BandwidthLimit = 0x0009
	Bandwidth256M BandwidthLimit = 0x000a
	Bandwidth512M BandwidthLimit = 0x000b
)

// SetIngressRate sets the ingress (incoming) rate limit on a port.
//
// Port is 1-based (1–8). Limit is a bandwidth enum (0 = none, 1 = 512K …
// 11 = 512M). Payload layout: {port u8, 00 00 reserved, limit u16 BE} = 5
// bytes. CONFIRMED layout (ProSafeLinux PslTypBandwidth).
func (c *Client) SetIngressRate(port int, limit BandwidthLimit) error {
	return c.setBandwidth(TagIngressRate, port, limit)
}

// SetEgressRate sets the egress (outgoing) rate limit on a port.
// Same layout as SetIngressRate.
func (c *Client) SetEgressRate(port int, limit BandwidthLimit) error {
	return c.setBandwidth(TagEgressRate, port, limit)
}

// SetBroadcastStormRate sets the broadcast storm rate limit on a port.
// Same layout as SetIngressRate.
func (c *Client) SetBroadcastStormRate(port int, limit BandwidthLimit) error {
	return c.setBandwidth(TagBroadcastStormRate, port, limit)
}

// setBandwidth builds the 5-byte bandwidth TLV payload: {port u8, 00 00,
// limit u16 BE}.
func (c *Client) setBandwidth(tag uint16, port int, limit BandwidthLimit) error {
	if port < 1 || port > 8 {
		return fmt.Errorf("nsdp: port %d out of range [1,8]", port)
	}
	buf := make([]byte, 5)
	buf[0] = byte(port)
	binary.BigEndian.PutUint16(buf[3:], uint16(limit))
	return c.SetRaw(tag, buf)
}

// SetPortConfig sets a port's admin enable and flow-control configuration
// (tag 0x9400).
//
// Port is 1-based (1–8). Payload layout: {port u8, admin u8, flow u8} = 3
// bytes. Semantics LIVE-PROVEN against the real switch via the web UI
// (notes ROUND 18):
//
//   - byte 2 = ADMIN enable: 0 = port disabled (the web UI renders the
//     port's Speed config column as "Disable"), 1 = enabled (the factory
//     value on all 8 ports).
//   - byte 3 = FLOW CONTROL: 0 = off (factory), 1 = on (the UI Flow
//     Control column flips to "Enable" when the byte is 1).
//
// The firmware SET handler (bank1 0x81f6, shared verbatim with tag
// 0x0c00) always writes ALL THREE bytes per port — there is no partial
// write — so a caller changing only one flag must read-modify-write: GET
// the 0x9400 block first and pass the other byte's current value back in
// (as nsdpctl's status/flowcontrol verbs do).
//
// OPEN QUESTION (unresolved; live verification pending): byte 2 may be a
// full speed-config enum (0 = Disable, 1 = Auto, 2+ = forced speeds)
// rather than a bare admin flag. This API only ever writes 0/1 either way.
func (c *Client) SetPortConfig(port int, adminEnabled bool, flowControl bool) error {
	if port < 1 || port > 8 {
		return fmt.Errorf("nsdp: port %d out of range [1,8]", port)
	}
	return c.SetRaw(TagPortAdminStatus, portConfigPayload(port, adminEnabled, flowControl))
}

// portConfigPayload builds the 3-byte tag-0x9400 payload
// {port u8, admin u8 (0|1), flow u8 (0|1)}.
func portConfigPayload(port int, adminEnabled, flowControl bool) []byte {
	admin, flow := byte(0), byte(0)
	if adminEnabled {
		admin = 1
	}
	if flowControl {
		flow = 1
	}
	return []byte{byte(port), admin, flow}
}

// SetPortMirroring configures port mirroring on the switch.
//
// DestPort is the 1-based mirror destination port, or 0 to disable
// mirroring entirely. SrcPorts is a list of 1-based source ports to
// mirror (use the PortBitmap helper).
// Payload layout: {dst_port u8, 00 reserved, src_ports u8 bitmap} = 3
// bytes; destPort 0 sends the all-zero payload that clears the mirror
// table.
// CONFIRMED layout: ProSafeLinux PslTypPortMirror plus the firmware SET
// handler (bank1 0x8382), which treats dst 0 as "clear mirroring" and
// expands the source bitmap from value byte 2.
func (c *Client) SetPortMirroring(destPort int, srcPorts []int) error {
	if destPort < 0 || destPort > 8 {
		return fmt.Errorf("nsdp: dest port %d out of range [0,8]", destPort)
	}
	return c.SetRaw(TagPortMirroring, buildMirrorPayload(destPort, srcPorts))
}

// buildMirrorPayload builds the 3-byte mirroring payload
// {dst u8, 00, src bitmap u8}; destPort 0 disables mirroring.
func buildMirrorPayload(destPort int, srcPorts []int) []byte {
	if destPort == 0 {
		return []byte{0, 0, 0}
	}
	return []byte{byte(destPort), 0, PortBitmap(srcPorts)}
}

// --- Global config SETs ---------------------------------------------------

// SetVLANEngineMode sets the VLAN engine mode.
//
// Mode is 0=none, 1=port-based, 2=id-based, 3=802.1Q port-based,
// 4=802.1Q extended. Payload layout: {mode u8} = 1 byte.
// CONFIRMED layout (ProSafeLinux PslTypVlanSupport + wireshark).
func (c *Client) SetVLANEngineMode(mode VLANEngineMode) error {
	if mode > 4 {
		return fmt.Errorf("nsdp: vlan engine mode %d out of range [0,4]", mode)
	}
	return c.SetRaw(TagVLANEngineMode, []byte{byte(mode)})
}

// SetIGMPSnooping enables or disables IGMP snooping and sets the VLAN ID.
//
// Enabled is 0=disabled, 1=enabled. VLANID is the IGMP snooping VLAN.
// Payload layout: {enabled u16 BE, vlan_id u16 BE} = 4 bytes. When
// disabled the whole payload is zeroed: ProSafeLinux sends {0,0} for
// "none" — the VLAN is not retained while snooping is off.
// CONFIRMED layout: ProSafeLinux PslTypIGMPSnooping plus the firmware
// SET handler (bank1 0x8477), which reads both u16 fields and commits
// the "igmpsnoop" config section.
func (c *Client) SetIGMPSnooping(enabled bool, vlanID uint16) error {
	return c.SetRaw(TagIGMPSnooping, buildIGMPSnoopingPayload(enabled, vlanID))
}

// buildIGMPSnoopingPayload builds the 4-byte IGMP snooping payload
// {enabled u16 BE, vlan u16 BE}; disabled zeroes the whole payload.
func buildIGMPSnoopingPayload(enabled bool, vlanID uint16) []byte {
	buf := make([]byte, 4)
	if enabled {
		binary.BigEndian.PutUint16(buf[0:], 1)
		binary.BigEndian.PutUint16(buf[2:], vlanID)
	}
	return buf
}

// SetBlockUnknownMulticast configures whether unknown multicast traffic
// is blocked. This is a global toggle on the GS108Ev3 firmware, not a
// per-port setting.
//
// Payload layout: {blocked u8} = 1 byte.
// CONFIRMED: ProSafeLinux PslTypBoolean packs exactly one byte, and the
// firmware SET handler (bank1 0x7c58) likewise reads a single value
// byte, validates it, and commits the "mcast" config section.
func (c *Client) SetBlockUnknownMulticast(blocked bool) error {
	return c.SetRaw(TagBlockUnknownMulticast, buildBoolPayload(blocked))
}

// SetIGMPHeaderValidation enables or disables IGMP header validation.
//
// Enabled is true/false. Payload layout: {enabled u8} = 1 byte.
// CONFIRMED: ProSafeLinux CMD_IGMP_HEADER_VALIDATION plus the firmware
// SET handler (bank1 0x7c38): single value byte, "igmpsnoop" section.
func (c *Client) SetIGMPHeaderValidation(enabled bool) error {
	return c.SetRaw(TagIGMPHeaderValidation, buildBoolPayload(enabled))
}

// buildBoolPayload builds the 1-byte payload {0|1} used by the firmware's
// single-value boolean SETs (0x6c00 block unknown multicast, 0x7000 IGMP
// header validation).
func buildBoolPayload(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}

// --- VLAN config SETs -----------------------------------------------------

// SetPortBasedVLAN adds or modifies a port-based VLAN membership.
//
// VLANID is the VLAN identifier. Ports is a list of 1-based port numbers
// to include in the VLAN.
// Payload layout: {vlan_id u16 BE, port_bitmap u8} = 3 bytes.
// CONFIRMED layout (ProSafeLinux PslTypVlanId pack_py).
func (c *Client) SetPortBasedVLAN(vlanID int, ports []int) error {
	if vlanID < 0 || vlanID > 4095 {
		return fmt.Errorf("nsdp: vlan id %d out of range [0,4095]", vlanID)
	}
	buf := make([]byte, 3)
	binary.BigEndian.PutUint16(buf[0:], uint16(vlanID))
	buf[2] = PortBitmap(ports)
	return c.SetRaw(TagPortBasedVLAN, buf)
}

// Set8021QVLAN adds or modifies an 802.1Q VLAN with tagged and untagged
// port assignments.
//
// ─── ROUND 19 layout (live evidence, casalta probe 2026-09-12,
// gaps-20260912-163538.log) ───
// The 0x2800 entry is {vlan_id u16 BE, MEMBER bitmap u8, TAGGED bitmap
// u8} — untagged is DERIVED (member AND NOT tagged), never carried on
// the wire. The earlier ProSafeLinux-derived tagged/untagged two-bitmap
// payload is FALSIFIED: the stage-2 SET {03 e7 20 08} read under the
// real model as members {3}, tagged {5} — tagged not a subset of
// members — and the firmware silently dropped the whole membership,
// storing VLAN 999 EMPTY with an OK reply (its known silent-no-op
// behavior; the provider's verify-corrective layer exists for exactly
// this). The payload below therefore sends byte2 = the member superset
// (tagged|untagged) and byte3 = the tagged subset.
// ───────────────────────────────────────────────────────────────────
//
// VLANID is the VLAN identifier. TaggedPorts and UntaggedPorts are lists
// of 1-based port numbers.
// Payload layout: {vlan_id u16 BE, member_bitmap u8, tagged_bitmap u8} = 4 bytes,
// where member_bitmap = PortBitmap(tagged|untagged).
// LIVE-PROVEN entry model (ROUND 19); payload derived from the same
// member/tagged wire model the six production VLANs fit with zero
// contradictions.
func (c *Client) Set8021QVLAN(vlanID int, taggedPorts, untaggedPorts []int) error {
	if vlanID < 0 || vlanID > 4095 {
		return fmt.Errorf("nsdp: vlan id %d out of range [0,4095]", vlanID)
	}
	return c.SetRaw(Tag8021QVLAN, vlan8021QPayload(vlanID, taggedPorts, untaggedPorts))
}

// vlan8021QPayload builds the 4-byte tag-0x2800 SET value
// {vlan_id u16 BE, member, tagged} under the ROUND 19 wire model:
// byte2 is the member superset (tagged|untagged), byte3 the tagged
// subset. Extracted like portConfigPayload so the payload bytes are
// unit-testable without network I/O (TestSet8021QVLANPayload).
func vlan8021QPayload(vlanID int, taggedPorts, untaggedPorts []int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:], uint16(vlanID))
	buf[2] = PortBitmap(taggedPorts) | PortBitmap(untaggedPorts)
	buf[3] = PortBitmap(taggedPorts)
	return buf
}

// Delete8021QVLAN deletes an 802.1Q VLAN entry.
//
// The payload is the VLAN ID as u16 BE. LIVE-PROVEN both directions
// (casalta probe, 2026-09-12, gaps-20260912-163538.log stage 4): deleting
// the existing VLAN 999 removed it while every other 0x2800 entry stayed
// byte-identical, and the missing-VLAN delete is a no-op — the firmware
// SET handler (bank1 0x8174) passes the value through a bank5 helper
// (0x1916 -> 0xe10e) whose check is NOT an existence test, so
// Delete8021QVLAN is idempotent. Layout: {vlan_id u16 BE} = 2 bytes.
// CONFIRMED (live probe + firmware; the tag is absent from
// ProSafeLinux).
func (c *Client) Delete8021QVLAN(vlanID int) error {
	if vlanID < 0 || vlanID > 4095 {
		return fmt.Errorf("nsdp: vlan id %d out of range [0,4095]", vlanID)
	}
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf[0:], uint16(vlanID))
	return c.SetRaw(TagDelete8021QVLAN, buf)
}

// --- Read helpers ---------------------------------------------------------

// GetIP reads the switch IP address (GET tag 0x06) and returns it as net.IP,
// or nil when the switch did not return a value.
func (c *Client) GetIP() (net.IP, error) {
	val, err := c.GetAttr(0x06)
	if err != nil {
		return nil, err
	}
	if len(val) != 4 {
		return nil, fmt.Errorf("nsdp: IP address TLV has %d bytes, want 4", len(val))
	}
	return net.IP(val), nil
}

// GetSubnetMask reads the switch subnet mask (GET tag 0x07) and returns
// it as net.IP, or nil when the switch did not return a value.
func (c *Client) GetSubnetMask() (net.IP, error) {
	val, err := c.GetAttr(0x07)
	if err != nil {
		return nil, err
	}
	if len(val) != 4 {
		return nil, fmt.Errorf("nsdp: subnet mask TLV has %d bytes, want 4", len(val))
	}
	return net.IP(val), nil
}

// GetGateway reads the switch gateway address (GET tag 0x08) and returns
// it as net.IP, or nil when the switch did not return a value.
func (c *Client) GetGateway() (net.IP, error) {
	val, err := c.GetAttr(0x08)
	if err != nil {
		return nil, err
	}
	if len(val) != 4 {
		return nil, fmt.Errorf("nsdp: gateway TLV has %d bytes, want 4", len(val))
	}
	return net.IP(val), nil
}

// GetLocation reads the switch system location (GET tag 0x05) and returns
// it as an ASCII string, or empty string when no value is present.
func (c *Client) GetLocation() (string, error) {
	val, err := c.GetAttr(0x05)
	if err != nil {
		return "", err
	}
	return asciiTrim(val), nil
}

// SetLocation sets the switch system location (SET tag 0x05).
// The payload is a plaintext ASCII string.
func (c *Client) SetLocation(location string) error {
	return c.SetRaw(TagSystemLocation, []byte(location))
}

// --- Management config SETs -----------------------------------------------

// SetIPAddress sets the switch IP address (SET tag 0x0006).
// addr is a dotted-quad IPv4 string (e.g. "10.0.0.1").
func (c *Client) SetIPAddress(addr string) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("nsdp: invalid IP address %q", addr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("nsdp: not an IPv4 address %q", addr)
	}
	return c.SetRaw(TagIPAddress, ip4)
}

// SetSubnetMask sets the switch subnet mask (SET tag 0x0007).
// mask is a dotted-quad IPv4 string (e.g. "255.255.255.0").
func (c *Client) SetSubnetMask(mask string) error {
	ip := net.ParseIP(mask)
	if ip == nil {
		return fmt.Errorf("nsdp: invalid subnet mask %q", mask)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("nsdp: not an IPv4 address %q", mask)
	}
	return c.SetRaw(TagSubnetMask, ip4)
}

// SetGatewayAddr sets the switch gateway address (SET tag 0x0008).
// addr is a dotted-quad IPv4 string (e.g. "10.0.0.254").
func (c *Client) SetGatewayAddr(addr string) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("nsdp: invalid gateway %q", addr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("nsdp: not an IPv4 address %q", addr)
	}
	return c.SetRaw(TagGatewayAddr, ip4)
}

// SetDHCPMode sets the switch DHCP mode (SET tag 0x000b).
// mode is 0=Static, 1=DHCP, 2=Refresh DHCP.
func (c *Client) SetDHCPMode(mode DHCPMode) error {
	if mode > 2 {
		return fmt.Errorf("nsdp: dhcp mode %d out of range [0,2]", mode)
	}
	return c.SetRaw(TagDHCPMode, []byte{byte(mode)})
}
