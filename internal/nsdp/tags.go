package nsdp

// Tag constants and the tag→name table for the NSDP command dictionaries:
// the nsdpmanager.exe decode + reply parser FUN_0048edc0 (RE notes ROUND
// 6/7) cross-checked against three third-party sources (RE notes ROUND
// 9/9b/10: the 2012 ProSafeLinux Python tool + its Wireshark dissector,
// the Sven Anders Linux-Magazin article, and the Wikipedia NSDP article).
//
// Small tags are 0x00NN. Family/extended tags are 0xNN00, where the
// "block id" NN IS the tag high byte (ROUND 6 block↔tag unification: a
// block GET is TLV{marker 0x0014, len 0} + TLV{tag 0xNN00, len, selector}).
//
// Name-table entries marked "(?)" are tags whose meaning the sources do
// not pin; the reply VALUE format may still be known (see dump.go for the
// decoders).
//
// PORT NUMBERING IS 1-BASED everywhere a per-port layout carries a port
// byte (ProSafeLinux psl_typ.py BIN_PORTS maps port 1→bit 0x80 … 8→0x01;
// all confirmed per-port layouts below use 1-based port numbers).

// Small reply/GET tags (0x00NN). "(?)" = name not pinned by any source.
const (
	TagProductName uint16 = 0x0001 // model string
	TagModelCode   uint16 = 0x0002 // BE16 model code
	TagSystemName  uint16 = 0x0003 // system name string
	TagMACAddress  uint16 = 0x0004 // raw 6-byte MAC
	// 0x0005 = device system LOCATION string (wireshark "Location" +
	// ProSafeLinux CMD_LOCATION + Wikipedia agree; corrects the old
	// "string, meaning unknown" label).
	TagSystemLocation uint16 = 0x0005

	// 0x06/0x07/0x08 = IP address / netmask / gateway. Three sources
	// agree (nsdpmanager SET dict + ProSafeLinux CMD_IP/NETMASK/GATEWAY +
	// wireshark; Wikipedia calls 0x0008 "Router IP-address"), correcting
	// the early "gateway at 07 / dhcp at 08" guess. All decode identically
	// (BE32 → net.IP).
	TagIPAddress   uint16 = 0x0006 // BE32 IPv4 address
	TagSubnetMask  uint16 = 0x0007 // BE32 netmask
	TagGatewayAddr uint16 = 0x0008 // BE32 gateway (router IP)

	// Password TLVs are SET-only and encrypted on nonce-capable firmware
	// (V1/V2 hash over old+new; nsdpmanager FUN_004879f0). 0x0009 = NEW
	// password, 0x000A = OLD/CURRENT password — per ProSafeLinux
	// (CMD_NEW_PASSWORD=0x0009, CMD_PASSWORD=0x000a), wireshark ("New
	// Password"/"Password") and the Linux-Magazin exploit frames (0x0009
	// new before 0x000A old). This corrects the previous 9=OLD/10=NEW
	// assignment. 0x000A also doubles as the PLAINTEXT auth TLV tag in the
	// no-nonce login branch (plaintext login sends {0x000A, len, pw}).
	TagNewPassword uint16 = 0x0009 // new password (encrypted SET-only)
	TagOldPassword uint16 = 0x000a // old/current password (encrypted SET-only; plaintext auth TLV in the no-nonce login branch)

	// 0x000b = DHCP MODE enum: 0=Static, 1=DHCP, 2=Refresh DHCP
	// (Wikipedia + ProSafeLinux + wireshark agree — corrects the old
	// "port/link flag" mislabel).
	TagDHCPMode      uint16 = 0x000b
	TagScalar000c    uint16 = 0x000c // u8, name not pinned
	TagFirmware1     uint16 = 0x000d // firmware image 1 string
	TagFirmware2     uint16 = 0x000e // firmware image 2 string
	TagActiveImage   uint16 = 0x000f // u8, low nibble = active image number
	TagString0011    uint16 = 0x0011 // login info blob: live value is a nested-TLV composite {0x0014 cap} + {0x0017 nonce} + trailing
	TagScalar0012    uint16 = 0x0012 // login composite marker (legacy name kept): empty, or the same nested composite as 0x0011
	TagCapabilityTag uint16 = 0x0014 // BE32 capability word
	TagNonceTag      uint16 = 0x0017 // raw 4-byte nonce
	TagReboot        uint16 = 0x0013 // reboot action (SET-only; ProSafeLinux CMD_REBOOT + wireshark + ROUND 9 notes)
)

// Family/extended tags (0xNN00): NN is the block id.
const (
	TagFactoryDefaults uint16 = 0x0400 // TLV_FACTORY_DEFAULTS (1-byte SET)
	// 0x0c00 = per-port SPEED/LINK STATUS: 3B {port u8 1-BASED, speed u8,
	// flow u8}. ProSafeLinux PslTypSpeedStat + wireshark "Speed/Link
	// Status" agree (2-of-3 sources) — resolves the old "unknown block
	// 0x0c" label. Byte 2 = link speed 0..5; byte 3 = the flow-control
	// flag mirroring the 0x9400 flow byte (ROUND 18), NOT the link state.
	TagSpeedLinkStatus uint16 = 0x0c00
	// 0x1000 = PER-PORT TRAFFIC STATISTICS: 49-byte entries {port u8
	// 1-BASED, received/sent/packets/broadcast/multicast/errors 6×u64 BE}
	// (ProSafeLinux PslTypPortStat "!b6Q" + wireshark "Port Traffic
	// Statistic" + Wikipedia — 3 sources agree). Corrects the ROUND 7
	// "serial blob" mislabel: the serial number is tag 0x7800 (21-byte
	// string), NOT this tag.
	TagPortTrafficStats uint16 = 0x1000
	// 0x1400 = reset per-port traffic statistics (SET-only action;
	// ProSafeLinux CMD_RESET_PORT_STAT + wireshark agree).
	TagResetPortStats  uint16 = 0x1400
	TagCableTest       uint16 = 0x1800 // TLV_CABLE_TEST
	TagVLANEngineMode  uint16 = 0x2000 // VLAN engine mode: 1B enum (PSL PslTypVlanSupport + wireshark agree, 2-of-3 sources)
	TagPortBasedVLAN   uint16 = 0x2400 // TLV_PORT_BASED_VLAN — VLAN-ID → port bitmap entries
	Tag8021QVLAN       uint16 = 0x2800 // TLV_8021Q_VLAN
	TagDelete8021QVLAN uint16 = 0x2c00 // TLV_DELETE_8021Q_VLAN
	TagPVID            uint16 = 0x3000 // TLV_PVID — 3B {port u8 1-BASED, vlan_id u16 BE} CONFIRMED (ProSafeLinux psl_typ.py:595-612; 2-of-3 sources: wireshark names the tag, only PSL pins the layout)
	// 0x3400 = QoS MODE: 1B {mode u8: 1=port-based, 2=802.1p}. CONFIRMED:
	// firmware SET handler (bank1 0x7b98) accepts only 1-2 and answers
	// anything else with the invalid-value reject; ProSafeLinux PslTypQos
	// pins the same values.
	TagQoSMode            uint16 = 0x3400
	TagPortBasedQoS       uint16 = 0x3800 // TLV_PORT_BASED_QoS — 2B {port u8 1-BASED, priority u8: 1=High, 2=Middle, 3=Normal, 4=Low} CONFIRMED (ProSafeLinux psl_typ.py:680-734; 2-of-3 sources)
	TagIngressRate        uint16 = 0x4c00 // TLV_INGRESS_RATE — 5B {port u8 1-BASED, 00 00 reserved, limit u16 BE} CONFIRMED (ProSafeLinux PslTypBandwidth; corrects ROUND 7's "4+1 concat" artifact)
	TagEgressRate         uint16 = 0x5000 // inferred name; same CONFIRMED 5B bandwidth layout (PSL CMD_BANDWIDTH_OUTGOING_LIMIT)
	TagBroadcastStormRate uint16 = 0x5800 // TLV_BROADCAST_STORM_RATE — same CONFIRMED 5B bandwidth layout (PSL CMD_BROADCAST_BANDWIDTH)
	// 0x5c00 = PORT MIRRORING: 3B {dst_port u8 (0=disabled), reserved u8
	// (semantics unknown — "fixme" in PSL), src_ports u8 bitmap}. 2-of-3
	// sources: ProSafeLinux PslTypPortMirror pins the layout; the
	// nsdpmanager reply parser instead reported a string form.
	TagPortMirroring uint16 = 0x5c00
	TagPortCount     uint16 = 0x6000 // number of available ports (PSL CMD_NUMBER_OF_PORTS + wireshark agree)
	// 0x6800 = IGMP SNOOPING: 4B {enabled u16 BE (0=off, 1=on),
	// vlan_id u16 BE} — ProSafeLinux PslTypIGMPSnooping and the ROUND 7
	// reply parser (2 × BE16) agree.
	TagIGMPSnooping          uint16 = 0x6800
	TagBlockUnknownMulticast uint16 = 0x6c00 // block unknown multicast per-port
	TagIGMPHeaderValidation  uint16 = 0x7000 // IGMP header validation per-port
	TagFWConfigString        uint16 = 0x7400 // fw/config string (BLOCK 0x74 "mystery resolved")
	TagSerialNumber          uint16 = 0x7800 // serial number string, 21 bytes (BLOCK 0x78; nsdp.js + docs + Linux-Magazin recovery-password role)
	TagStaticRouterPort      uint16 = 0x8000 // TLV_IGS_STATIC_ROUTER_PORT (SET); replies carry a fw image string
	TagLAGroupSetting        uint16 = 0x8800 // TLV_LA_GROUP_SETTING — reply layout UNVERIFIED (multi-entry)
	TagPortAdminStatus       uint16 = 0x9400 // TLV_PORT_ADMIN_STATUS — {port u8, admin u8 (1=enabled), flow-control u8 (1=on)} per-port entries — semantics live-proven via web UI (ROUND 18)
	TagOneToOneMirror        uint16 = 0x9c00 // TLV_ONE_TO_ONE_MIRROR — reply carries len-3 "VLAN config" entries
	TagLoginSwitch           uint16 = 0xe400 // TLV_LOGIN_SWITCH (auth TLV only)
	TagSetDeviceInfo         uint16 = 0xe800 // TLV_SET_DEVICE_INFO (IP/mask/gateway/DHCP bundle)
	TagExtension             uint16 = 0xf400 // TLV_EXTENSION (4-byte BE32 selector)
)

// tagNames maps known tags to short human-readable names for dumps.
var tagNames = map[uint16]string{
	TagProductName:    "product name (model)",
	TagModelCode:      "model code",
	TagSystemName:     "system name",
	TagMACAddress:     "mac address",
	TagSystemLocation: "system location",
	TagIPAddress:      "ip address",
	TagSubnetMask:     "subnet mask",
	TagGatewayAddr:    "gateway address",
	TagNewPassword:    "new password (encrypted SET-only)",
	TagOldPassword:    "old password (encrypted SET-only; plaintext auth TLV in no-nonce login)",
	TagDHCPMode:       "dhcp mode (0=static 1=dhcp 2=refresh)",
	TagScalar000c:     "scalar 0x0c (?)",
	TagFirmware1:      "firmware image 1",
	TagFirmware2:      "firmware image 2",
	TagActiveImage:    "active image",
	TagString0011:     "login info blob",
	TagScalar0012:     "login composite marker",
	TagReboot:         "reboot (SET-only)",
	TagCapabilityTag:  "capability word",
	TagNonceTag:       "nonce (raw 4 bytes)",

	TagFactoryDefaults:    "factory defaults (1-byte SET)",
	TagSpeedLinkStatus:    "speed/link status (per port)",
	TagPortTrafficStats:   "per-port traffic statistics",
	TagResetPortStats:     "reset per-port traffic statistics (SET-only)",
	TagCableTest:          "cable test",
	TagVLANEngineMode:     "vlan engine mode",
	TagPortBasedVLAN:      "port based vlan (vlan id → port bitmap)",
	Tag8021QVLAN:          "802.1q vlan",
	TagDelete8021QVLAN:    "delete 802.1q vlan",
	TagPVID:               "pvid (per port)",
	TagQoSMode:            "qos mode (global)",
	TagPortBasedQoS:       "port based qos (per port)",
	TagIngressRate:        "ingress rate limit (per port)",
	TagEgressRate:         "egress rate limit (inferred name; per port)",
	TagBroadcastStormRate: "broadcast storm rate limit (per port)",
	TagPortMirroring:      "port mirroring",
	TagPortCount:          "number of ports",
	TagIGMPSnooping:       "igmp snooping",
	0x6c00:                "block unknown multicasts",
	0x7000:                "igmp header validation",
	TagFWConfigString:     "fw/config string",
	TagSerialNumber:       "serial number",
	0x7c00:                "registration (1-byte SET toggle; firmware commits the 'registration' section)",
	TagStaticRouterPort:   "fw image string (SET: igs static router port)",
	0x8400:                "scalar 0x8400 (?)",
	TagLAGroupSetting:     "la group setting (layout UNVERIFIED)",
	0x8c00:                "scalar 0x8c00 (?)",
	0x9000:                "loop detection (1-byte SET toggle; firmware commits the 'loopdetect' section)",
	TagPortAdminStatus:    "port admin status",
	TagOneToOneMirror:     "one-to-one mirror (reply: vlan config entry?)",
	0xa000:                "scalar 0xa000 (?)",
	0xa800:                "broadcast storm control (?)",
	0xac00:                "scalar 0xac00 (?)",
	0xb000:                "string blob 0xb000 (?)",
	TagLoginSwitch:        "login switch",
	TagSetDeviceInfo:      "set device info",
	0xec00:                "config bundle 0xec00 (?)",
	0xf000:                "scalar 0xf000 (?)",
	TagExtension:          "extension",
	0xf800:                "scalar 0xf800 (?)",
}

// TagName returns the dictionary name for tag, or "" when the tag is not in
// the ROUND 6/7/9/10 dictionaries.
func TagName(tag uint16) string {
	return tagNames[tag]
}
