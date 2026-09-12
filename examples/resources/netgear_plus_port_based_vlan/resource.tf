provider "netgear" {
  agent_mac = "8c:3b:ad:25:1b:88" # placeholder: your switch's MAC address
  interface = "en0"               # placeholder: local NIC used for NSDP broadcast
  password  = "REPLACE_WITH_SWITCH_PASSWORD"
}

# NOTE: this resource only applies while the switch's VLAN engine is in
# port-based mode. In 802.1Q modes it refuses to touch the table; manage
# those VLANs with netgear_plus_vlan_state instead.

resource "netgear_plus_port_based_vlan" "switch" {
  vlans {
    vlan_id = 1
    ports   = [1, 2, 3, 4, 5, 6, 7, 8]
  }

  vlans {
    vlan_id = 10
    ports   = [1, 2, 3] # overlapping with VLAN 1 is valid for port-based VLANs
  }
}
