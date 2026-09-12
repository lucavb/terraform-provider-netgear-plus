provider "netgear" {
  host     = "192.0.2.10" # placeholder: your switch's hostname or URL
  password = "REPLACE_WITH_SWITCH_PASSWORD"
}

# Read the live VLAN and PVID state before managing it authoritatively
# with the netgear_plus_vlan_state resource: copy these values into the
# resource first, then make one additive change at a time.

data "netgear_plus_vlan_state" "current" {}

output "live_vlans" {
  value = data.netgear_plus_vlan_state.current.vlan
}

output "live_pvids" {
  value = data.netgear_plus_vlan_state.current.pvids
}
