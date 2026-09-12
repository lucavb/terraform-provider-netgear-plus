provider "netgear" {
  host     = "192.0.2.10" # placeholder: your switch's hostname or URL
  password = "REPLACE_WITH_SWITCH_PASSWORD"
}

data "netgear_plus_switch" "target" {}

# The serial number is what you pin write operations with:
#
# resource "netgear_plus_vlan_state" "switch" {
#   expected_serial_number = data.netgear_plus_switch.target.serial_number
#   # ...
# }

output "switch_identity" {
  value = {
    model            = data.netgear_plus_switch.target.model
    serial_number    = data.netgear_plus_switch.target.serial_number
    mac_address      = data.netgear_plus_switch.target.mac_address
    firmware_version = data.netgear_plus_switch.target.firmware_version
    switch_name      = data.netgear_plus_switch.target.switch_name
  }
}
