provider "netgear" {
  host     = "192.0.2.10" # placeholder: your switch's hostname or URL
  password = "REPLACE_WITH_SWITCH_PASSWORD"
}

# This resource is authoritative: `vlan` blocks plus `pvids` describe the
# complete desired state. Read the live state first with the
# netgear_plus_vlan_state data source and copy it in before changing it.
# Keep allow_vlan_deletions = false for first live use.

resource "netgear_plus_vlan_state" "switch" {
  expected_serial_number = "SERIAL1234567890" # placeholder: from data.netgear_plus_switch
  allow_vlan_deletions   = false

  vlan {
    id = 1
    ports = {
      "1" = "untagged"
      "2" = "untagged"
      "5" = "untagged"
      "6" = "untagged"
      "7" = "untagged"
      "8" = "tagged"
    }
  }

  vlan {
    id = 10
    ports = {
      "3" = "untagged"
      "4" = "untagged"
      "8" = "tagged"
    }
  }

  # The PVID map must cover all 8 ports, and each port's PVID VLAN must
  # include that port as a member.
  pvids = {
    "1" = 1
    "2" = 1
    "3" = 10
    "4" = 10
    "5" = 1
    "6" = 1
    "7" = 1
    "8" = 1
  }
}
