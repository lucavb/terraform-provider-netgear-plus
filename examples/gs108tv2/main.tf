terraform {
  required_providers {
    netgear = {
      source = "registry.terraform.io/lucavb/netgear-plus"
    }
  }
}

variable "switch_password" {
  type      = string
  sensitive = true
}

# host drives the text-config channel (the two resources below and the
# config backup data source); agent_mac drives the NSDP v1 identity reads
# that carry the serial number the resources pin against. With both set,
# NSDP is sent unicast to host, so one address serves both channels.
provider "netgear" {
  host      = "192.0.2.20"        # placeholder: your switch's address
  password  = var.switch_password
  model     = "gs108tv2"
  agent_mac = "8c:3b:ad:2c:e9:7d" # placeholder: your switch's MAC
  interface = "en0"               # placeholder: NIC used for NSDP identity reads
}

# Read the stable startup-config backup first. Its canonical copy is
# usable as a drift comparand; its content is the exact file the provider
# stages against. The `spanning-tree configuration name` line inside
# content carries the switch's MAC if you need to discover agent_mac.
data "netgear_plus_switch_config" "startup" {}

# Identity facts (switch name, MAC, serial) come from NSDP v1, so this
# data source needs agent_mac on gs108tv2. Its serial_number is what the
# resources pin expected_serial_number with.
data "netgear_plus_switch" "target" {}

output "startcfg_system" {
  value = {
    system_description     = data.netgear_plus_switch_config.startup.system_description
    system_software_version = data.netgear_plus_switch_config.startup.system_software_version
  }
}

output "switch_serial" {
  value = data.netgear_plus_switch.target.serial_number
}

# Authoritative VLAN state on the FASTPATH config channel.
#
# STAGE-ONLY: applies rewrite the SWITCH'S STARTUP-CONFIG and do not
# reboot it. The running configuration stays put until the switch's next
# boot, and `changes_pending` in the state tells you a staged change is
# waiting. Reads and drift detection compare the startup-config.
resource "netgear_plus_vlan_state" "switch" {
  expected_serial_number = data.netgear_plus_switch.target.serial_number

  # Keep this false for first live use, same as on gs108ev3.
  allow_vlan_deletions = false

  # reboot_to_apply = true would reboot the switch after every staged
  # apply so changes take effect immediately, but on this firmware build
  # it is refused with an actionable error until the gs108tv2 reboot
  # endpoint is pinned for FASTPATH 5.4.2.36 (live pinning pending).
  # Staging works without it: changes activate on the switch's next boot.

  vlan {
    id = 1
    ports = {
      "1" = "untagged"
      "2" = "untagged"
      "5" = "untagged"
      "6" = "untagged"
      "7" = "untagged"
      "8" = "untagged"
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

# Authoritative port settings on the FASTPATH config channel.
#
# On gs108tv2 this resource manages `enabled` and `flow_control` at the
# moment; qos_priority / ingress_rate / egress_rate refuse non-default
# values with a typed per-port error until that firmware's grammar is
# pinned, so they are left at their defaults here (default = absence in
# the config file, exactly what the factory emits).
resource "netgear_plus_port_config" "switch" {
  ports {
    port = 1
  }

  ports {
    port = 2
  }

  ports {
    port         = 3
    flow_control = true
  }

  ports {
    port = 4
  }

  ports {
    port = 5
  }

  ports {
    port    = 6
    enabled = false
  }

  ports {
    port = 7
  }

  ports {
    port = 8
    # qos_priority  = "low"   # accepted, but "high"/rates refuse:
    # ingress_rate  = "none"  # leave unset on gs108tv2 for now.
  }
}

# Both applies above stage into the startup-config without rebooting, so
# after a successful `apply` the switch may still be running its old
# configuration until you reboot it (or set reboot_to_apply once the
# endpoint pin lands).
