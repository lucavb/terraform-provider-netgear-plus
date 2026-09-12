provider "netgear" {
  agent_mac = "8c:3b:ad:25:1b:88" # placeholder: your switch's MAC address
  interface = "en0"               # placeholder: local NIC used for NSDP broadcast
  password  = "REPLACE_WITH_SWITCH_PASSWORD"
}

resource "netgear_plus_switch_settings" "switch" {
  # All factory defaults except one flip:

  qos_mode                = "port-based"
  block_unknown_multicast = true

  # Port mirroring stays disabled: destination 0, no source ports.
  # To enable it instead:
  #   mirror_destination_port = 6
  #   mirror_source_ports     = [1, 2]
  mirror_destination_port = 0
}
