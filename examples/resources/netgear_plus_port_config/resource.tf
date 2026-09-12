provider "netgear" {
  agent_mac = "8c:3b:ad:25:1b:88" # placeholder: your switch's MAC address
  interface = "en0"               # placeholder: local NIC used for NSDP broadcast
  password  = "REPLACE_WITH_SWITCH_PASSWORD"
}

resource "netgear_plus_port_config" "switch" {
  # Exactly one ports block per physical port, 1 through 8.
  # Attributes left out keep their factory defaults.

  ports {
    port = 1
  }

  ports {
    port = 2
  }

  ports {
    port         = 3
    qos_priority = "high"
    ingress_rate = "1m"
  }

  ports {
    port = 4
  }

  ports {
    port = 5
  }

  ports {
    port = 6
  }

  ports {
    port = 7
  }

  ports {
    port        = 8
    enabled     = false
    egress_rate = "512k"
  }
}
