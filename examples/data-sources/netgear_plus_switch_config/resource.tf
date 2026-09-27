provider "netgear" {
  host     = "192.0.2.20" # placeholder: your gs108tv2 switch's hostname or URL
  password = "REPLACE_WITH_SWITCH_PASSWORD"
  model    = "gs108tv2"
}

# Reads the switch's startup-config over the FASTPATH text-config channel.
# `content` differs on every read (the switch re-stamps !System Up Time);
# `canonical` is the stable copy for diffs and drift checks.
data "netgear_plus_switch_config" "startup" {}

output "config_header" {
  value = {
    system_description     = data.netgear_plus_switch_config.startup.system_description
    system_software_version = data.netgear_plus_switch_config.startup.system_software_version
  }
}

output "config_canonical" {
  value = data.netgear_plus_switch_config.startup.canonical
}
