---
page_title: "netgear_plus_switch_config Data Source"
subcategory: ""
description: |-
  Read the FASTPATH startup-config of a GS108Tv2/GS110TPv2-class switch verbatim over the switch's web UI file channel.
---

# netgear_plus_switch_config Data Source

Use `netgear_plus_switch_config` to read a model `gs108tv2` switch's startup-config verbatim.

The data source requires the provider model attribute to be `gs108tv2` and the provider `host` and `password` attributes: the FASTPATH text-config channel transfers over the switch's web UI (emweb), which needs the switch's routable address and the admin password. Reads run under the provider's per-device lock and pacing like every other operation against the same switch.

The transfer performs a session login, an arming GET, and then reads the startup-config file: the firmware copies its stored `nvram:startup-config` to a backup and serves it as plain text, NSDP text-config header line intact (the same header the firmware validates when a config is restored).

## Example Usage

```hcl
provider "netgear" {
  host     = "192.0.2.20"
  password = var.switch_password
  model    = "gs108tv2"
}

data "netgear_plus_switch_config" "startup" {}

output "config_fingerprint" {
  value = data.netgear_plus_switch_config.startup.canonical
}
```

Because the file carries the switch's own NSDP text-config header, `canonical` also makes a solid drift comparand: hash it (or store it) between runs to tell "something really changed in the config" apart from "the switch ticked over a minute".

## Why `content` always changes between reads

The startup-config embeds a `!System Up Time` stamp near the top, and the switch re-stamps it on **every** export. Consecutive reads of an unchanged switch return different `content` values — and different content hashes. Never compare `content` against previous runs.

`canonical` is the same file with the `!System Up Time` line excluded. Two reads of a switch whose configuration did not change return identical `canonical` values. Use `canonical` for diffs, state snapshots, and drift detection; use `content` only when you need the byte-exact file (for example to upload it back verbatim).

## Attribute Reference

- `canonical` - The startup-config bytes with the `!System Up Time` stamp line excluded. This is the stable comparand: two reads that agree except for the uptime stamp have identical `canonical` values, while `content` always differs between reads.
- `content` - The verbatim text configuration file, NSDP magic header line intact (the firmware validates this header on restore).
- `id` - Resource identity, in the form `fastpath@<host>/startup-config`.
- `system_description` - From the `!System Description` annotation (for example `GS108Tv2`) — the product family marker the switch itself compares on config restore.
- `system_software_version` - From the `!System Software Version` annotation — the firmware revision marker restore validation compares.

## Related

- `netgear_plus_vlan_state` with provider model `gs108tv2` stages VLAN changes into this same startup-config file (see its gs108tv2 section).
- `netgear_plus_port_config` with provider model `gs108tv2` stages port settings into it.
