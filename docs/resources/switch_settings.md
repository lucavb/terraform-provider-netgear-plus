---
page_title: "netgear_plus_switch_settings Resource"
subcategory: ""
description: |-
  Manage global switch settings on an NSDP-managed Netgear Plus GS108Ev3 switch: QoS scheduling mode, unknown-multicast blocking, and port mirroring.
---

# netgear_plus_switch_settings Resource

`netgear_plus_switch_settings` manages the global switch settings: the QoS scheduling mode, unknown-multicast blocking, and port mirroring.

One instance of this resource models the whole switch; the attributes are globals, not per-port settings. Per-port QoS priorities and rate limits belong to `netgear_plus_port_config`.

The resource uses the NSDP protocol. It requires the `agent_mac` provider attribute, not `host`.

## Behavior

- Applies are diff-then-verify: the provider reads the current settings, sends only the SETs for values that differ (QoS mode, then multicast blocking, then one mirroring SET that carries destination and source ports together), and reads the switch back. If the readback still disagrees with the plan, one corrective pass is sent, and any remaining difference becomes a typed drift error naming the field.
- A from-factory apply is a no-op: the defaults are the factory values (`qos_mode = "port-based"`, `block_unknown_multicast = false`, mirroring disabled).
- If the switch does not answer a SET (reply lost), the provider never re-sends it. It records a warning and settles the question with the verification read instead.
- Destroy removes Terraform state only. The switch keeps its configuration; the existing settings are never rolled back.

These SETs are implemented from the vendor's protocol sources but have not yet been validated against live hardware. A write the switch silently ignores surfaces as a typed drift error, never as false success.

## Example Usage

```hcl
provider "netgear" {
  agent_mac = "8c:3b:ad:25:1b:88" # placeholder: your switch's MAC address
  interface = "en0"                # placeholder: local NIC used for NSDP broadcast
  password  = "REPLACE_WITH_SWITCH_PASSWORD"
}

resource "netgear_plus_switch_settings" "switch" {
  # All factory defaults except one flip:

  qos_mode                 = "port-based"
  block_unknown_multicast   = true

  # Port mirroring stays disabled (destination 0, no source ports).
  mirror_destination_port = 0
}
```

## Argument Reference

- `qos_mode` - (Optional) Global QoS scheduling mode. Defaults to `port-based`, the factory value. Valid values: `port-based` (scheduling by the per-port priorities configured in `netgear_plus_port_config`) and `802.1p` (priority taken from the 802.1p field of tagged frames).
- `block_unknown_multicast` - (Optional) Block unknown multicast traffic, a global toggle. Defaults to `false`, the factory value.
- `mirror_destination_port` - (Optional) Mirror destination (sniffer) port, 1-8; `0` disables port mirroring. Defaults to `0`, the factory value.
- `mirror_source_ports` - (Optional) Set of mirror source ports, each 1-8. Defaults to the empty set.

The mirroring attributes are validated as a pair:

- `mirror_source_ports` must be empty when `mirror_destination_port` is `0` (mirroring disabled).
- `mirror_source_ports` must name at least one port when `mirror_destination_port` is not `0`.
- The destination port must not also appear in `mirror_source_ports`.

## Attribute Reference

- `id` - Stable switch identifier, in the form `nsdp@<agent MAC>`.

## Import

Import by the resource ID, which is `nsdp@` followed by the switch's agent MAC address:

```sh
terraform import netgear_plus_switch_settings.switch nsdp@8c:3b:ad:25:1b:88
```
