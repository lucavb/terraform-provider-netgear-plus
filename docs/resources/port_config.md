---
page_title: "netgear_plus_port_config Resource"
subcategory: ""
description: |-
  Manage the authoritative per-port configuration (enable, flow control, QoS priority, ingress and egress rate limits) of all 8 ports on an NSDP-managed Netgear Plus GS108Ev3 switch.
---

# netgear_plus_port_config Resource

`netgear_plus_port_config` manages the per-port configuration of the switch: admin enable, flow control, per-port QoS priority, and ingress/egress rate limits.

One instance of this resource models the whole switch. The `ports` block is the complete, authoritative per-port configuration: exactly 8 entries, one per physical port, with the port numbers being exactly the set 1-8. Ports cannot be managed partially — omitting a port is not possible, and removing the resource from configuration does not change the switch.

The resource uses the NSDP protocol. It requires the `agent_mac` provider attribute, not `host`.

## Behavior

- Applies are diff-then-verify: the provider reads the current per-port state, sends only the SETs for values that differ, and reads the switch back. If the readback still disagrees with the plan, one corrective pass is sent, and any remaining difference becomes a typed drift error naming the port and field (for example `port 5: qos_priority=low (wanted high)`).
- A from-factory apply is a no-op: all attributes default to the factory values (`enabled = true`, `flow_control = false`, `qos_priority = "low"`, `ingress_rate = "none"`, `egress_rate = "none"` on all ports).
- If the switch does not answer a SET (reply lost), the provider never re-sends it. It records a warning and settles the question with the verification read instead, because redundant SET attempts can strike the firmware's login lockout.
- Destroy removes Terraform state only. The switch keeps its configuration; the existing port settings are never rolled back or reset.

The rate-limit SETs are implemented from the vendor's protocol sources but have not yet been validated against live hardware. A write the switch silently ignores surfaces as the typed drift error described above, never as false success.

## Example Usage

```hcl
provider "netgear" {
  agent_mac = "8c:3b:ad:25:1b:88" # placeholder: your switch's MAC address
  interface = "en0"                # placeholder: local NIC used for NSDP broadcast
  password  = "REPLACE_WITH_SWITCH_PASSWORD"
}

resource "netgear_plus_port_config" "switch" {
  # Exactly one ports block per physical port, 1 through 8.

  ports {
    port = 1
    # All defaults: enabled, flow control off, qos low, no rate limits.
  }

  ports {
    port = 2
  }

  ports {
    port = 3
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
    port = 8
    enabled      = false
    egress_rate  = "512k"
  }
}
```

## Argument Reference

- `ports` - (Required) Complete authoritative per-port configuration. Exactly 8 entries, one per physical port; the `port` numbers must be exactly the set 1-8. (see [below for nested schema](#nested-block-ports)).

## Attribute Reference

- `id` - Stable switch identifier, in the form `nsdp@<agent MAC>`.

## Nested Block: `ports`

- `port` - (Required) Physical port number, 1-8.
- `enabled` - (Optional) Port admin enable. Defaults to `true`, the factory value on all ports.
- `flow_control` - (Optional) Port flow control. Defaults to `false`, the factory value on all ports.
- `qos_priority` - (Optional) Per-port QoS priority, used when the QoS mode is port-based. Defaults to `low`. Valid values: `high`, `middle`, `normal`, `low`.
- `ingress_rate` - (Optional) Ingress (incoming) rate limit. Defaults to `none`. Valid values: `none`, `512k`, `1m`, `2m`, `4m`, `8m`, `16m`, `32m`, `64m`, `128m`, `256m`, `512m`.
- `egress_rate` - (Optional) Egress (outgoing) rate limit. Defaults to `none`. Valid values: `none`, `512k`, `1m`, `2m`, `4m`, `8m`, `16m`, `32m`, `64m`, `128m`, `256m`, `512m`.

## Import

Import by the resource ID, which is `nsdp@` followed by the switch's agent MAC address:

```sh
terraform import netgear_plus_port_config.switch nsdp@8c:3b:ad:25:1b:88
```
