---
page_title: "netgear_plus_port_config Resource"
subcategory: ""
description: |-
  Manage the authoritative per-port configuration (enable, flow control, QoS priority, ingress and egress rate limits) of all 8 ports on a Netgear Plus switch: all five attributes over NSDP on gs108ev3; enable and flow control over the FASTPATH text-config channel on gs108tv2.
---

# netgear_plus_port_config Resource

`netgear_plus_port_config` manages the per-port configuration of the switch: admin enable, flow control, per-port QoS priority, and ingress/egress rate limits.

One instance of this resource models the whole switch. The `ports` block is the complete, authoritative per-port configuration: exactly 8 entries, one per physical port, with the port numbers being exactly the set 1-8. Ports cannot be managed partially — omitting a port is not possible, and removing the resource from configuration does not change the switch.

The resource uses the NSDP protocol on gs108ev3. It requires the `agent_mac` provider attribute, not `host`. On the gs108tv2 model it runs over the switch's text-config channel instead — see the [gs108tv2 section](#gs108tv2-gs108tvglass110tpv2-class); that path also needs the `host` attribute.

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
- `reboot_to_apply` - (Optional) gs108tv2 only. Reboot the switch after staging so the changes activate immediately. Defaults to `false`. See the [gs108tv2 section](#gs108tv2-gs108tvglass110tpv2-class) for the current availability.
- `changes_pending` - (Computed) gs108tv2: `true` while the last Terraform apply staged changes without a Terraform-driven reboot; always `false` on gs108ev3.

## Attribute Reference

- `id` - Stable switch identifier, in the form `nsdp@<agent MAC>` on gs108ev3, or `gs108tv2@<host>` when the provider model is `gs108tv2`.
- `changes_pending` - `true` after a gs108tv2 apply staged changes without a Terraform-driven reboot. Cleared by the next apply, not by a manual reboot; see the [gs108tv2 section](#gs108tv2-gs108tvglass110tpv2-class).

## Nested Block: `ports`

- `port` - (Required) Physical port number, 1-8.
- `enabled` - (Optional) Port admin enable. Defaults to `true`, the factory value on all ports.
- `flow_control` - (Optional) Port flow control. Defaults to `false`, the factory value on all ports.
- `qos_priority` - (Optional) Per-port QoS priority, used when the QoS mode is port-based. Defaults to `low`. Valid values: `high`, `middle`, `normal`, `low`.
- `ingress_rate` - (Optional) Ingress (incoming) rate limit. Defaults to `none`. Valid values: `none`, `512k`, `1m`, `2m`, `4m`, `8m`, `16m`, `32m`, `64m`, `128m`, `256m`, `512m`.
- `egress_rate` - (Optional) Egress (outgoing) rate limit. Defaults to `none`. Valid values: `none`, `512k`, `1m`, `2m`, `4m`, `8m`, `16m`, `32m`, `64m`, `128m`, `256m`, `512m`.

## gs108tv2 (GS108Tv2/GS110TPv2-class)

With the provider model attribute set to `gs108tv2`, this resource manages port settings through the same channel as `netgear_plus_vlan_state`: the switch's text-config file. The startup-config is downloaded, the `interface 0/1`..`0/8` bodies are rewritten, and the file is restored — with the identical stage-to-startup semantics as for VLAN state:

- The restore writes the startup-config only. No reboot happens, and the running configuration is unchanged until the next boot; every read and drift comparison is against the startup config because running port state is unreadable over this channel.
- Every apply that stages real changes warns (`gs108tv2: Port configuration changes are staged for the next reboot`). Wait behavior during the firmware's ingest window is the same as documented for [vlan_state](vlan_state.md).
- Safety rails: applies require the provider `agent_mac` on gs108tv2 (fail-closed before staging, same whole-file-rewrite reasoning as vlan_state; the serial the pin compares is only readable via NSDP v1). This resource does not carry `expected_serial_number` on any model — the whole-state identity pin here is exactly that provider-level rail, plus the resource's `id` convention (`gs108tv2@<host>` on this model). The set-up needs both `host` (text-config channel) and `agent_mac` (identity pin).
- The same `reboot_to_apply` and `changes_pending` attributes and semantics as vlan_state apply here, including the current refusal until the gs108tv2 reboot endpoint is pinned for FASTPATH 5.4.2.36.
- The diff/verify shape is mirrored from the NSDP path: a no-op apply sends no config restore at all, and a read-back that disagrees with the plan after restore fails as a typed post-apply verification error naming the port and field.

### Capability matrix

What the text-config channel can express on this firmware today (from the driver's capability table in `internal/client/gs108tv2/grammar.go`):

| Attribute | gs108tv2 status | Notes |
|---|---|---|
| `enabled` | managed | Renders as a `shutdown` line on disable, by absence on enable (absence IS the factory state). |
| `flow_control` | managed | Renders as `flow control` on, by absence on off. |
| `qos_priority` | refused | No known text-config grammar on this firmware. Non-default values (`high`, `middle`, `normal`) fail with a typed per-port error naming the port, the attribute, and the requested value — before anything is sent to the switch. |
| `ingress_rate` | refused | Same refusal rule; only the default `none` is accepted. |
| `egress_rate` | refused | Same refusal rule; only the default `none` is accepted. |

Default values (`qos_priority = "low"`, `ingress_rate = "none"`, `egress_rate = "none"`) are accepted on gs108tv2 and render by absence — a config lacking the attribute is literally how the switch's own factory files express those values.

The managed-attribute grammar (the `shutdown` and `flow control` line templates) was implemented from bench observation and is provisional pending live pinning on real hardware; the provider re-verifies every apply against the startup-config decode regardless.

So, stated plainly: **on gs108tv2 this resource manages enable + flow control only, for now.** The schema vocabulary is unchanged for every model — qos and rate overrides simply refuse to stage on gs108tv2 until that firmware's grammar is pinned — and the gs108ev3/NSDP path manages all five attributes exactly as documented above.

```hcl
resource "netgear_plus_port_config" "switch" {
  ports {
    port         = 3
    flow_control = true
  }

  ports {
    port    = 5
    enabled = false
  }

  ports {
    port = 8
  }

  # ...
  # ports 1, 2, 4, 6, 7 similarly; all 8 required.
  # qos_priority / ingress_rate / egress_rate not set anywhere: any
  # non-default value refuses on gs108tv2.
}
```

## Import

Import by the resource ID, which is `nsdp@` followed by the switch's agent MAC address, or `gs108tv2@<host>` on the gs108tv2 text-config path:

```sh
terraform import netgear_plus_port_config.switch nsdp@8c:3b:ad:25:1b:88

terraform import netgear_plus_port_config.switch gs108tv2@192.0.2.20
```
