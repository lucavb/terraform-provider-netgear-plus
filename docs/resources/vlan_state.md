---
page_title: "netgear_plus_vlan_state Resource"
subcategory: ""
description: |-
  Manage authoritative VLAN membership and PVID state on a Netgear Plus GS108Ev3 device with conservative safety checks.
---

# netgear_plus_vlan_state Resource

`netgear_plus_vlan_state` manages authoritative VLAN membership and PVID state on the target switch.

This resource is intentionally conservative:

- `expected_serial_number` should be set before live changes.
- VLAN deletions are blocked unless `allow_vlan_deletions = true`.
- Destroy removes Terraform state only and leaves switch configuration unchanged.

Use this resource only after you have read the live switch state with `netgear_plus_switch` and `netgear_plus_vlan_state`.

## Example Usage

```hcl
data "netgear_plus_switch" "target" {}

data "netgear_plus_vlan_state" "current" {}

resource "netgear_plus_vlan_state" "switch" {
  expected_serial_number = data.netgear_plus_switch.target.serial_number
  allow_vlan_deletions   = false

  vlan {
    id = 1
    ports = {
      "1" = "untagged"
      "2" = "untagged"
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
```

## Safe Workflow

1. Read `data.netgear_plus_switch.target` to confirm the switch identity.
2. Read `data.netgear_plus_vlan_state.current` to capture the current VLAN and PVID layout.
3. Copy that live state into `netgear_plus_vlan_state`.
4. Make one additive change only.
5. Keep `allow_vlan_deletions = false` until delete behavior has been validated on the target device.

Because this resource is authoritative, omitting a VLAN means "Terraform should remove it" once deletions are enabled.

## Argument Reference

- `pvids` - (Required) Complete per-port PVID map for the switch.
- `vlan` - (Required) Complete authoritative VLAN definition for the switch. At least one block is required.
- `allow_vlan_deletions` - (Optional) Allow authoritative removal of VLANs omitted from configuration. Defaults to `false`.
- `expected_serial_number` - (Optional, but strongly recommended for all live changes) Expected device serial number. Create and update fail if the connected switch does not match.

## Attribute Reference

- `id` - Stable switch identifier.

## Nested Block: `vlan`

- `id` - VLAN ID.
- `ports` - Per-port membership map using `untagged` or `tagged`. Omitted ports are normalized to `ignored`.

Example membership map:

```hcl
vlan {
  id = 10
  ports = {
    "3" = "untagged"
    "4" = "untagged"
    "8" = "tagged"
  }
}
```

## Import

Import by the resource ID stored in state:

```sh
terraform import netgear_plus_vlan_state.switch gs108ev3@192.0.2.10
```
