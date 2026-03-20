---
page_title: "netgear_plus_vlan_state Resource"
subcategory: ""
description: |-
  Manage authoritative VLAN membership and PVID state on a Netgear Plus GS108Ev3 device.
---

# netgear_plus_vlan_state Resource

`netgear_plus_vlan_state` manages authoritative VLAN membership and PVID state on the target switch.

This resource is intentionally conservative:

- `expected_serial_number` should be set before live changes.
- VLAN deletions are blocked unless `allow_vlan_deletions = true`.
- Destroy removes Terraform state only and leaves switch configuration unchanged.

## Example Usage

```hcl
data "netgear_plus_switch" "target" {}

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

## Schema

### Required

- `pvids` (Map of Number) Complete per-port PVID map for the switch.
- `vlan` (Block List, Min: 1) Complete authoritative VLAN definition for the switch.

### Optional

- `allow_vlan_deletions` (Boolean) Allow authoritative removal of VLANs omitted from configuration. Defaults to `false`.
- `expected_serial_number` (String) Expected device serial number. Create and update fail if the connected switch does not match.

### Read-Only

- `id` (String) Stable switch identifier.

### Nested Schema for `vlan`

- `id` (Number) VLAN ID.
- `ports` (Map of String) Per-port membership map using `untagged` or `tagged`. Omitted ports are normalized to `ignored`.

## Import

Import by the resource ID stored in state:

```sh
terraform import netgear_plus_vlan_state.switch gs108ev3@192.0.2.10
```
