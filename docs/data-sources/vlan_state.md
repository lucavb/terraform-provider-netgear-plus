---
page_title: "netgear_plus_vlan_state Data Source"
subcategory: ""
description: |-
  Read live VLAN membership and PVID state from a Netgear Plus GS108Ev3 device.
---

# netgear_plus_vlan_state Data Source

Use `netgear_plus_vlan_state` to read the live VLAN and PVID state from the target switch before managing it authoritatively.

## Example Usage

```hcl
data "netgear_plus_vlan_state" "current" {}
```

## Schema

### Read-Only

- `id` (String) Stable switch identifier.
- `pvids` (Map of Number) Per-port PVID map.
- `vlan` (List of Objects) Live VLAN definitions.

### Nested Schema for `vlan`

- `id` (Number) VLAN ID.
- `ports` (Map of String) Per-port membership map. Values are switch membership modes such as `untagged`, `tagged`, or `ignored`.
