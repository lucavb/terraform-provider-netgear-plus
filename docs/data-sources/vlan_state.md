---
page_title: "netgear_plus_vlan_state Data Source"
subcategory: ""
description: |-
  Read live VLAN membership and PVID state from a Netgear Plus GS108Ev3 device before managing it authoritatively.
---

# netgear_plus_vlan_state Data Source

Use `netgear_plus_vlan_state` to read the live VLAN and PVID state from the target switch before managing it authoritatively.

## Example Usage

```hcl
data "netgear_plus_vlan_state" "current" {}
```

Typical import-first workflow:

1. Run `data.netgear_plus_switch.target`.
2. Run `data.netgear_plus_vlan_state.current`.
3. Copy the returned VLANs and PVIDs into `netgear_plus_vlan_state`.
4. Make one additive change only.

This data source helps you avoid guessing at the live configuration before enabling management.

## Attribute Reference

- `id` - Stable switch identifier.
- `pvids` - Per-port PVID map.
- `vlan` - Live VLAN definitions.

## Nested Attributes for `vlan`

- `id` - VLAN ID.
- `ports` - Per-port membership map. Values are switch membership modes such as `untagged`, `tagged`, or `ignored`.
