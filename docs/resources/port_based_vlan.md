---
page_title: "netgear_plus_port_based_vlan Resource"
subcategory: ""
description: |-
  Manage the authoritative port-based VLAN table of an NSDP-managed Netgear Plus GS108Ev3 switch.
---

# netgear_plus_port_based_vlan Resource

`netgear_plus_port_based_vlan` manages the port-based VLAN table of the switch: which ports are grouped into which port-based VLANs.

One instance of this resource models the whole table. The `vlans` block is the complete, authoritative port-based VLAN table, and it must include every VLAN that exists on the switch (see below).

Port-based VLANs may overlap: the same physical port can be a member of several port-based VLANs, and that is how port-based VLANs are meant to be used. Overlapping port sets are valid; only duplicate `vlan_id` values are rejected.

The resource uses the NSDP protocol. It requires the `agent_mac` provider attribute, not `host`.

## VLAN engine-mode guard

This resource only applies while the switch's VLAN engine is in port-based mode. On every create, update, and read it first reads the engine mode and refuses to touch the table in any other mode (none, id-based, 802.1Q port-based, or 802.1Q extended):

- The refusal is an error naming the detected engine mode; no configuration is sent to the switch.
- The resource never changes the VLAN engine mode itself.
- 802.1Q VLAN membership, tagged ports, and PVIDs are managed by the `netgear_plus_vlan_state` resource — use that instead when the switch is in an 802.1Q mode. PVIDs always belong to `netgear_plus_vlan_state`, never to this resource.

## Behavior

- Applies are diff-then-verify: the provider reads the table, sends only the SETs for VLANs whose port sets differ (in ascending VLAN order), and reads the switch back. If the readback still disagrees with the plan, one corrective pass is sent, and any remaining difference becomes a typed drift error naming the VLAN (for example `vlan 10: ports=[1, 2] (wanted [1, 2, 3])`).
- If the switch does not answer a SET (reply lost), the provider never re-sends it. It records a warning and settles the question with the verification read instead.
- Destroy removes Terraform state only. There is no protocol-level port-based VLAN delete; the table is left exactly as it is.

Because there is no protocol-level delete, the resource is strict about VLANs that exist on the switch but are missing from your configuration: applying a plan that omits them fails with an error listing the unmanaged VLAN IDs and asking you to add them. Include every VLAN in `vlans`, then change port memberships.

The port-based VLAN SET is implemented from the vendor's protocol sources but has not yet been validated against live hardware. A write the switch silently ignores surfaces as a typed drift error, never as false success.

## Example Usage

```hcl
provider "netgear" {
  agent_mac = "8c:3b:ad:25:1b:88" # placeholder: your switch's MAC address
  interface = "en0"                # placeholder: local NIC used for NSDP broadcast
  password  = "REPLACE_WITH_SWITCH_PASSWORD"
}

# NOTE: only applies while the switch's VLAN engine is in port-based mode.
# In 802.1Q modes, use netgear_plus_vlan_state instead.

resource "netgear_plus_port_based_vlan" "switch" {
  vlans {
    vlan_id = 1
    ports   = [1, 2, 3, 4, 5, 6, 7, 8]
  }

  vlans {
    vlan_id = 10
    ports   = [1, 2, 3] # overlaps with VLAN 1, which is valid
  }
}
```

## Argument Reference

- `vlans` - (Required) Complete authoritative port-based VLAN table. At least one block is required, and the set of blocks must cover every VLAN present on the switch. (see [below for nested schema](#nested-block-vlans)).

## Attribute Reference

- `id` - Stable switch identifier, in the form `nsdp@<agent MAC>`.

## Nested Block: `vlans`

- `vlan_id` - (Required) Port-based VLAN ID, 1-4094. Must be unique within this resource; duplicate VLAN IDs are rejected.
- `ports` - (Required) Member ports of the VLAN: a non-empty set of port numbers, each 1-8. Port sets of different VLANs may overlap.

## Import

Import by the resource ID, which is `nsdp@` followed by the switch's agent MAC address:

```sh
terraform import netgear_plus_port_based_vlan.switch nsdp@8c:3b:ad:25:1b:88
```
