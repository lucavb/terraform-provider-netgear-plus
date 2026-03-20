---
page_title: "netgear_plus_switch Data Source"
subcategory: ""
description: |-
  Read switch identity and firmware facts from a Netgear Plus GS108Ev3 device.
---

# netgear_plus_switch Data Source

Use `netgear_plus_switch` to read identifying information and firmware details from the target switch.

This is usually the first data source to run on a real device because it gives you the serial number needed to pin later write operations with `expected_serial_number`.

## Example Usage

```hcl
data "netgear_plus_switch" "target" {}
```

You can use the returned serial number to guard live changes:

```hcl
resource "netgear_plus_vlan_state" "switch" {
  expected_serial_number = data.netgear_plus_switch.target.serial_number
  # ...
}
```

## Attribute Reference

- `bootloader_version` - Switch bootloader version.
- `firmware_version` - Switch firmware version.
- `id` - Stable switch identifier.
- `mac_address` - Switch MAC address.
- `model` - Switch model.
- `serial_number` - Switch serial number.
- `switch_name` - Device name reported by the switch.
