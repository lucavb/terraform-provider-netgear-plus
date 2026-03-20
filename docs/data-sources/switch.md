---
page_title: "netgear_plus_switch Data Source"
subcategory: ""
description: |-
  Read switch facts from a Netgear Plus GS108Ev3 device.
---

# netgear_plus_switch Data Source

Use `netgear_plus_switch` to read identifying information and firmware details from the target switch.

## Example Usage

```hcl
data "netgear_plus_switch" "target" {}
```

## Schema

### Read-Only

- `bootloader_version` (String) Switch bootloader version.
- `firmware_version` (String) Switch firmware version.
- `id` (String) Stable switch identifier.
- `mac_address` (String) Switch MAC address.
- `model` (String) Switch model.
- `serial_number` (String) Switch serial number.
- `switch_name` (String) Device name reported by the switch.
