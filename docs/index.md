---
page_title: "netgear_plus Provider"
subcategory: ""
description: |-
  Manage Netgear Plus GS108Ev3 switch facts, VLAN membership, and PVID state with an import-first workflow.
---

# netgear_plus Provider

The `netgear_plus` provider manages Netgear Plus switch state for `GS108Ev3` devices.

This provider is intentionally narrow and conservative:

- Supported hardware: `GS108Ev3`
- Read-only discovery: `netgear_plus_switch` and `netgear_plus_vlan_state`
- Managed state: authoritative VLAN membership and PVIDs through `netgear_plus_vlan_state`
- Safety model: serial-number pinning, deletion guardrails, and state-only destroy

Use the fully qualified source address in OpenTofu:

```hcl
terraform {
  required_providers {
    netgear_plus = {
      source = "registry.terraform.io/lucavb/netgear-plus"
    }
  }
}
```

Terraform can also use the shorthand source `lucavb/netgear-plus`.

## Example Usage

```hcl
terraform {
  required_providers {
    netgear_plus = {
      source = "registry.terraform.io/lucavb/netgear-plus"
    }
  }
}

provider "netgear_plus" {
  host            = "192.0.2.10"
  password        = var.switch_password
  request_spacing = 5
}

data "netgear_plus_switch" "target" {}

data "netgear_plus_vlan_state" "current" {}

resource "netgear_plus_vlan_state" "switch" {
  expected_serial_number = data.netgear_plus_switch.target.serial_number

  # Keep this false for first live use.
  allow_vlan_deletions = false

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

Configure VLAN membership with repeated `vlan {}` blocks. If you generate configuration from variables or locals, use a `dynamic "vlan"` block rather than assigning `vlan = [...]`.

## Getting Started Safely

Start in read-only mode first:

1. Configure the provider and run `data.netgear_plus_switch.target`.
2. Run `data.netgear_plus_vlan_state.current`.
3. Copy the live VLANs and PVIDs into `netgear_plus_vlan_state`.
4. Set `expected_serial_number` from `data.netgear_plus_switch.target.serial_number`.
5. Make one additive change only.
6. Apply with `allow_vlan_deletions = false`.

This avoids treating unknown live VLANs as safe to delete before you have validated behavior on real hardware.

## Safety Notes

- `netgear_plus_vlan_state` is authoritative for the VLANs and PVIDs you declare.
- Live `create` and `update` require `expected_serial_number`, so the provider fails closed if it connects to the wrong switch.
- VLAN deletions are blocked unless `allow_vlan_deletions = true`.
- `destroy` removes Terraform state only. It does not roll switch configuration back.
- The provider serializes operations per host and waits `5` seconds between requests by default to avoid firmware lockouts on `GS108Ev3`.

If live runs feel slow, the default pacing is deliberate. If the switch is still touchy, raise `request_spacing` above `5`.

If you are using this provider with your own switch and want to avoid the stock firmware lockout mechanism entirely, the repository includes the optional helper script `patch_lockout.py`. It patches a specific `GS108Ev3` firmware image to bypass the login lockout checks and recomputes the firmware checksum.

This script has only been tested with `GS108Ev3`. It modifies vendor firmware, is completely outside the provider's supported runtime behavior, and you use it entirely at your own risk. I take absolutely no responsibility for bricked devices, failed flashes, or any other damage whatsoever.

## Argument Reference

- `host` - (Required) Switch hostname or URL.
- `password` - (Required, Sensitive) Switch admin password.
- `insecure_http` - (Optional) Allow plaintext HTTP transport for switch access. Defaults to `true`. If set to `false`, use an `https://` host.
- `model` - (Optional) Switch model to bind to. Defaults to `GS108Ev3`, which is currently the only supported model.
- `request_spacing` - (Optional) Minimum delay in seconds between requests and operations against the same switch. Defaults to `5`.
- `request_timeout` - (Optional) HTTP timeout in seconds. Defaults to `15`.
