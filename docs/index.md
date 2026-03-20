---
page_title: "netgear_plus Provider"
subcategory: ""
description: |-
  The netgear_plus provider manages Netgear Plus switch state for GS108Ev3 devices.
---

# netgear_plus Provider

The `netgear_plus` provider manages Netgear Plus switch state for `GS108Ev3` devices.

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
provider "netgear_plus" {
  host            = "192.0.2.10"
  password        = var.switch_password
  model           = "GS108Ev3"
  request_timeout = 15
  request_spacing = 5
  insecure_http   = true
}
```

## Schema

### Required

- `host` (String) Switch hostname or URL.
- `password` (String, Sensitive) Switch admin password.

### Optional

- `insecure_http` (Boolean) Allow plaintext HTTP transport for switch access.
- `model` (String) Switch model to bind to. Currently only `GS108Ev3` is supported.
- `request_spacing` (Number) Minimum delay in seconds between requests and operations against the same switch.
- `request_timeout` (Number) HTTP timeout in seconds.
