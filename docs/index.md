---
page_title: "netgear_plus Provider"
subcategory: ""
description: |-
  Manage Netgear Plus GS108Ev3 and GS108Tv2/GS110TPv2-class switch facts, VLAN membership, and PVID state with an import-first workflow.
---

# netgear_plus Provider

The `netgear_plus` provider manages Netgear Plus switch state for two firmware families:

- `gs108ev3` (Plus line, HTTP web UI + NSDP v2): VLANs and PVIDs apply live.
- `gs108tv2` (GS108Tv2/GS110TPv2-class FASTPATH line): VLAN and port management stage into the switch's startup-config over the FASTPATH text-config channel (change the startup-config file, switch reboots into it); identity facts (switch name, serial, MAC) come from NSDP v1 and need `agent_mac`.

This provider is intentionally narrow and conservative:

- Supported hardware: `GS108Ev3`, and the `gs108tv2` FASTPATH class (GS108Tv2/GS110TPv2, FASTPATH firmware such as 5.4.2.36)
- Read-only discovery: `netgear_plus_switch` (identity) and `netgear_plus_vlan_state` (VLAN/PVID state)
- Managed state: authoritative VLAN membership and PVIDs through `netgear_plus_vlan_state`, authoritative port settings through `netgear_plus_port_config`
- Config backup on `gs108tv2`: `netgear_plus_switch_config` (startup-config verbatim + uptime-canonical copy)
- Safety model: serial-number pinning, deletion guardrails, and state-only destroy

Use the fully qualified source address in OpenTofu:

```hcl
terraform {
  required_providers {
    netgear = {
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
    netgear = {
      source = "registry.terraform.io/lucavb/netgear-plus"
    }
  }
}

provider "netgear" {
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
- The provider serializes operations per host and waits `5` seconds between requests by default to avoid firmware lockouts on `GS108Ev3`. That lock only covers one Terraform process; the cross-process limits are described under [Concurrency across processes](#concurrency-across-processes) and matter most on gs108tv2 whole-file staging.

If live runs feel slow, the default pacing is deliberate. If the switch is still touchy, raise `request_spacing` above `5`.

If you are using this provider with your own switch and want to avoid the stock firmware lockout mechanism entirely, the repository includes the optional helper script `patch_lockout.py`. It patches a specific `GS108Ev3` firmware image to bypass the login lockout checks and recomputes the firmware checksum.

This script has only been tested with `GS108Ev3`. It modifies vendor firmware, is completely outside the provider's supported runtime behavior, and you use it entirely at your own risk. I take absolutely no responsibility for bricked devices, failed flashes, or any other damage whatsoever.

### Concurrency across processes

The per-device lock and 5-second pacing live inside one provider process. They cannot coordinate two separate `terraform apply` runs. Concurrent applies from separate processes against one switch can interleave whole-file read-modify-write cycles (gs108tv2 stages whatever file is current when its cycle starts) or interleave NSDP SET/GET traffic, and a restore ingest window makes the switch refuse other clients meanwhile. Serialize applies against one switch operationally: one pipeline or a lock of your own (a CI mutex, a file lock, anything that keeps two applies from overlapping).

### gs108tv2 model note

On `model = "gs108tv2"` the two identities split across channels:

- `host` drives the text-config channel (the `netgear_plus_vlan_state` and `netgear_plus_port_config` resources and the `netgear_plus_switch_config` data source). Their applies go through whole-file read-modify-write cycles of the startup-config, and they stage: the switch reboots into the changes; nothing changes in the running config before that.
- `agent_mac` drives NSDP v1, which on this firmware carries only identity (switch name, MAC, serial, firmware) — no VLAN or port datatypes. It is what makes the serial pin possible on the two resources above (they refuse to stage without it) and what `netgear_plus_switch` reads.

See the gs108tv2 sections on [netgear_plus_vlan_state](resources/vlan_state.md) and [netgear_plus_port_config](resources/port_config.md) for the whole story, and the `reboot_to_apply` documentation there for when staged changes become active.

## Argument Reference

- `host` - (Required for gs108tv2 resources and HTTP/gs108ev3 access) Switch hostname or URL. Targets the switch web UI over the HTTP driver, the NSDP unicast destination when `agent_mac` is also set, and the gs108tv2 text-config channel when `model = "gs108tv2"`.
- `agent_mac` - (Optional) Switch (agent) MAC address for NSDP, e.g. `8c:3b:ad:25:1b:88` (colon-separated). Needed by the NSDP resources (`netgear_plus_port_config`, `netgear_plus_switch`, serial pinning) and by gs108tv2 identity reads. At least one of `host` or `agent_mac` must be set.
- `interface` - (Optional) Local network interface used for NSDP traffic (for example `en0`), including its hardware address as the NSDP manager MAC. If unset, the first non-loopback interface with a hardware address is used.
- `password` - (Required, Sensitive) Switch admin password.
- `insecure_http` - (Optional) Allow plaintext HTTP transport for switch access. Defaults to `true`. If set to `false`, use an `https://` host.
- `model` - (Optional) Switch model to bind to. One of `gs108ev3` (Plus line, HTTP web UI + NSDP v2; the default) or `gs108tv2` (GS108Tv2/GS110TPv2-class FASTPATH line: VLAN and port management run over the switch's text-config channel via `host`, and identity facts are NSDP v1 only, needing `agent_mac`).
- `request_spacing` - (Optional) Minimum delay in seconds between requests and operations against the same switch. Defaults to `5`.
- `request_timeout` - (Optional) HTTP timeout in seconds. Defaults to `15`.
