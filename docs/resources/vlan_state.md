---
page_title: "netgear_plus_vlan_state Resource"
subcategory: ""
description: |-
  Manage authoritative VLAN membership and PVID state on a Netgear Plus switch (gs108ev3 live over HTTP; gs108tv2 staged into the startup-config) with conservative safety checks.
---

# netgear_plus_vlan_state Resource

`netgear_plus_vlan_state` manages authoritative VLAN membership and PVID state on the target switch.

This resource is intentionally conservative:

- `expected_serial_number` should be set before live changes. On gs108tv2 the provider also needs `agent_mac` for the serial pin; see the [gs108tv2 section](#gs108tv2-gs108tvglass110tpv2-class).
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
      "5" = "untagged"
      "6" = "untagged"
      "7" = "untagged"
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
- `reboot_to_apply` - (Optional) gs108tv2 only. Reboot the switch after staging so the changes activate immediately. Defaults to `false`. See the [gs108tv2 section](#gs108tv2-gs108tvglass110tpv2-class) for the current availability.
- `changes_pending` - (Computed) gs108tv2: `true` while the last Terraform apply staged changes without a Terraform-driven reboot; always `false` on gs108ev3. See the [gs108tv2 section](#gs108tv2-gs108tvglass110tpv2-class).

## Attribute Reference

- `id` - Stable switch identifier.
- `changes_pending` - `true` after a gs108tv2 apply staged changes without a Terraform-driven reboot. Cleared by the next apply, not by a manual reboot; see the [gs108tv2 section](#gs108tv2-gs108tvglass110tpv2-class).

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

## gs108tv2 (GS108Tv2/GS110TPv2-class)

With the provider model attribute set to `gs108tv2`, this resource manages VLANs and PVIDs on the FASTPATH firmware line through a completely different channel: the switch's text-config file, not NSDP.

**Stage-to-startup semantics.** Every apply downloads the switch's current startup-config, mutates the VLAN/PVID bodies, and restores the file. The restore writes the startup-config **only** — it does not reboot the switch, and the running configuration is untouched until the next boot. Running VLAN state cannot be read over this channel at all: every read, plan, and drift comparison on this model compares against the **startup config**, so a Terraform-fresh switch reports what will become true at the next reboot, not what is currently passing frames. If you need the running state, look at the switch UI.

**Per-port validation is stricter here.** Omitting a VLAN means the same thing on both channels: authoritative removal, guarded by `allow_vlan_deletions`. What differs is which per-port states each channel accepts — on gs108ev3/NSDP a port's PVID may point at a VLAN that carries the port tagged, while this firmware requires the PVID's VLAN to carry the port untagged and allows at most one untagged membership per port (typed per-port refusals name the port and the rule). You cannot omit a port from management on any channel: the `pvids` map must cover every port and every PVID must name a VLAN that carries its port, so a valid configuration always declares every port somewhere.

Mechanics worth knowing in one sentence each:

- The config-restore kicks off a roughly two-minute ingest window on this firmware (logins are refused while the switch digests the file). The apply handles that window internally — it re-logins and retries, and the verification step waits until the switch serves a coherent re-read — so you do not need to fix anything around the apply itself.
- Diagnostics: on every apply that actually staged changes you get a warning (`gs108tv2: VLAN changes are staged for the next reboot`) stating exactly that.
- When the switch re-serializes the file through its own normalizer during restore (the state still verifies correct, but bytes differ from what the provider uploaded), you get a second warning about canonical divergence. It is benign and mostly matters when you diff config backups; keep it in mind when comparing `netgear_plus_switch_config.canonical` values across providers.

### Safety rails (unchanged semantics, same reason)

- `expected_serial_number` must still be set for live applies, and on this model the serial can only be read via NSDP v1, so the provider **also requires `agent_mac`** on gs108tv2. Without `agent_mac`, any apply fails closed before staging with an actionable refusal that says the text-config channel rewrites the whole startup-config and quotes the reason plus the hint that the config backup itself carries the MAC in its `spanning-tree configuration name` line. Set both `host` (text-config channel) and `agent_mac` (serial/identity) to the same switch and the pins all work.
- `allow_vlan_deletions` blocks VLAN removals by default on gs108tv2 exactly as it does on gs108ev3; when permitted, deletions ship in the same restored file.
- The `id` on this model is `gs108tv2@<host>` (canonicalized provider host), **not** the `nsdp@<MAC>` form — switching transports changes the ID, so import after switching rather than letting Terraform destroy.

### `reboot_to_apply`

`reboot_to_apply` defaults to `false` (staging only, no reboot).

- `true`: every apply that stages changes **reboots** the switch after staging and waits for it to come back with the startup-config intact — at success your changes are ACTIVE in the running config, and `changes_pending` stays `false`. Two implications: a failed reboot leaves the apply as a typed error and unwritten state (the next apply short-circuits the already-staged config and re-attempts only the reboot), and leaving the flag `true` means later unrelated diffs reboot the switch too. Mind what you leave enabled.
- `false`: staging only, as described above. This is the default and is what most gs108tv2 deploy flows want today.

One sentence on availability: **on gs108tv2, `reboot_to_apply = true` currently still fails with an actionable refusal** because the reboot endpoint is not yet pinned for FASTPATH 5.4.2.36 (the driver refuses to reboot on a guessed URL). Staging works without it. When the pin lands, the same flag starts rebooting.

### `changes_pending` (computed)

`changes_pending` is `true` after an apply staged real changes without a Terraform-driven reboot, and `false` after a no-op apply, a rebooting apply, or any gs108ev3 apply.

It does not clear on refresh: **a manual/out-of-band reboot is not observable** through the startup-config channel, so a Read of this resource passes the prior value through unchanged. The flag says "Terraform staged this and no Terraform-driven reboot has consumed it yet" — the next apply clears it.

### Import, delete, gs108ev3

- Import reads the startup config and adopts the staged state (use the `gs108tv2@<host>` ID form shown under [Import](#import)); the `expected_serial_number` + `agent_mac` pins apply on subsequent reads too if you pin them.
- `terraform destroy` removes Terraform state only. On gs108tv2 the staged startup-config stays exactly as the last apply left it — the switch will boot into it on the next reboot. This is "no implicit rollback" behavior, consistent with gs108ev3.
- gs108ev3 behavior is unchanged: applies go through the switch's HTTP driver live and take effect immediately; `reboot_to_apply` is refused on gs108ev3 (there is nothing to reboot into).

## Import

Import by the resource ID stored in state.

```sh
# gs108ev3 (HTTP web-UI driver): the model prefix is gs108ev3.
terraform import netgear_plus_vlan_state.switch gs108ev3@192.0.2.10

# gs108tv2 (text-config channel): the model prefix is gs108tv2, host is
# the provider's host attribute.
terraform import netgear_plus_vlan_state.switch gs108tv2@192.0.2.20
```
