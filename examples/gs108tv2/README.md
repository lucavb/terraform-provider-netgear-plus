# gs108tv2 worked example (GS108Tv2 / GS110TPv2-class)

A complete, operator-shaped example set for a FASTPATH-class switch: identity pin via
NSDP v1, config backup data source, then the two managed resources that stage into the
switch's startup-config.

This directory is standalone (no imports of other example files). The
`resource.tf` files under `examples/data-sources/netgear_plus_switch_config/`
show the data source on its own for the generated registry docs.

## Provider block — what each attribute is for on this model

- `host`: the text-config channel (config backup data source, vlan_state,
  port_config). Operations run over the switch's web UI.
- `agent_mac`: NSDP v1 identity (switch name, serial, firmware — the serial
  is a flat TLV there; VLAN/port datatypes do not exist in v1). Both
  managed resources refuse to stage without it, because the serial pin
  requires it.
- `model = "gs108tv2"` selects this whole transport split.

NSDP traffic goes unicast to `host` when both are set, so one L3 address
serves both channels.

## Applying the staged resources

Applies download the startup-config, patch it, and restore it. The restore
does NOT reboot the switch — changes sit in the startup-config until the
next boot (`changes_pending = true` in state). See
`docs/resources/vlan_state.md`, gs108tv2 section.

`reboot_to_apply = true` on the resources would reboot the switch after
each staged apply, but on this firmware build the provider refuses it
actionably until the reboot endpoint is pinned (FASTPATH 5.4.2.36,
"phase 0b"); it is shown commented out below for that reason.

## Remote LAN validation (cross-compile + scp)

From your dev machine, when the switch is reachable only from a jump host
(e.g. `casalta-lan`):

```sh
SWITCH_PASSWORD='…' ./deploy-remote-validate.sh
```

For a configure smoke test only (skips read-only tofu; still slow on the switch):

```sh
SKIP_READ_VALIDATE=1 LIVE_APPLY=1 SKIP_FACTORY_RESTORE=1 SWITCH_PASSWORD='…' ./deploy-remote-validate.sh
```

Each staged apply can sit mostly silent for **up to ~5 minutes** while the driver waits out the FASTPATH post-restore ingest window (90s before the first verify attempt, then 15s polls). That is expected, not a hung SSH session.

This cross-compiles `linux/amd64` artifacts, copies them to
`/tmp/netgear-plus-live-validate` on `REMOTE_HOST` (override with env vars),
runs `netgear-plus-debug` (NSDP + emweb config fetch), then OpenTofu apply on
read-only data sources using a filesystem provider mirror (`0.0.0-dev`).

## Running against a real switch

Build the provider locally and point `terraformrc.tfrc` at it (same shape
as `examples/live-test`):

```sh
go build -o examples/gs108tv2/.providers/terraform-provider-netgear-plus .
```

Put the password in `secrets.auto.tfvars` (keep it out of git):

```hcl
switch_password = "your-password"
```

Then plan with `-parallelism=1`; this keeps a second read from colliding
with a restore's ingest window.
