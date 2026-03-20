# terraform-provider-netgear-plus

Terraform provider for Netgear Plus switches, currently scoped to `GS108Ev3`.

## Status

This project is usable for careful, operator-driven testing, but it is still an early provider.

- Supported model: `GS108Ev3`
- Terraform source: `lucavb/netgear-plus`
- OpenTofu source: `registry.terraform.io/lucavb/netgear-plus`
- Current maturity: prototype, not production-grade

## What It Does

- reads switch identity and firmware facts with `netgear_plus_switch`
- reads live VLAN and PVID state with `netgear_plus_vlan_state`
- manages authoritative VLAN membership and PVID state with `netgear_plus_vlan_state`

## Example

Use the fully qualified provider source for OpenTofu:

```hcl
terraform {
  required_providers {
    netgear_plus = {
      source = "registry.terraform.io/lucavb/netgear-plus"
    }
  }
}
```

Terraform CLI can also use the shorthand source `lucavb/netgear-plus`.

```hcl
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

Configure VLAN membership with repeated `vlan {}` blocks. If you generate configuration, use `dynamic "vlan"` to emit those blocks rather than assigning `vlan = [...]`.

## Safe First Use

Start in read-only mode first:

1. Read `data.netgear_plus_switch.target`.
2. Read `data.netgear_plus_vlan_state.current`.
3. Copy the live VLANs and PVIDs into `netgear_plus_vlan_state`.
4. Set `expected_serial_number` from the switch data source.
5. Make one additive change only.
6. Apply with `allow_vlan_deletions = false`.

This avoids treating unknown live VLANs as safe to remove before delete semantics are proven on hardware.

## Safety Model

This provider is optimized for correctness over breadth on `GS108Ev3`.

- `netgear_plus_vlan_state` is authoritative for the VLANs and PVIDs you configure.
- VLAN deletions are disabled by default. A plan that would remove switch VLANs fails unless `allow_vlan_deletions = true` is set explicitly.
- Live `create` and `update` require `expected_serial_number` so the provider fails closed if it connects to the wrong switch.
- `destroy` removes Terraform state only. It does not roll VLAN settings back on the device.

## Session Safety

The provider serializes all operations per switch host so `plan`, `read`, and `apply` do not open overlapping provider-managed sessions to the same device.

The provider also intentionally waits `5s` between requests to the same switch by default. This is a deliberate safety throttle for `GS108Ev3` firmware, which is prone to temporary login lockouts when clients send requests too quickly. If a live `plan` or `apply` feels slow, that delay is there to protect the switch rather than because the provider is doing unnecessary work.

If your switch firmware is still touchy, raise the provider's `request_spacing` above `5` seconds. For example, `request_spacing = 10` is a reasonable debugging setting when you are trying to stay well clear of the lockout threshold.

The switch can still report firmware lockouts if other clients are logging in at the same time, such as a browser session or another OpenTofu process. If that happens, wait for the lockout window to clear and retry with only one active client. While debugging, `tofu plan -parallelism=1` is a useful way to rule out unrelated concurrent activity.

When debugging repeated lockouts, simplify the configuration to one read path at a time. Start with either `data.netgear_plus_switch.target` or `data.netgear_plus_vlan_state.current`, confirm that it succeeds consistently, and only then add the second data source or managed resource back in.

## Live Testing

The checked-in live example stays focused on local operator workflows such as local provider mirrors and SOPS-backed secrets. See `examples/live-test/README.md` if you want a real-device workflow starting from read-only discovery before moving to managed changes.

## Known Limits

- `GS108Ev3` is the only supported model.
- The provider uses the switch's HTTP management surface as implemented today.
- Write operations are multi-step and not transactional.
- Import identity still uses `model@host`; the serial-number pin is the live-apply safety mechanism.
- The checked-in tests cover parsing and mock-driver behavior, not full hardware acceptance.

## Development

Build:

```sh
go build ./...
```

Test:

```sh
go test ./...
```

## Releases

- GitHub Actions runs validation on pushes and pull requests.
- Tagged releases are built by GoReleaser and uploaded to GitHub Releases with Terraform Registry-compatible artifacts.
- Release signing requires the GitHub Actions secrets `GPG_PRIVATE_KEY` and `PASSPHRASE`.
- The repository root must contain `terraform-registry-manifest.json` so the registry can detect protocol metadata.
- Create a tag such as `v0.1.0` on `main` to publish a signed GitHub release.
- After the signed release exists, publish the provider in the Terraform Registry under `lucavb/netgear-plus`.

## Production-Grade Follow-Up

The prototype is safer for first live use after the current hardening work, but it is not yet a production-grade provider. Remaining work includes:

- broader firmware validation and acceptance tests on real hardware
- stronger import and drift semantics
- more robust retry and re-auth behavior during long write sequences
- explicit compatibility documentation by model and firmware
- clearer operator docs for partial management, drift, and lifecycle expectations
