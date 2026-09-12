# AGENTS.md

## Cloned Dependency Source

Read-only dependency source repositories are available under
`.slim/clonedeps/repos/` for inspection. Do not edit these clones.

- `.slim/clonedeps/repos/foxey__py-netgear-plus/` - `foxey/py-netgear-plus` at `v0.6.4`; Python library for NETGEAR Plus switches — reference implementation for the GS108Ev3 HTTP UI session/login flow and switch state reads (source in `src/py_netgear_plus`).
- `.slim/clonedeps/repos/ckarrie__ha-netgear-plus/` - `ckarrie/ha-netgear-plus` at `main`; Home Assistant custom integration for Netgear Plus switches — consumer-side view of the py-netgear-plus library (session lifecycle, polling).
- `.slim/clonedeps/repos/paultyng__terraform-provider-unifi/` - `paultyng/terraform-provider-unifi` at `main` (archived upstream, `vendor/` stripped); Terraform provider for UniFi — pattern reference for session-based providers and resource design (own source in `internal/`).
- `.slim/clonedeps/repos/terraform-routeros__terraform-provider-routeros/` - `terraform-routeros/terraform-provider-routeros` at `main`; Terraform provider for MikroTik RouterOS — pattern reference for network-device resources and session handling.

All four are source tarballs fetched from `codeload.github.com` (the sandbox denies git's HTTPS remote helper), so they carry no `.git` history. Structured manifest: `.slim/clonedeps.json`.
