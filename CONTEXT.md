# terraform-provider-netgear-plus

Terraform provider managing Netgear Plus smart switches across two firmware families: the `gs108ev3` Plus line (HTTP web UI + NSDP) and the `gs108tv2` FASTPATH line (NSDP v1 identity + startup-config staging). The two families share the VLAN state vocabulary but converge through different models.

## Language

### Switch state

**VLAN state**:
The authoritative whole-switch VLAN configuration: every VLAN's per-port membership plus every port's PVID.
_Avoid_: VLAN config, VLAN table

**Membership**:
A port's role in one VLAN — tagged, untagged, or ignored. A port belongs to a VLAN iff its membership is tagged or untagged.
_Avoid_: port mode

**PVID**:
The VLAN an untagged frame ingressing a port is classified into. One per port, and it must be a VLAN carrying that port untagged.
_Avoid_: native VLAN

**Preserved port**:
A port omitted from the desired membership; under incremental convergence the plan splices its current membership into the VLAN its current PVID references. Currently latent: validation requires every port to be a live member of its PVID's VLAN, so no valid desired state has preserved ports.
_Avoid_: unmanaged port, leftover port

### Convergence

**Convergence plan**:
The ordered VLAN operations that move a switch from current to desired VLAN state without passing through an invalid intermediate state: widen memberships first, set PVIDs, exact memberships, deletes last.
_Avoid_: apply sequence, diff

**VLAN applier**:
The seam that executes one convergence plan against a single switch channel; each channel provides its own.
_Avoid_: driver, writer

**Incremental convergence**:
The `gs108ev3` family's model: the plan applies live against the running switch, and omitted ports are preserved ports.
_Avoid_: live apply

**Staged whole-file rewrite**:
The `gs108tv2` family's model: the desired VLAN state is rendered into the startup-config and becomes active on the next reboot. The channel accepts a strictly smaller set of per-port states than incremental convergence: a PVID must sit on an untagged membership, at most one per port.
_Avoid_: staging

**Startup-config**:
The file a FASTPATH switch boots from. On the `gs108tv2` channel it is the only readable configuration surface, so every read describes the next boot, not the running state.
_Avoid_: running config
