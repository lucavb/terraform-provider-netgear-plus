---
status: accepted
---

# The convergence plan serves the incremental channels only

The three VLAN apply paths split into two genuinely different convergence models: the gs108ev3 HTTP driver and the NSDP transport converge incrementally (identical widen → PVID → exact → delete-last ordering with preserved-port fixups, duplicated between `internal/client/gs108ev3/vlan.go` and `internal/provider/nsdp_switch_transport.go`), while the gs108tv2 text-config channel renders the entire desired VLAN database into the startup-config (removals by absence; omitted ports reset to factory state instead of being preserved). We extract the incremental algorithm into `internal/model` as the convergence plan and deliberately leave gs108tv2 on its render-and-stage model: ordered ops are dead weight on a whole-file channel, and an "effective state" abstraction would mean different things per channel (factory fallback vs preserved ports).

## Considered Options

- Unify all three channels under the plan — rejected: requires an effective-state abstraction whose rules differ per channel (gs108tv2 has no preserved-port splice and no preserve-removed-VLANs filter); wider interface, zero leverage.
- Defer until the plan exists — rejected: the duplication is an active bug generator (the two copies had already drifted on PVID batch ordering), and two real adapters already justify the seam.

## Consequences

- The two convergence models are named on purpose (see `CONTEXT.md`): **incremental convergence** and **staged whole-file rewrite**. Future architecture reviews should not re-suggest unifying them without new facts.
- Preserved-port semantics on gs108tv2, if ever wanted, is a new feature requiring its own live-hardware validation — not a refactor.
