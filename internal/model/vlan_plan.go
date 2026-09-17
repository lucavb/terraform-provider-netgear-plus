package model

import (
	"context"
	"slices"
)

// This file transposes the shared convergence pipeline of the two
// ApplyVLANState implementations — internal/client/gs108ev3/vlan.go
// (HTTP web-UI driver) and internal/provider/nsdp_switch_transport.go
// (NSDP transport) — into a pure plan: model.Plan computes an ordered
// list of ops from (current, desired), and model.Run replays them
// through one channel-specific VLANApplier. The pipeline logic is
// byte-for-byte the same computation both transports perform inline
// today; the transports keep their own copies until they adopt this
// seam in follow-up PRs.

// VLANOp is one mutating step of a VLANPlan. The vocabulary is sealed:
// only the four concrete op types in this file implement the marker
// method.
type VLANOp interface {
	isVLANOp()
}

// AddVLANOp creates VLAN VID. Phase 1 of the plan. The HTTP adapter
// executes the web UI's add form here; the NSDP adapter no-ops because
// NSDP's Set8021QVLAN upserts in phase 2.
type AddVLANOp struct {
	VID int
}

// SetMembershipOp writes the full per-port membership map for VLAN VID.
// Appears in phase 2 (widened memberships so every PVID target stays a
// member during the transition) and phase 4 (exact memberships, plus
// all-ignored pre-clears for removed VLANs and preserved-port splices).
type SetMembershipOp struct {
	VID   int
	Ports map[int]PortMembership
}

// SetPVIDsOp assigns Ports (ascending) as PVID members of VLAN VID.
// Phase 3 of the plan. Unlike the HTTP original, which iterates the
// BatchPVIDs map directly (nondeterministic), iteration here is sorted.
type SetPVIDsOp struct {
	VID   int
	Ports []int
}

// DeleteVLANsOp deletes the listed VLAN IDs. Phase 5, always last, and
// omitted entirely when the filtered removed set is empty.
type DeleteVLANsOp struct {
	VIDs []int
}

func (AddVLANOp) isVLANOp()       {}
func (SetMembershipOp) isVLANOp() {}
func (SetPVIDsOp) isVLANOp()      {}
func (DeleteVLANsOp) isVLANOp()   {}

// VLANPlan is the ordered convergence plan produced by Plan.
type VLANPlan []VLANOp

// VLANApplier is the seam between the pure plan and a channel-specific
// wire implementation. NSDP's adapter will ignore ctx (its client is
// synchronous); the HTTP driver needs it. Keeping ctx in the interface
// lets both fit one seam.
type VLANApplier interface {
	AddVLAN(ctx context.Context, vid int) error
	SetMembership(ctx context.Context, vid int, ports map[int]PortMembership) error
	SetPVIDs(ctx context.Context, vid int, ports []int) error
	DeleteVLANs(ctx context.Context, vids []int) error
}

// Plan computes the pure convergence plan from current to desired.
//
// It transposes the normalize→validate→diff→op pipeline shared by the
// gs108ev3 HTTP driver and the NSDP transport exactly:
//
//   - desired is normalized then validated; validation failure returns
//     (nil, err) with no ops.
//   - current is normalized; semantic equality short-circuits to an
//     empty plan.
//   - Membership transition state is built as in the originals: added
//     VLANs go into step1 with their exact desired membership; VLANs
//     present in both states go into step1 with the per-port minimum
//     (widened) membership and into step2 with the exact desired
//     membership; removed VLANs go into step2 pre-cleared to
//     all-ignored; ports omitted from desired splice their current
//     membership into step2 for the VLAN their current PVID references.
//   - removed is filtered through PreserveRemovedVLANs so no VLAN a
//     preserved port's current PVID still references is deleted.
//
// Ops are emitted in this fixed order — the ordering IS the module:
//
//  1. AddVLANOp per added vid, ascending (HTTP adapter executes its add
//     form; NSDP adapter no-ops — Set8021QVLAN upserts in phase 2).
//  2. SetMembershipOp per step1 vid, ascending — widened memberships so
//     every PVID target stays a member during the transition.
//  3. SetPVIDsOp per BatchPVIDs vid, ascending (BatchPVIDs already
//     sorts the ports). This fixes the HTTP original's nondeterministic
//     map iteration over BatchPVIDs.
//  4. SetMembershipOp per step2 vid, ascending — exact memberships,
//     including all-ignored pre-clears for removed VLANs and
//     preserved-port splices.
//  5. One DeleteVLANsOp with the filtered removed list, omitted when
//     empty.
//
// Port ranges come from desired.PortCount — unlike the originals,
// which each hardcode their driver-local port count (8).
func Plan(current, desired VLANState) (VLANPlan, error) {
	desired = desired.Normalize()
	if err := desired.Validate(); err != nil {
		return nil, err
	}

	current = current.Normalize()
	if current.Equal(desired) {
		return VLANPlan{}, nil
	}

	portCount := desired.PortCount

	removed := RemovedVLANs(current, desired)
	preservedPorts := PreservedPorts(desired)

	step1 := make(map[int]Vlan)
	step2 := make(map[int]Vlan)

	for _, vid := range AddedVLANs(current, desired) {
		step1[vid] = desired.VLANs[vid]
	}

	for _, vid := range intersectVLANIDs(current.VLANIDs(), desired.VLANIDs()) {
		step1[vid] = Vlan{
			ID:    vid,
			Ports: mergedMembership(current.VLANs[vid].Ports, desired.VLANs[vid].Ports, portCount),
		}
		step2[vid] = desired.VLANs[vid]
	}

	for _, vid := range removed {
		step2[vid] = Vlan{
			ID:    vid,
			Ports: ignoredPorts(portCount),
		}
	}

	splicePreservedPorts(step2, current, preservedPorts, portCount)

	removed = PreserveRemovedVLANs(removed, current, preservedPorts)

	added := AddedVLANs(current, desired)
	pvidBatches := BatchPVIDs(desired)

	var plan VLANPlan

	// Phase 1: create added VLANs.
	for _, vid := range added {
		plan = append(plan, AddVLANOp{VID: vid})
	}

	// Phase 2: widen memberships so PVID writes in phase 3 land on
	// ports that are already members of their target VLAN.
	for _, vid := range sortedVLANKeys(step1) {
		plan = append(plan, SetMembershipOp{VID: vid, Ports: step1[vid].Ports})
	}

	// Phase 3: move PVIDs, batched per VLAN, vids ascending.
	for _, vid := range sortedVLANKeys(pvidBatches) {
		plan = append(plan, SetPVIDsOp{VID: vid, Ports: pvidBatches[vid]})
	}

	// Phase 4: exact memberships (also pre-clears removed VLANs).
	for _, vid := range sortedVLANKeys(step2) {
		plan = append(plan, SetMembershipOp{VID: vid, Ports: step2[vid].Ports})
	}

	// Phase 5: deletes last, once, only when something remains to
	// delete.
	if len(removed) > 0 {
		plan = append(plan, DeleteVLANsOp{VIDs: removed})
	}

	return plan, nil
}

// splicePreservedPorts transposes the preserved-port fixup loop shared
// by both ApplyVLANState copies (nsdp_switch_transport.go:287-298,
// gs108ev3/vlan.go:62-73) verbatim: a port omitted from desired keeps
// its current membership in the VLAN its current PVID references, so
// the PVID write in phase 3 stays valid. (Note: desired.Validate gates
// Plan before this runs, and validation already forces every port to be
// a non-ignored member of its PVID VLAN, so PreservedPorts is empty for
// every state reaching here — the loop is carried faithfully from the
// originals.)
func splicePreservedPorts(step2 map[int]Vlan, current VLANState, preservedPorts []int, portCount int) {
	for _, port := range preservedPorts {
		pvid := current.PVIDs[port]
		vlan := step2[pvid]
		if vlan.Ports == nil {
			vlan = current.VLANs[pvid]
		}
		if vlan.Ports == nil {
			vlan = Vlan{ID: pvid, Ports: ignoredPorts(portCount)}
		}
		vlan.Ports[port] = current.VLANs[pvid].Ports[port]
		step2[pvid] = vlan
	}
}

// Run applies ops to applier in plan order, propagating errors AS-IS:
// adapters own their wire error strings byte-for-byte, so no wrapping
// happens here. An empty plan is a no-op returning nil.
func Run(ctx context.Context, plan VLANPlan, applier VLANApplier) error {
	for _, op := range plan {
		switch o := op.(type) {
		case AddVLANOp:
			if err := applier.AddVLAN(ctx, o.VID); err != nil {
				return err
			}
		case SetMembershipOp:
			if err := applier.SetMembership(ctx, o.VID, o.Ports); err != nil {
				return err
			}
		case SetPVIDsOp:
			if err := applier.SetPVIDs(ctx, o.VID, o.Ports); err != nil {
				return err
			}
		case DeleteVLANsOp:
			if err := applier.DeleteVLANs(ctx, o.VIDs); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Membership helpers mirrored from the two ApplyVLANState copies (same
// semantics; the HTTP originals cannot be imported here). Unlike the
// originals, they take the port count explicitly instead of each
// hardcoding a driver-local 8.
// ---------------------------------------------------------------------------

// ignoredPorts returns an all-ignored membership over all portCount
// ports.
func ignoredPorts(portCount int) map[int]PortMembership {
	ports := make(map[int]PortMembership, portCount)
	for port := 1; port <= portCount; port++ {
		ports[port] = PortMembershipIgnored
	}
	return ports
}

// mergedMembership takes the per-port minimum of the current and
// desired membership (untagged < tagged < ignored) — the widening step
// that keeps every PVID target valid during the transition.
func mergedMembership(current, desired map[int]PortMembership, portCount int) map[int]PortMembership {
	result := ignoredPorts(portCount)
	for port := 1; port <= portCount; port++ {
		result[port] = minMembership(current[port], desired[port])
	}
	return result
}

func minMembership(left, right PortMembership) PortMembership {
	order := map[PortMembership]int{
		PortMembershipUntagged: 1,
		PortMembershipTagged:   2,
		PortMembershipIgnored:  3,
	}

	if order[left] <= order[right] {
		return left
	}
	return right
}

func intersectVLANIDs(left, right []int) []int {
	set := make(map[int]struct{}, len(left))
	for _, value := range left {
		set[value] = struct{}{}
	}

	result := make([]int, 0, len(right))
	for _, value := range right {
		if _, ok := set[value]; ok {
			result = append(result, value)
		}
	}

	return result
}

func sortedVLANKeys[V any](m map[int]V) []int {
	ids := make([]int, 0, len(m))
	for vid := range m {
		ids = append(ids, vid)
	}
	slices.Sort(ids)
	return ids
}
