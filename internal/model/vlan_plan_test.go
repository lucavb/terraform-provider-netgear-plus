package model

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// membershipString renders a membership map deterministically so
// recorded applier calls assert full per-port coverage in op order.
func membershipString(ports map[int]PortMembership) string {
	ids := make([]int, 0, len(ports))
	for port := range ports {
		ids = append(ids, port)
	}
	sort.Ints(ids)

	parts := make([]string, 0, len(ids))
	for _, port := range ids {
		parts = append(parts, fmt.Sprintf("%d=%s", port, ports[port]))
	}
	return strings.Join(parts, " ")
}

// recordingVLANApplier appends a human-readable op string per call and
// can fail on the nth call (1-based) with an injected error.
type recordingVLANApplier struct {
	ops    []string
	calls  int
	failOn int
	err    error
}

func (a *recordingVLANApplier) record(op string) {
	a.calls++
	a.ops = append(a.ops, op)
}

func (a *recordingVLANApplier) maybeFail() error {
	if a.err != nil && a.calls == a.failOn {
		return a.err
	}
	return nil
}

func (a *recordingVLANApplier) AddVLAN(_ context.Context, vid int) error {
	a.record(fmt.Sprintf("add vlan %d", vid))
	return a.maybeFail()
}

func (a *recordingVLANApplier) SetMembership(_ context.Context, vid int, ports map[int]PortMembership) error {
	a.record(fmt.Sprintf("set vlan %d membership: %s", vid, membershipString(ports)))
	return a.maybeFail()
}

func (a *recordingVLANApplier) SetPVIDs(_ context.Context, vid int, ports []int) error {
	a.record(fmt.Sprintf("set pvids vlan %d ports %v", vid, ports))
	return a.maybeFail()
}

func (a *recordingVLANApplier) DeleteVLANs(_ context.Context, vids []int) error {
	a.record(fmt.Sprintf("delete vlans %v", vids))
	return a.maybeFail()
}

// runPlan drives the plan through Run against a recording applier and
// returns the recorded op strings in emitted order.
func runPlan(t *testing.T, plan VLANPlan) []string {
	t.Helper()

	applier := &recordingVLANApplier{}
	if err := Run(context.Background(), plan, applier); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	return applier.ops
}

func assertOps(t *testing.T, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("op count = %d, want %d\n got: %q\nwant: %q", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("op %d = %q, want %q\n got: %q\nwant: %q", i, got[i], want[i], got, want)
		}
	}
}

// TestVLANPlanWideTransition covers every phase of the pipeline in one
// scenario: add, widen, PVID move, exact memberships (including the
// pre-clear of an unrelated removed VLAN), delete last.
//
// The scenario from the settled design has no removed VLAN (vlan 10
// survives the transition), yet a DeleteVLANsOp must terminate the
// plan, so the current state additionally carries a stray vlan 30
// (tagged-only port 7 whose PVID stays 1) that the desired state no
// longer contains.
func TestVLANPlanWideTransition(t *testing.T) {
	t.Parallel()

	current := VLANState{
		PortCount: 8,
		VLANs: map[int]Vlan{
			1: {
				ID: 1,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
					2: PortMembershipUntagged,
					3: PortMembershipUntagged,
					5: PortMembershipUntagged,
					6: PortMembershipUntagged,
					7: PortMembershipUntagged,
					8: PortMembershipUntagged,
				},
			},
			10: {
				ID: 10,
				Ports: map[int]PortMembership{
					3: PortMembershipUntagged,
					4: PortMembershipUntagged,
					8: PortMembershipTagged,
				},
			},
			30: {
				ID: 30,
				Ports: map[int]PortMembership{
					7: PortMembershipTagged,
				},
			},
		},
		PVIDs: map[int]int{
			1: 1, 2: 1, 3: 1, 4: 10, 5: 1, 6: 1, 7: 1, 8: 1,
		},
	}

	desired := VLANState{
		PortCount: 8,
		VLANs: map[int]Vlan{
			1: {
				ID: 1,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
					2: PortMembershipUntagged,
					3: PortMembershipUntagged,
					5: PortMembershipUntagged,
					6: PortMembershipUntagged,
					7: PortMembershipUntagged,
					8: PortMembershipUntagged,
				},
			},
			10: {
				ID: 10,
				Ports: map[int]PortMembership{
					3: PortMembershipUntagged,
				},
			},
			20: {
				ID: 20,
				Ports: map[int]PortMembership{
					4: PortMembershipUntagged,
					8: PortMembershipTagged,
				},
			},
		},
		PVIDs: map[int]int{
			1: 1, 2: 1, 3: 1, 4: 20, 5: 1, 6: 1, 7: 1, 8: 1,
		},
	}

	plan, err := Plan(current, desired)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan) != 10 {
		t.Fatalf("Plan() emitted %d ops, want 10\n got: %q", len(plan), runPlan(t, plan))
	}

	want := []string{
		// Phase 1: added VLAN first.
		"add vlan 20",
		// Phase 2: widened memberships for step1 vids; the added vid
		// carries its exact desired membership here and nowhere else
		// (added vids are in step1 only, not step2).
		"set vlan 1 membership: 1=untagged 2=untagged 3=untagged 4=ignored 5=untagged 6=untagged 7=untagged 8=untagged",
		"set vlan 10 membership: 1=ignored 2=ignored 3=untagged 4=untagged 5=ignored 6=ignored 7=ignored 8=tagged",
		"set vlan 20 membership: 1=ignored 2=ignored 3=ignored 4=untagged 5=ignored 6=ignored 7=ignored 8=tagged",
		// Phase 3: PVIDs, vids ascending.
		"set pvids vlan 1 ports [1 2 3 5 6 7 8]",
		"set pvids vlan 20 ports [4]",
		// Phase 4: exact memberships for intersecting vids (added vids
		// were exact already), incl. the all-ignored pre-clear of
		// removed vlan 30.
		"set vlan 1 membership: 1=untagged 2=untagged 3=untagged 4=ignored 5=untagged 6=untagged 7=untagged 8=untagged",
		"set vlan 10 membership: 1=ignored 2=ignored 3=untagged 4=ignored 5=ignored 6=ignored 7=ignored 8=ignored",
		"set vlan 30 membership: 1=ignored 2=ignored 3=ignored 4=ignored 5=ignored 6=ignored 7=ignored 8=ignored",
		// Phase 5: delete last.
		"delete vlans [30]",
	}
	assertOps(t, runPlan(t, plan), want)
}

func TestVLANPlanEqualShortCircuitsToEmptyPlan(t *testing.T) {
	t.Parallel()

	state := VLANState{
		PortCount: 2,
		VLANs: map[int]Vlan{
			1: {
				ID: 1,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
					2: PortMembershipUntagged,
				},
			},
			10: {
				ID: 10,
				Ports: map[int]PortMembership{
					1: PortMembershipTagged,
				},
			},
		},
		PVIDs: map[int]int{
			1: 1, 2: 1,
		},
	}

	plan, err := Plan(state, state.Clone())
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plan) != 0 {
		t.Fatalf("Plan() emitted %d ops for equal states, want none: %q", len(plan), runPlan(t, plan))
	}
}

func TestVLANPlanRejectsInvalidDesired(t *testing.T) {
	t.Parallel()

	current := VLANState{
		PortCount: 2,
		VLANs: map[int]Vlan{
			1: {
				ID: 1,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
					2: PortMembershipUntagged,
				},
			},
		},
		PVIDs: map[int]int{
			1: 1, 2: 1,
		},
	}

	t.Run("missing pvid", func(t *testing.T) {
		t.Parallel()

		desired := VLANState{
			PortCount: 2,
			VLANs: map[int]Vlan{
				1: {
					ID: 1,
					Ports: map[int]PortMembership{
						1: PortMembershipUntagged,
						2: PortMembershipUntagged,
					},
				},
			},
			PVIDs: map[int]int{
				1: 1,
			},
		}

		plan, err := Plan(current, desired)
		if err == nil {
			t.Fatal("Plan() error = nil, want the validation error for the missing pvid")
		}
		if !strings.Contains(err.Error(), "pvids must include all 2 ports") {
			t.Fatalf("Plan() error = %v, want the pvid coverage error", err)
		}
		if plan != nil {
			t.Fatalf("Plan() = %q with error, want no ops", runPlan(t, plan))
		}
	})

	t.Run("pvid vlan ignores the port", func(t *testing.T) {
		t.Parallel()

		desired := VLANState{
			PortCount: 2,
			VLANs: map[int]Vlan{
				1: {
					ID: 1,
					Ports: map[int]PortMembership{
						1: PortMembershipUntagged,
					},
				},
				10: {
					ID: 10,
					Ports: map[int]PortMembership{
						1: PortMembershipTagged,
					},
				},
			},
			PVIDs: map[int]int{
				1: 1, 2: 10,
			},
		}

		plan, err := Plan(current, desired)
		if err == nil {
			t.Fatal("Plan() error = nil, want the validation error for the ignored pvid vlan membership")
		}
		if !strings.Contains(err.Error(), "pvid vlan 10 for port 2 cannot be ignored") {
			t.Fatalf("Plan() error = %v, want the ignored-pvid-vlan membership error", err)
		}
		if plan != nil {
			t.Fatalf("Plan() = %q with error, want no ops", runPlan(t, plan))
		}
	})
}

// TestVLANPlanSplicesPreservedPortMembership is a white-box test: with
// the settled VLANState.Validate, every validated desired state forces
// each port to be a non-ignored member of its PVID VLAN, so
// PreservedPorts(desired) is provably empty and the splice loop is
// unreachable through Plan (the two transposed originals carry the same
// property). The loop is therefore exercised directly, verbatim.
func TestVLANPlanSplicesPreservedPortMembership(t *testing.T) {
	t.Parallel()

	current := VLANState{
		PortCount: 4,
		VLANs: map[int]Vlan{
			1: {
				ID: 1,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
				},
			},
			5: {
				ID: 5,
				Ports: map[int]PortMembership{
					2: PortMembershipUntagged,
					3: PortMembershipTagged,
				},
			},
		},
		PVIDs: map[int]int{
			1: 1, 2: 5, 3: 1, 4: 1,
		},
	}

	t.Run("step2 lacks the pvid vlan", func(t *testing.T) {
		t.Parallel()

		step2 := make(map[int]Vlan)
		splicePreservedPorts(step2, current, []int{2}, 4)

		vlan, ok := step2[5]
		if !ok {
			t.Fatal("splice did not seed step2 with the current pvid vlan")
		}
		if vlan.ID != 5 {
			t.Fatalf("spliced vlan id = %d, want 5", vlan.ID)
		}
		if vlan.Ports[2] != PortMembershipUntagged {
			t.Fatalf("spliced port 2 membership = %q, want the current untagged membership", vlan.Ports[2])
		}
		if vlan.Ports[3] != PortMembershipTagged {
			t.Fatalf("untouched port 3 membership = %q, want the current tagged membership", vlan.Ports[3])
		}
	})

	t.Run("step2 pre-cleared the pvid vlan", func(t *testing.T) {
		t.Parallel()

		step2 := map[int]Vlan{
			5: {ID: 5, Ports: ignoredPorts(4)},
		}
		splicePreservedPorts(step2, current, []int{2}, 4)

		vlan := step2[5]
		if vlan.Ports[2] != PortMembershipUntagged {
			t.Fatalf("spliced port 2 membership = %q, want untagged overriding the all-ignored pre-clear", vlan.Ports[2])
		}
		if vlan.Ports[3] != PortMembershipIgnored {
			t.Fatalf("pre-cleared port 3 membership = %q, want ignored", vlan.Ports[3])
		}
	})
}

// TestPreserveRemovedVLANsSparesReferencedVLANs is likewise white-box:
// PreserveRemovedVLANs only matters when a preserved port exists, which
// validated desired states cannot produce (see the splice test above),
// so the filter — the exact computation the plan applies before its
// DeleteVLANsOp — is asserted directly against the exported helper.
func TestPreserveRemovedVLANsSparesReferencedVLANs(t *testing.T) {
	t.Parallel()

	current := VLANState{
		PortCount: 2,
		VLANs: map[int]Vlan{
			1: {
				ID: 1,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
					2: PortMembershipUntagged,
				},
			},
			5: {
				ID: 5,
				Ports: map[int]PortMembership{
					2: PortMembershipUntagged,
				},
			},
		},
		PVIDs: map[int]int{
			1: 1, 2: 5,
		},
	}

	filtered := PreserveRemovedVLANs([]int{5, 40}, current, []int{2})
	if !reflect.DeepEqual(filtered, []int{40}) {
		t.Fatalf("PreserveRemovedVLANs() = %v, want [40]: removed vlan 5 is still the pvid vlan of preserved port 2", filtered)
	}

	kept := PreserveRemovedVLANs([]int{5, 40}, current, nil)
	if !reflect.DeepEqual(kept, []int{5, 40}) {
		t.Fatalf("PreserveRemovedVLANs() = %v, want [5 40] without preserved ports", kept)
	}

	if PreserveRemovedVLANs(nil, current, []int{2}) != nil {
		t.Fatal("PreserveRemovedVLANs() with no removed vlans = non-nil, want nil")
	}
}

func TestVLANPlanPreClearsRemovedVLANBeforeDelete(t *testing.T) {
	t.Parallel()

	current := VLANState{
		PortCount: 2,
		VLANs: map[int]Vlan{
			1: {
				ID: 1,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
					2: PortMembershipUntagged,
				},
			},
			40: {
				ID: 40,
				Ports: map[int]PortMembership{
					2: PortMembershipTagged,
				},
			},
		},
		PVIDs: map[int]int{
			1: 1, 2: 1,
		},
	}

	desired := VLANState{
		PortCount: 2,
		VLANs: map[int]Vlan{
			1: {
				ID: 1,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
					2: PortMembershipUntagged,
				},
			},
		},
		PVIDs: map[int]int{
			1: 1, 2: 1,
		},
	}

	plan, err := Plan(current, desired)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	want := []string{
		"set vlan 1 membership: 1=untagged 2=untagged",
		"set pvids vlan 1 ports [1 2]",
		"set vlan 1 membership: 1=untagged 2=untagged",
		// The removed VLAN is pre-cleared to all-ignored in phase 4,
		// before the phase 5 delete.
		"set vlan 40 membership: 1=ignored 2=ignored",
		"delete vlans [40]",
	}
	assertOps(t, runPlan(t, plan), want)

	// The pre-clear must precede the delete op in the plan itself.
	deleteIndex := -1
	preClearIndex := -1
	for i, op := range plan {
		switch o := op.(type) {
		case SetMembershipOp:
			if o.VID == 40 {
				preClearIndex = i
			}
		case DeleteVLANsOp:
			deleteIndex = i
		}
	}
	if preClearIndex == -1 || deleteIndex == -1 || preClearIndex > deleteIndex {
		t.Fatalf("plan = %q, want the vlan 40 pre-clear before the delete op", runPlan(t, plan))
	}
}

// TestVLANPlanOpOrderIsDeterministic asserts ascending vid order inside
// every phase across several added, intersecting, removed, and PVID
// vids, and that repeated Plan() calls yield identical sequences.
func TestVLANPlanOpOrderIsDeterministic(t *testing.T) {
	t.Parallel()

	current := VLANState{
		PortCount: 2,
		VLANs: map[int]Vlan{
			1: {
				ID: 1,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
					2: PortMembershipUntagged,
				},
			},
			3: {
				ID: 3,
				Ports: map[int]PortMembership{
					1: PortMembershipTagged,
				},
			},
			5: {
				ID: 5,
				Ports: map[int]PortMembership{
					2: PortMembershipTagged,
				},
			},
		},
		PVIDs: map[int]int{
			1: 1, 2: 1,
		},
	}

	desired := VLANState{
		PortCount: 2,
		VLANs: map[int]Vlan{
			1: {
				ID: 1,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
					2: PortMembershipUntagged,
				},
			},
			2: {
				ID: 2,
				Ports: map[int]PortMembership{
					2: PortMembershipUntagged,
				},
			},
			3: {
				ID: 3,
				Ports: map[int]PortMembership{
					1: PortMembershipTagged,
				},
			},
			7: {
				ID: 7,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
				},
			},
		},
		PVIDs: map[int]int{
			1: 7, 2: 2,
		},
	}

	want := []string{
		"add vlan 2",
		"add vlan 7",
		"set vlan 1 membership: 1=untagged 2=untagged",
		"set vlan 2 membership: 1=ignored 2=untagged",
		"set vlan 3 membership: 1=tagged 2=ignored",
		"set vlan 7 membership: 1=untagged 2=ignored",
		"set pvids vlan 2 ports [2]",
		"set pvids vlan 7 ports [1]",
		// Phase 4 keys are intersecting and removed vids only; the
		// added vids (2, 7) already carry exact memberships from
		// phase 2.
		"set vlan 1 membership: 1=untagged 2=untagged",
		"set vlan 3 membership: 1=tagged 2=ignored",
		"set vlan 5 membership: 1=ignored 2=ignored",
		"delete vlans [5]",
	}

	plan, err := Plan(current, desired)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	assertOps(t, runPlan(t, plan), want)

	// Phase ordering over vids with mixed origins (added, intersecting,
	// removed, PVID-only) must be stable across runs.
	for run := 0; run < 5; run++ {
		plan, err := Plan(current, desired)
		if err != nil {
			t.Fatalf("Plan() run %d error = %v", run, err)
		}
		assertOps(t, runPlan(t, plan), want)
	}
}

func TestVLANPlanRunExecutesOpsAndPropagatesErrors(t *testing.T) {
	t.Parallel()

	plan := VLANPlan{
		AddVLANOp{VID: 2},
		SetPVIDsOp{VID: 2, Ports: []int{1}},
		DeleteVLANsOp{VIDs: []int{3}},
	}

	t.Run("ops reach the applier in plan order", func(t *testing.T) {
		t.Parallel()

		assertOps(t, runPlan(t, plan), []string{
			"add vlan 2",
			"set pvids vlan 2 ports [1]",
			"delete vlans [3]",
		})
	})

	t.Run("empty plan is a no-op", func(t *testing.T) {
		t.Parallel()

		applier := &recordingVLANApplier{}
		if err := Run(context.Background(), VLANPlan{}, applier); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if len(applier.ops) != 0 {
			t.Fatalf("Run() on empty plan recorded %q", applier.ops)
		}
	})

	t.Run("injected failure stops at the failing op unwrapped", func(t *testing.T) {
		t.Parallel()

		wireErr := errors.New("set pvids wire failure " + strconv.Itoa(41))
		applier := &recordingVLANApplier{failOn: 2, err: wireErr}

		err := Run(context.Background(), plan, applier)
		if !errors.Is(err, wireErr) {
			t.Fatalf("Run() error = %v, want the injected applier error unwrapped", err)
		}
		if err != wireErr {
			t.Fatal("Run() wrapped the applier error, want byte-for-byte propagation")
		}
		if got := applier.calls; got != 2 {
			t.Fatalf("applier saw %d calls, want 2 (Run must stop at the failing op)", got)
		}
		assertOps(t, applier.ops, []string{
			"add vlan 2",
			"set pvids vlan 2 ports [1]",
		})
	})
}
