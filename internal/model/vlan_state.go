package model

import (
	"fmt"
	"slices"
	"sort"
)

// PortMembership is the normalized per-port membership state.
type PortMembership string

const (
	PortMembershipIgnored  PortMembership = "ignored"
	PortMembershipUntagged PortMembership = "untagged"
	PortMembershipTagged   PortMembership = "tagged"
)

// Vlan represents one VLAN in normalized form.
type Vlan struct {
	ID    int
	Ports map[int]PortMembership
}

// VLANState is the canonical in-memory representation used for diffing.
type VLANState struct {
	PortCount int
	VLANs     map[int]Vlan
	PVIDs     map[int]int
}

// Clone returns a deep copy.
func (s VLANState) Clone() VLANState {
	cloned := VLANState{
		PortCount: s.PortCount,
		VLANs:     make(map[int]Vlan, len(s.VLANs)),
		PVIDs:     make(map[int]int, len(s.PVIDs)),
	}

	for vid, vlan := range s.VLANs {
		ports := make(map[int]PortMembership, len(vlan.Ports))
		for port, membership := range vlan.Ports {
			ports[port] = membership
		}
		cloned.VLANs[vid] = Vlan{ID: vlan.ID, Ports: ports}
	}

	for port, pvid := range s.PVIDs {
		cloned.PVIDs[port] = pvid
	}

	return cloned
}

// Normalize returns a normalized copy with full port coverage.
func (s VLANState) Normalize() VLANState {
	normalized := VLANState{
		PortCount: s.PortCount,
		VLANs:     make(map[int]Vlan, len(s.VLANs)),
		PVIDs:     make(map[int]int, len(s.PVIDs)),
	}

	for vid, vlan := range s.VLANs {
		ports := make(map[int]PortMembership, s.PortCount)
		for port := 1; port <= s.PortCount; port++ {
			membership, ok := vlan.Ports[port]
			if !ok {
				membership = PortMembershipIgnored
			}
			ports[port] = membership
		}
		normalized.VLANs[vid] = Vlan{
			ID:    vid,
			Ports: ports,
		}
	}

	for port, pvid := range s.PVIDs {
		normalized.PVIDs[port] = pvid
	}

	return normalized
}

// Validate checks semantic correctness for a complete switch state.
func (s VLANState) Validate() error {
	if s.PortCount <= 0 {
		return fmt.Errorf("port_count must be greater than zero")
	}

	if len(s.PVIDs) != s.PortCount {
		return fmt.Errorf("pvids must include all %d ports", s.PortCount)
	}

	for vid, vlan := range s.VLANs {
		if vid <= 0 {
			return fmt.Errorf("vlan id must be greater than zero")
		}

		for port, membership := range vlan.Ports {
			if port < 1 || port > s.PortCount {
				return fmt.Errorf("port %d is outside valid range 1..%d", port, s.PortCount)
			}
			switch membership {
			case PortMembershipIgnored, PortMembershipUntagged, PortMembershipTagged:
			default:
				return fmt.Errorf("invalid membership %q for port %d in vlan %d", membership, port, vid)
			}
		}
	}

	for port := 1; port <= s.PortCount; port++ {
		pvid, ok := s.PVIDs[port]
		if !ok {
			return fmt.Errorf("missing pvid for port %d", port)
		}

		vlan, ok := s.VLANs[pvid]
		if !ok {
			return fmt.Errorf("pvid %d for port %d does not exist", pvid, port)
		}

		if vlan.Ports[port] == PortMembershipIgnored {
			return fmt.Errorf("pvid vlan %d for port %d cannot be ignored", pvid, port)
		}
	}

	return nil
}

// Equal compares semantic state after normalization.
func (s VLANState) Equal(other VLANState) bool {
	left := s.Normalize()
	right := other.Normalize()

	if left.PortCount != right.PortCount {
		return false
	}

	if !mapsEqualInt(left.PVIDs, right.PVIDs) {
		return false
	}

	if len(left.VLANs) != len(right.VLANs) {
		return false
	}

	for vid, leftVLAN := range left.VLANs {
		rightVLAN, ok := right.VLANs[vid]
		if !ok {
			return false
		}
		if !mapsEqualMembership(leftVLAN.Ports, rightVLAN.Ports) {
			return false
		}
	}

	return true
}

// VLANIDs returns sorted VLAN IDs.
func (s VLANState) VLANIDs() []int {
	ids := make([]int, 0, len(s.VLANs))
	for vid := range s.VLANs {
		ids = append(ids, vid)
	}
	sort.Ints(ids)
	return ids
}

// SortedPorts returns all port numbers in ascending order.
func (s VLANState) SortedPorts() []int {
	ports := make([]int, 0, s.PortCount)
	for port := 1; port <= s.PortCount; port++ {
		ports = append(ports, port)
	}
	return ports
}

// AddedVLANs returns VLANs present in desired but absent in current.
func AddedVLANs(current, desired VLANState) []int {
	var vids []int
	for _, vid := range desired.VLANIDs() {
		if _, ok := current.VLANs[vid]; !ok {
			vids = append(vids, vid)
		}
	}
	return vids
}

// RemovedVLANs returns VLANs present in current but absent in desired.
func RemovedVLANs(current, desired VLANState) []int {
	var vids []int
	for _, vid := range current.VLANIDs() {
		if _, ok := desired.VLANs[vid]; !ok {
			vids = append(vids, vid)
		}
	}
	return vids
}

// PreserveRemovedVLANs filters removed VLANs that are still required as PVIDs.
func PreserveRemovedVLANs(removed []int, current VLANState, preservedPorts []int) []int {
	if len(removed) == 0 {
		return nil
	}

	blocked := make(map[int]struct{}, len(preservedPorts))
	for _, port := range preservedPorts {
		blocked[current.PVIDs[port]] = struct{}{}
	}

	filtered := removed[:0]
	for _, vid := range removed {
		if _, ok := blocked[vid]; ok {
			continue
		}
		filtered = append(filtered, vid)
	}

	return filtered
}

// PreservedPorts returns ports omitted from desired membership and therefore preserved.
func PreservedPorts(desired VLANState) []int {
	active := make(map[int]struct{})
	for _, vlan := range desired.VLANs {
		for port, membership := range vlan.Ports {
			if membership != PortMembershipIgnored {
				active[port] = struct{}{}
			}
		}
	}

	ports := make([]int, 0, desired.PortCount)
	for port := 1; port <= desired.PortCount; port++ {
		if _, ok := active[port]; ok {
			continue
		}
		ports = append(ports, port)
	}

	return ports
}

// BatchPVIDs transposes pvid assignments into VLAN->ports batches.
func BatchPVIDs(state VLANState) map[int][]int {
	grouped := make(map[int][]int)
	for port, vid := range state.PVIDs {
		grouped[vid] = append(grouped[vid], port)
	}
	for vid := range grouped {
		slices.Sort(grouped[vid])
	}
	return grouped
}

func mapsEqualInt(left, right map[int]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func mapsEqualMembership(left, right map[int]PortMembership) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
