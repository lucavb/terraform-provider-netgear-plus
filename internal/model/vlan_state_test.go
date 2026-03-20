package model

import "testing"

func TestVLANStateValidate(t *testing.T) {
	t.Parallel()

	state := VLANState{
		PortCount: 2,
		VLANs: map[int]Vlan{
			1: {
				ID: 1,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
					2: PortMembershipTagged,
				},
			},
			10: {
				ID: 10,
				Ports: map[int]PortMembership{
					1: PortMembershipTagged,
					2: PortMembershipUntagged,
				},
			},
		},
		PVIDs: map[int]int{
			1: 1,
			2: 10,
		},
	}

	if err := state.Validate(); err != nil {
		t.Fatalf("Validate() returned error: %v", err)
	}
}

func TestVLANStateEqualNormalizesImplicitIgnoredPorts(t *testing.T) {
	t.Parallel()

	left := VLANState{
		PortCount: 2,
		VLANs: map[int]Vlan{
			1: {
				ID: 1,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
				},
			},
		},
		PVIDs: map[int]int{
			1: 1,
			2: 1,
		},
	}

	right := VLANState{
		PortCount: 2,
		VLANs: map[int]Vlan{
			1: {
				ID: 1,
				Ports: map[int]PortMembership{
					1: PortMembershipUntagged,
					2: PortMembershipIgnored,
				},
			},
		},
		PVIDs: map[int]int{
			1: 1,
			2: 1,
		},
	}

	if !left.Equal(right) {
		t.Fatal("Equal() should treat omitted ports as ignored after normalization")
	}
}
