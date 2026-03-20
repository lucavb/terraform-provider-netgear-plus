package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

func TestVLANStateResourceSchemaUsesRepeatableVLANBlocks(t *testing.T) {
	t.Parallel()

	r := &vlanStateResource{}
	var resp resource.SchemaResponse

	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)

	if _, ok := resp.Schema.Attributes["vlan"]; ok {
		t.Fatal("schema should expose vlan as a block, not an attribute")
	}

	block, ok := resp.Schema.Blocks["vlan"]
	if !ok {
		t.Fatal("schema should expose vlan block")
	}

	listBlock, ok := block.(rschema.ListNestedBlock)
	if !ok {
		t.Fatalf("schema block type = %T, want resource/schema.ListNestedBlock", block)
	}

	if _, ok := listBlock.NestedObject.Attributes["id"]; !ok {
		t.Fatal("vlan block should include id attribute")
	}
	if _, ok := listBlock.NestedObject.Attributes["ports"]; !ok {
		t.Fatal("vlan block should include ports attribute")
	}

	if diags := resp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatalf("schema validation returned errors: %v", diags)
	}
}

func TestBlockedVLANRemovalsDisallowsDeletesByDefault(t *testing.T) {
	t.Parallel()

	current := model.VLANState{
		PortCount: 2,
		VLANs: map[int]model.Vlan{
			1:  {ID: 1, Ports: map[int]model.PortMembership{1: model.PortMembershipUntagged, 2: model.PortMembershipUntagged}},
			10: {ID: 10, Ports: map[int]model.PortMembership{1: model.PortMembershipTagged, 2: model.PortMembershipTagged}},
		},
		PVIDs: map[int]int{1: 1, 2: 1},
	}
	desired := model.VLANState{
		PortCount: 2,
		VLANs: map[int]model.Vlan{
			1: {ID: 1, Ports: map[int]model.PortMembership{1: model.PortMembershipUntagged, 2: model.PortMembershipUntagged}},
		},
		PVIDs: map[int]int{1: 1, 2: 1},
	}

	removed := blockedVLANRemovals(current, desired, types.BoolNull())
	if len(removed) != 1 || removed[0] != 10 {
		t.Fatalf("blockedVLANRemovals() = %v", removed)
	}
}

func TestBlockedVLANRemovalsAllowsExplicitDeletes(t *testing.T) {
	t.Parallel()

	current := model.VLANState{
		PortCount: 1,
		VLANs: map[int]model.Vlan{
			1:  {ID: 1, Ports: map[int]model.PortMembership{1: model.PortMembershipUntagged}},
			20: {ID: 20, Ports: map[int]model.PortMembership{1: model.PortMembershipTagged}},
		},
		PVIDs: map[int]int{1: 1},
	}
	desired := model.VLANState{
		PortCount: 1,
		VLANs: map[int]model.Vlan{
			1: {ID: 1, Ports: map[int]model.PortMembership{1: model.PortMembershipUntagged}},
		},
		PVIDs: map[int]int{1: 1},
	}

	if removed := blockedVLANRemovals(current, desired, types.BoolValue(true)); len(removed) != 0 {
		t.Fatalf("blockedVLANRemovals() = %v", removed)
	}
}

func TestRequireExpectedSerialNumber(t *testing.T) {
	t.Parallel()

	if err := requireExpectedSerialNumber(types.StringNull()); err == nil {
		t.Fatal("requireExpectedSerialNumber() should reject null values")
	}
	if err := requireExpectedSerialNumber(types.StringValue("   ")); err == nil {
		t.Fatal("requireExpectedSerialNumber() should reject blank values")
	}
	if err := requireExpectedSerialNumber(types.StringValue("ABC123")); err != nil {
		t.Fatalf("requireExpectedSerialNumber() error = %v", err)
	}
}

func TestAssertExpectedSerialNumber(t *testing.T) {
	t.Parallel()

	if err := assertExpectedSerialNumber(types.StringValue("ABC123"), "ABC123"); err != nil {
		t.Fatalf("assertExpectedSerialNumber() error = %v", err)
	}
	if err := assertExpectedSerialNumber(types.StringValue("ABC123"), "XYZ999"); err == nil {
		t.Fatal("assertExpectedSerialNumber() should reject mismatched serial numbers")
	}
}

func TestCanonicalHostKeyNormalizesDefaultPorts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "bare host", host: "192.0.2.10", want: "192.0.2.10"},
		{name: "http default port", host: "192.0.2.10:80", want: "192.0.2.10"},
		{name: "http explicit scheme", host: "http://192.0.2.10:80", want: "192.0.2.10"},
		{name: "https default port", host: "https://192.0.2.10:443", want: "192.0.2.10"},
		{name: "non-default port preserved", host: "https://192.0.2.10:8443", want: "192.0.2.10:8443"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := canonicalHostKey(tt.host); got != tt.want {
				t.Fatalf("canonicalHostKey(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}
