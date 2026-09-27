package main

import (
	"reflect"
	"testing"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client/gs108tv2"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

func TestValidateRestoreFlags(t *testing.T) {
	tests := []struct {
		name      string
		file      string
		roundtrip bool
		wantErr   bool
	}{
		{"roundtrip only", "", true, false},
		{"file only", "GS108Ev3.cfg", false, false},
		{"neither set", "", false, true},
		{"both set", "GS108Ev3.cfg", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRestoreFlags(tt.file, tt.roundtrip)
			if tt.wantErr && err == nil {
				t.Fatalf("validateRestoreFlags(%q, %v) = nil, want error", tt.file, tt.roundtrip)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateRestoreFlags(%q, %v) = %v, want nil", tt.file, tt.roundtrip, err)
			}
		})
	}
}

func TestValidateApplyVLANStateFlags(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		password string
		file     string
		wantErr  bool
	}{
		{"all present", "10.0.2.8", "sekrit", "vlan-spec.json", false},
		{"missing host", "", "sekrit", "vlan-spec.json", true},
		{"missing password", "10.0.2.8", "", "vlan-spec.json", true},
		{"missing file", "10.0.2.8", "sekrit", "", true},
		{"all missing", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateApplyVLANStateFlags(tt.host, tt.password, tt.file)
			if tt.wantErr && err == nil {
				t.Fatalf("validateApplyVLANStateFlags(%q, %q, %q) = nil, want error", tt.host, tt.password, tt.file)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateApplyVLANStateFlags(%q, %q, %q) = %v, want nil", tt.host, tt.password, tt.file, err)
			}
		})
	}
}

func TestParseApplyVLANStateSpec(t *testing.T) {
	t.Run("valid spec builds the state", func(t *testing.T) {
		state, err := parseApplyVLANStateSpec([]byte(`{
			"vlans": [
				{"id": 42, "ports": {"1": "tagged", "2": "untagged"}}
			],
			"pvids": {"2": 42}
		}`))
		if err != nil {
			t.Fatalf("parseApplyVLANStateSpec() error = %v", err)
		}
		if state.PortCount != 8 {
			t.Fatalf("PortCount = %d, want 8", state.PortCount)
		}
		vlan, ok := state.VLANs[42]
		if !ok {
			t.Fatalf("VLAN 42 missing from %v", state.VLANs)
		}
		if vlan.Ports[1] != model.PortMembershipTagged {
			t.Fatalf("port 1 = %s, want tagged", vlan.Ports[1])
		}
		if vlan.Ports[2] != model.PortMembershipUntagged {
			t.Fatalf("port 2 = %s, want untagged", vlan.Ports[2])
		}
		if state.PVIDs[2] != 42 {
			t.Fatalf("port 2 PVID = %d, want 42", state.PVIDs[2])
		}
		// Omitted ports normalize to ignored.
		if vlan.Ports[7] != model.PortMembershipIgnored {
			t.Fatalf("port 7 = %s, want ignored (ommitted ports normalize away)", vlan.Ports[7])
		}
	})

	t.Run("empty spec is the normalized default state", func(t *testing.T) {
		state, err := parseApplyVLANStateSpec([]byte(`{}`))
		if err != nil {
			t.Fatalf("parseApplyVLANStateSpec() error = %v", err)
		}
		norm := (model.VLANState{PortCount: 8, VLANs: map[int]model.Vlan{}, PVIDs: map[int]int{}}).Normalize()
		if !state.Equal(norm) {
			t.Fatalf("empty spec parsed %+v, want the normalized default %+v", state, norm)
		}
	})

	t.Run("malformed JSON fails", func(t *testing.T) {
		if _, err := parseApplyVLANStateSpec([]byte(`{"vlans":`)); err == nil {
			t.Fatal("malformed JSON must fail")
		}
	})

	t.Run("bad port key fails", func(t *testing.T) {
		for _, bad := range []string{`{"pvids":{"9":1}}`, `{"pvids":{"zero":1}}`, `{"vlans":[{"id":42,"ports":{"0":"tagged"}}]}`} {
			if _, err := parseApplyVLANStateSpec([]byte(bad)); err == nil {
				t.Fatalf("spec %s must fail", bad)
			}
		}
	})

	t.Run("bad membership fails", func(t *testing.T) {
		if _, err := parseApplyVLANStateSpec([]byte(`{"vlans":[{"id":42,"ports":{"1":"hybrid"}}]}`)); err == nil {
			t.Fatal("membership \"hybrid\" must fail")
		}
	})

	t.Run("out-of-range VLAN id fails", func(t *testing.T) {
		if _, err := parseApplyVLANStateSpec([]byte(`{"vlans":[{"id":4095}]}`)); err == nil {
			t.Fatal("VLAN id 4095 must fail")
		}
	})
}

func TestValidateRebootFlags(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		password string
		wantErr  bool
	}{
		{"both present", "10.0.2.8", "sekrit", false},
		{"missing host", "", "sekrit", true},
		{"missing password", "10.0.2.8", "", true},
		{"both missing", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRebootFlags(tt.host, tt.password)
			if tt.wantErr && err == nil {
				t.Fatalf("validateRebootFlags(%q, %q) = nil, want error", tt.host, tt.password)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateRebootFlags(%q, %q) = %v, want nil", tt.host, tt.password, err)
			}
		})
	}
}

func TestParsePortSettingsSpec(t *testing.T) {
	t.Run("valid spec with defaults and overrides", func(t *testing.T) {
		settings, err := parsePortSettingsSpec([]byte(`{
			"ports": [
				{"port": 3, "enabled": true, "flow_control": true},
				{"port": 5, "enabled": false, "qos_priority": "LOW"}
			]
		}`))
		if err != nil {
			t.Fatalf("parsePortSettingsSpec() error = %v", err)
		}
		want := gs108tv2.DefaultPortSettingsMap()
		p3 := want[3]
		p3.FlowControl = true
		want[3] = p3
		p5 := want[5]
		p5.Enabled = false
		want[5] = p5

		for port := 1; port <= 8; port++ {
			if settings[port] != want[port] {
				t.Fatalf("port %d = %+v, want %+v", port, settings[port], want[port])
			}
		}
		if len(settings) != 8 {
			t.Fatalf("map size = %d, want 8 (defaults fill the gaps)", len(settings))
		}
	})

	t.Run("empty spec is the factory map", func(t *testing.T) {
		settings, err := parsePortSettingsSpec([]byte(`{}`))
		if err != nil {
			t.Fatalf("parsePortSettingsSpec({}) error = %v", err)
		}
		if want := gs108tv2.DefaultPortSettingsMap(); !reflect.DeepEqual(settings, want) {
			t.Fatalf("empty spec = %+v, want factory defaults", settings)
		}
	})

	t.Run("malformed JSON fails", func(t *testing.T) {
		if _, err := parsePortSettingsSpec([]byte(`{"ports":`)); err == nil {
			t.Fatal("malformed JSON must fail")
		}
	})

	t.Run("bad port numbers fail", func(t *testing.T) {
		for _, bad := range []string{
			`{"ports":[{"port":9,"enabled":true}]}`,
			`{"ports":[{"port":0,"enabled":true}]}`,
			`{"ports":[{"enabled":true}]}`,
		} {
			if _, err := parsePortSettingsSpec([]byte(bad)); err == nil {
				t.Fatalf("spec %s must fail", bad)
			}
		}
	})

	t.Run("duplicate ports fail", func(t *testing.T) {
		if _, err := parsePortSettingsSpec([]byte(`{"ports":[{"port":3,"enabled":true},{"port":3,"enabled":false}]}`)); err == nil {
			t.Fatal("duplicate port entries must fail")
		}
	})

	t.Run("bad enum values fail", func(t *testing.T) {
		for _, bad := range []string{
			`{"ports":[{"port":3,"qos_priority":"urgent"}]}`,
			`{"ports":[{"port":3,"ingress_rate":"10m"}]}`,
			`{"ports":[{"port":3,"egress_rate":null}]}`,
		} {
			_, err := parsePortSettingsSpec([]byte(bad))
			// null fields are "omitted" and must NOT fail; discard the
			// semantic difference by checking only the enum rejects.
			if bad == `{"ports":[{"port":3,"egress_rate":null}]}` {
				if err != nil {
					t.Fatalf("null field must be treated as omitted, got %v", err)
				}
				continue
			}
			if err == nil {
				t.Fatalf("spec %s must fail", bad)
			}
		}
	})
}
