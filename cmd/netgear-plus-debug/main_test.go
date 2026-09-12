package main

import "testing"

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
