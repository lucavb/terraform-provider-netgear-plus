package model

import "fmt"

// SwitchFacts contains stable read-only metadata about a switch.
type SwitchFacts struct {
	Host              string
	Model             string
	SwitchName        string
	SerialNumber      string
	MACAddress        string
	FirmwareVersion   string
	BootloaderVersion string
}

// ResourceID returns a stable Terraform resource/data source identifier.
func (f SwitchFacts) ResourceID() string {
	return fmt.Sprintf("%s@%s", f.Model, f.Host)
}
