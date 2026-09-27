package gs108tv2

import (
	"context"
	"fmt"
	"strings"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/fastpath"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// ReadSwitchFacts extracts switch identity facts from a fresh text
// config fetch.
//
// Channel limits (documented):
//   - SerialNumber is "" — the text-config channel cannot read it; the
//     serial is pinned via NSDP v1 identity at the provider layer.
//   - BootloaderVersion is "" — the text config carries no bootloader
//     annotation on this firmware line.
//   - SwitchName is "" — the startup-config has no system-name field
//     in the factory emitter's output.
func (d *Driver) ReadSwitchFacts(ctx context.Context) (model.SwitchFacts, error) {
	raw, err := d.SaveStartupConfig(ctx)
	if err != nil {
		return model.SwitchFacts{}, err
	}
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		return model.SwitchFacts{}, fmt.Errorf("gs108tv2: facts: %w", err)
	}

	facts := model.SwitchFacts{
		Host:              d.cfg.Host,
		Model:             strings.ToLower(strings.TrimSpace(tc.SystemDescription)),
		FirmwareVersion:   tc.SystemSoftwareVersion,
		SerialNumber:      "",
		BootloaderVersion: "",
		SwitchName:        "",
	}
	if facts.Model == "" {
		// Degenerate config without a description annotation: the
		// channel only speaks to this generation anyway.
		facts.Model = "gs108tv2"
	}
	facts.MACAddress = switchMACFromConfig(tc)
	return facts, nil
}

// switchMACFromConfig pulls the MAC from the spanning-tree
// configuration name (the switch self-names its STP identity with the
// dash-separated uppercase MAC, e.g.
// `spanning-tree configuration name "8C-3B-AD-2C-E9-7D"`, emitted
// inside the configure section body) and normalizes it to
// colon-separated lowercase. Empty when the annotation is absent.
func switchMACFromConfig(tc fastpath.TextConfig) string {
	for _, l := range strings.Split(string(tc.Raw), "\n") {
		line := strings.TrimSpace(strings.TrimRight(l, "\r"))
		if !strings.HasPrefix(line, stpNamePrefix) {
			continue
		}
		value := quotedValue(line)
		if value == "" {
			return ""
		}
		return strings.ToLower(strings.ReplaceAll(value, "-", ":"))
	}
	return ""
}

// stpNamePrefix marks the spanning-tree identity line.
const stpNamePrefix = "spanning-tree configuration name"

// quotedValue returns the content of the first double-quoted field of
// the line, or "".
func quotedValue(line string) string {
	i := strings.IndexByte(line, '"')
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(line[i+1:], '"')
	if j < 0 {
		return ""
	}
	return line[i+1 : i+1+j]
}
