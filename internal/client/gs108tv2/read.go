package gs108tv2

import (
	"context"
	"fmt"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/fastpath"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// ---------------------------------------------------------------------------
// ReadVLANState / ReadPortSettings: the driver-package READ sides of the
// two managed namespaces. NO CACHING: every call performs its own fresh
// SaveStartupConfig, so the caller always sees the switch's live staging
// state (the resource layer compares plan vs device freshly on every
// apply). Fail-closed: a decode error (ErrGrammarLine / ErrMissingSection
// from the codec) surfaces verbatim — the reads never guess.
//
// Scope note (milestone 3): BOTH namespaces decode in one pass here
// (decodeTextConfig handles vlan + port grammar together), and each read
// returns from the SAME single decode — decode once, expose twice. The
// VLAN state reads the STARTUP config only: running VLAN state is
// UNREADABLE on this firmware, so plan/verify compares against the
// staged file's content until the next reboot.
// ---------------------------------------------------------------------------

// ReadVLANState fetches a fresh startup-config and decodes its VLAN
// state. This is the one authoritative VLAN decode surface; provider
// transports and the plan/verify pipeline must use it (they must NOT
// re-implement the codec).
func (d *Driver) ReadVLANState(ctx context.Context) (model.VLANState, error) {
	raw, err := d.SaveStartupConfig(ctx)
	if err != nil {
		return model.VLANState{}, err
	}
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		return model.VLANState{}, fmt.Errorf("gs108tv2: read vlan state: %w", err)
	}
	dec, err := decodeTextConfig(tc)
	if err != nil {
		return model.VLANState{}, fmt.Errorf("gs108tv2: read vlan state: %w", err)
	}
	return dec.State, nil
}

// ReadPortSettings fetches a fresh startup-config and decodes the
// per-port admin settings (interface 0/1..0/8 bodies). Ports the
// config carries no section for decode at their factory defaults
// (absence semantics of the codec).
func (d *Driver) ReadPortSettings(ctx context.Context) (map[int]PortSettings, error) {
	raw, err := d.SaveStartupConfig(ctx)
	if err != nil {
		return nil, err
	}
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("gs108tv2: read port settings: %w", err)
	}
	dec, err := decodeTextConfig(tc)
	if err != nil {
		return nil, fmt.Errorf("gs108tv2: read port settings: %w", err)
	}
	return dec.Ports, nil
}
