package gs108tv2

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/fastpath"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// ApplyOutcome reports the result of a stage-only apply.
type ApplyOutcome struct {
	// Staged is true when the re-fetched startup-config parses to the
	// desired state (structural verify, model.Equal — the truth).
	Staged bool

	// CanonicalDiverged is the WARNING signal: the re-fetched
	// config's CanonicalBytes (uptime line excluded) differ from the
	// uploaded bytes'. The state still matched, so the switch rewrote
	// the file through its own normalizer (e.g. emitted an explicit
	// `vlan 1` declaration the codec never generates). Never a
	// failure by comparison discipline.
	CanonicalDiverged bool
}

// ErrRestoreRejected is the switch-side rejection of the restore POST
// itself (err_flag=1 / non-2xx page, e.g. "Invalid text config
// header!"). Not retried: the upload never left the gate.
type ErrRestoreRejected struct {
	Detail string
}

func (e *ErrRestoreRejected) Error() string {
	return "gs108tv2: config restore rejected by switch: " + e.Detail
}

// ErrRestoreDeadline is the typed end-state of a transient ingest
// window that never cleared within Config.RestoreWaitTimeout. Cause
// carries the LAST observed failure and LastClass its class ("login",
// "fetch" or "parse") for diagnostics.
type ErrRestoreDeadline struct {
	Wait      time.Duration
	LastClass string
	Cause     error
}

func (e *ErrRestoreDeadline) Error() string {
	note := ""
	if e.LastClass == "login" {
		// Post-restore login refusals for the whole window are
		// expected while the switch ingests (~2 min on 5.4.2.36);
		// a full-window refusal usually means the wait budget did
		// not cover the ingest or the restore truly failed.
		note = "; post-restore logins refused for the entire ingest window are expected, but a full-window refusal also means the restore may have not landed — check the switch"
	}
	return fmt.Sprintf("gs108tv2: staged startup-config did not verify within %s (last failure class %q): %v%s",
		e.Wait, e.LastClass, e.Cause, note)
}

func (e *ErrRestoreDeadline) Unwrap() error { return e.Cause }

// ErrDriftDetected is the typed verification failure for a fetch that
// parses cleanly to a DIFFERENT VLAN state than desired: the switch is
// serving its own consistent file, so this is real drift — never a
// transient artifact (mangled mid-ingest fetches fail header/parse
// validation and are retried instead).
type ErrDriftDetected struct {
	Detail string
}

func (e *ErrDriftDetected) Error() string {
	return "gs108tv2: staged startup-config drifted from the desired state: " + e.Detail
}

// verifyPlan is what waitTransientAndVerify must find in the
// re-fetched config. Both namespaces are always checked when available:
// a VLAN apply carries the pre-apply port settings (proves the VLAN
// render preserved them) and a port apply carries the pre-apply VLAN
// state (proves the port render preserved it). vlanCheck=false skips
// the VLAN dimension (port applies over configs whosevlan bodies carry
// foreign/unpinned `vlan` lines the codec refuses to interpret); those
// lines survive the port render as passthrough either way.
type verifyPlan struct {
	vlan       model.VLANState
	vlanCheck  bool
	ports      map[int]PortSettings
	portsCheck bool
}

// ApplyVLANState stages the desired state into the startup-config.
//
// Flow (STAGE-ONLY — no reboot):
//  1. fresh SaveStartupConfig (NO CACHING), parse, decode;
//  2. SHORT-CIRCUIT: if the fetched config already parses Equal to the
//     desired state, return Staged WITHOUT a ConfigRestore and without
//     the wait loop — after a reboot failure the next apply must only
//     re-attempt the reboot (re-stage would pointlessly burn a restore
//     cycle), and no-op applies are cheap;
//  3. capture foreign lines inside managed sections, render desired
//     into a TextConfigEditor (vlan database body + interface
//     0/1..0/8 PVID lines; everything else untouched, so `interface
//     3/x`, the configure preamble and the PORT settings line stay
//     byte-identical);
//  4. ConfigRestore; switch-side rejection is an immediate error;
//  5. waitTransientAndVerify: poll through the ingest window until the
//     re-fetched config structurally equals the desired state (VLAN
//     state AND untouched port settings).
//
// The DEFAULT state renders byte-identically to the factory shape.
func (d *Driver) ApplyVLANState(ctx context.Context, desired model.VLANState) (ApplyOutcome, error) {
	norm := desired.Normalize()
	if err := validateRenderable(norm); err != nil {
		return ApplyOutcome{}, err
	}
	if err := ctx.Err(); err != nil {
		return ApplyOutcome{}, err
	}

	raw, err := d.SaveStartupConfig(ctx)
	if err != nil {
		return ApplyOutcome{}, err
	}
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		return ApplyOutcome{}, fmt.Errorf("gs108tv2: apply: parse fetched config: %w", err)
	}

	// Short-circuit on a full decode; fall back to the render path on
	// foreign `vlan` grammar the codec refuses to interpret (the
	// render replaces managed bodies wholesale, so unpinned vlan lines
	// are superseded by the desired state, F2a semantics).
	dec, derr := decodeTextConfig(tc)
	if derr == nil && dec.State.Equal(norm) {
		// Idempotent: staged content already matches. No restore, no
		// ingest-window wait.
		return ApplyOutcome{Staged: true}, nil
	}

	plan := verifyPlan{
		vlan:       norm,
		vlanCheck:  true,
		ports:      dec.Ports,
		portsCheck: true,
	}

	foreign := captureForeign(tc)
	editor, err := fastpath.NewTextConfigEditor(tc)
	if err != nil {
		return ApplyOutcome{}, fmt.Errorf("gs108tv2: apply: open editor: %w", err)
	}
	upload, err := renderVLANState(editor, norm, foreign)
	if err != nil {
		return ApplyOutcome{}, fmt.Errorf("gs108tv2: apply: %w", err)
	}
	// Pre-flight the firmware's own header guards so a malformed
	// upload fails locally instead of on the switch.
	if err := fastpath.ValidateTextConfigHeader(upload, tc.SystemDescription, tc.SystemSoftwareVersion); err != nil {
		return ApplyOutcome{}, fmt.Errorf("gs108tv2: apply: %w", err)
	}

	outcome, err := d.restoreAndVerify(ctx, plan, upload)
	if err != nil {
		return ApplyOutcome{}, err
	}
	return outcome, nil
}

// restoreAndVerify uploads the rendered bytes and runs the convergence
// wait loop; shared by both codecs (VLAN and port).
func (d *Driver) restoreAndVerify(ctx context.Context, plan verifyPlan, upload []byte) (ApplyOutcome, error) {
	session := d.sessionHandle()
	if session == nil {
		return ApplyOutcome{}, fmt.Errorf("gs108tv2: apply: no live session after fresh save")
	}
	res, rerr := session.ConfigRestore(upload, "startup-config")
	if rerr != nil {
		return ApplyOutcome{}, fmt.Errorf("gs108tv2: apply: config restore: %w", rerr)
	}
	if res.Failed() {
		return ApplyOutcome{}, &ErrRestoreRejected{Detail: res.Error()}
	}
	return d.waitTransientAndVerify(ctx, plan, upload)
}

// ApplyPortSettings stages the desired per-port admin settings
// (`interface 0/1`..`0/8` bodies) via the same restore → converge flow
// as the VLAN codec.
//
// Namespace symmetry (each codec passes the other through):
//   - the port render regenerates ONLY `shutdown` / `flow control`
//     lines and keeps `vlan pvid` + foreign lines in their original
//     order (dec.PortPass);
//   - the VLAN render keeps the port lines as its foreign capture, so
//     applying VLANs never disturbs port settings and vice versa;
//   - capability-gated: unsupported attributes may only carry their
//     default value (absence render); a non-default value is refused
//     by typed error BEFORE any upload;
//   - SHORT-CIRCUIT: if the fresh config already decodes Equal to the
//     desired port map (and the VLAN state is intact), no restore and
//     no wait — idempotent re-applies after a reboot failure stay
//     cheap;
//   - `interface 3/x` sections are NEVER managed.
func (d *Driver) ApplyPortSettings(ctx context.Context, desired map[int]PortSettings) (ApplyOutcome, error) {
	norm := normalizePortSettings(desired)
	if err := validatePortSettings(norm); err != nil {
		return ApplyOutcome{}, err
	}
	if err := ctx.Err(); err != nil {
		return ApplyOutcome{}, err
	}

	raw, err := d.SaveStartupConfig(ctx)
	if err != nil {
		return ApplyOutcome{}, err
	}
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		return ApplyOutcome{}, fmt.Errorf("gs108tv2: ports: parse fetched config: %w", err)
	}

	dec, derr := decodeTextConfig(tc)
	if derr == nil && equalPortSettings(dec.Ports, norm) {
		// Idempotent: port settings already staged. No restore, no
		// wait (the VLAN state is untouched by definition).
		return ApplyOutcome{Staged: true}, nil
	}

	editor, err := fastpath.NewTextConfigEditor(tc)
	if err != nil {
		return ApplyOutcome{}, fmt.Errorf("gs108tv2: ports: open editor: %w", err)
	}
	upload, err := renderPortSettings(editor, tc, norm, dec.PortPass)
	if err != nil {
		return ApplyOutcome{}, fmt.Errorf("gs108tv2: ports: %w", err)
	}
	if err := fastpath.ValidateTextConfigHeader(upload, tc.SystemDescription, tc.SystemSoftwareVersion); err != nil {
		return ApplyOutcome{}, fmt.Errorf("gs108tv2: ports: %w", err)
	}

	plan := verifyPlan{
		// The port render passes VLAN lines through verbatim, so the
		// VLAN state must decode identically after the apply — unless
		// the current config carries vlan grammar the codec refuses
		// to interpret (those lines survive as passthrough either way,
		// they are just not verifiable through the codec).
		vlan:       dec.State,
		vlanCheck:  derr == nil,
		ports:      norm,
		portsCheck: true,
	}
	outcome, err := d.restoreAndVerify(ctx, plan, upload)
	if err != nil {
		return ApplyOutcome{}, err
	}
	return outcome, nil
}

// waitTransientAndVerify polls through the post-restore ingest window
// until the re-fetched startup-config parses to the desired state.
//
// Failure classification (transient artifacts are NEVER drift):
//   - login refused/failed: still inside the window → keep polling
//     (fresh session per poll — emweb SIDs are connection-bound);
//   - SaveConfig error, including the firmware-validated header
//     failure on a mangled mid-ingest fetch ("!x4e47…"): transient →
//     keep polling;
//   - parse error or fail-closed grammar error: classified "parse" →
//     transient, keep polling;
//   - decoded state ≠ desired: REAL drift → ErrDriftDetected
//     immediately (stage-only semantics: the fetched file is the
//     switch's own written outcome; more waiting cannot invent it).
//
// Deadline exhausted → ErrRestoreDeadline carrying the last failure
// class (and a whole-window note for the all-logins-refused case).
func (d *Driver) waitTransientAndVerify(ctx context.Context, plan verifyPlan, uploaded []byte) (ApplyOutcome, error) {
	uploadedTC, err := fastpath.ParseTextConfig(uploaded)
	if err != nil {
		// Defensive: the editor rendered it and ValidateTextConfigHeader
		// passed; this cannot happen.
		return ApplyOutcome{}, fmt.Errorf("gs108tv2: apply: uploaded config does not parse: %w", err)
	}
	uploadedCanonical := string(uploadedTC.CanonicalBytes())

	if err := sleepCtx(ctx, d.cfg.RestoreFirstDelay); err != nil {
		return ApplyOutcome{}, err
	}
	deadline := time.Now().Add(d.cfg.RestoreWaitTimeout)

	lastClass, lastErr := "", error(nil)

	for {
		if err := ctx.Err(); err != nil {
			return ApplyOutcome{}, err
		}

		// 1. Fresh login per poll.
		if lerr := d.Login(ctx); lerr != nil {
			lastClass, lastErr = "login", lerr
			if werr := d.sleepToDeadline(ctx, deadline, &lastClass, &lastErr); werr != nil {
				return ApplyOutcome{}, werr
			}
			continue
		}

		// 2. Fresh save: auth refusals, stale-session 404s and the
		// mangled mid-ingest fetch (header validation inside
		// SaveConfig) all surface as "fetch".
		raw, serr := d.sessionHandle().SaveConfig()
		if serr != nil {
			lastClass, lastErr = "fetch", serr
			if werr := d.sleepToDeadline(ctx, deadline, &lastClass, &lastErr); werr != nil {
				return ApplyOutcome{}, werr
			}
			continue
		}

		// 3. Parse + decode: parse errors are transient, never drift.
		tc, perr := fastpath.ParseTextConfig(raw)
		if perr != nil {
			lastClass, lastErr = "parse", perr
			if werr := d.sleepToDeadline(ctx, deadline, &lastClass, &lastErr); werr != nil {
				return ApplyOutcome{}, werr
			}
			continue
		}
		dec, derr := decodeTextConfig(tc)
		if derr != nil {
			lastClass, lastErr = "parse", derr
			if werr := d.sleepToDeadline(ctx, deadline, &lastClass, &lastErr); werr != nil {
				return ApplyOutcome{}, werr
			}
			continue
		}

		// 4. Structural verify: the truth is whole-decode Equal,
		// nothing else. Both namespaces when the plan covers them.
		if plan.vlanCheck && !dec.State.Equal(plan.vlan) {
			return ApplyOutcome{}, &ErrDriftDetected{
				Detail: fmt.Sprintf("re-fetched config decodes to %s, want %s",
					summariseVLANState(dec.State), summariseVLANState(plan.vlan)),
			}
		}
		if plan.portsCheck && !equalPortSettings(dec.Ports, plan.ports) {
			return ApplyOutcome{}, &ErrDriftDetected{
				Detail: fmt.Sprintf("re-fetched port settings drifted: %s", describePortsDelta(plan.ports, dec.Ports)),
			}
		}

		// Converged. Canonical byte divergence is recorded as the
		// warning only.
		outcome := ApplyOutcome{Staged: true}
		outcome.CanonicalDiverged = string(tc.CanonicalBytes()) != uploadedCanonical
		return outcome, nil
	}
}

// sleepToDeadline waits one poll interval without crossing deadline.
// Past the deadline it returns ErrRestoreDeadline carrying the live
// last-failure context.
func (d *Driver) sleepToDeadline(ctx context.Context, deadline time.Time, lastClass *string, lastErr *error) error {
	remaining := time.Until(deadline)
	wait := d.cfg.RestorePollInterval
	if remaining <= 0 {
		return &ErrRestoreDeadline{Wait: d.cfg.RestoreWaitTimeout, LastClass: *lastClass, Cause: *lastErr}
	}
	if wait > remaining {
		wait = remaining
	}
	if err := sleepCtx(ctx, wait); err != nil {
		return err
	}
	if !time.Now().Before(deadline) {
		return &ErrRestoreDeadline{Wait: d.cfg.RestoreWaitTimeout, LastClass: *lastClass, Cause: *lastErr}
	}
	return nil
}

// sleepCtx sleeps dur, aborting on ctx cancellation.
func sleepCtx(ctx context.Context, dur time.Duration) error {
	if dur <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(dur)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// summariseVLANState renders a compact state digest for error text.
func summariseVLANState(s model.VLANState) string {
	ids := make([]int, 0, len(s.VLANs))
	for vid := range s.VLANs {
		ids = append(ids, vid)
	}
	sort.Ints(ids)
	var parts []string
	for _, vid := range ids {
		ports := make([]string, 0, s.PortCount)
		for port := 1; port <= s.PortCount; port++ {
			m, ok := s.VLANs[vid].Ports[port]
			if !ok {
				m = model.PortMembershipIgnored
			}
			ports = append(ports, fmt.Sprintf("%d:%s", port, m))
		}
		parts = append(parts, fmt.Sprintf("vlan%d{%s}", vid, strings.Join(ports, ",")))
	}
	pvids := make([]string, 0, s.PortCount)
	for port := 1; port <= s.PortCount; port++ {
		pvids = append(pvids, fmt.Sprintf("%d:%d", port, s.PVIDs[port]))
	}
	return fmt.Sprintf("VLANs[%s] PVIDs[%s]", strings.Join(parts, " "), strings.Join(pvids, ","))
}
