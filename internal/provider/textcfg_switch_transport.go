package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/client/gs108tv2"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// ---------------------------------------------------------------------------
// textcfgSwitchTransport: the composite gs108tv2 implementation of
// switchTransport. It mirrors nsdp_switch_transport.go's shape: it holds
// no session state of its own; locking, pacing, and driver/NSDP client
// caching live in withTextcfgSwitchTransport / withSwitchTransport,
// shared with every other transport branch.
//
// Routing (milestone 3): for provider model gs108tv2, the vlan_state
// resource family runs entirely over the FASTPATH text-config channel
// (internal/client/gs108tv2: save startup-config → mutate → restore →
// structural verify). NSDP v1 stays on for IDENTITY only: the serial
// number, switch name, and firmware facts are readable only over the
// NSDP v1 flat scalar set, so when the provider agent_mac is configured
// the composite's ReadSwitchFacts delegates to an nsdpSwitchTransport
// identity adapter (the same nsdpClient cache everything else uses).
// Without agent_mac, facts come from the config file itself — where the
// serial is simply not representable (documented channel limit).
//
// STAGED SEMANTICS (live-measured, GS108Tv2 5.4.2.36): the restore
// writes the startup-config only and does NOT reboot; the running
// config is unchanged until the next boot. Running VLAN state is
// UNREADABLE on this model, so every Read/plan/drift comparison here —
// and in the resource layer's post-apply verification — is against the
// STARTUP config. Apply ends with NO reboot: the vlan_state resource
// surfaces the staged semantics as a warning diagnostic.
// ---------------------------------------------------------------------------

// textcfgDriver is the surface of the gs108tv2 text-config driver the
// composite transport calls. It exists so provider tests can stub the
// whole transport without sockets. The production instance is the
// concrete *gs108tv2.Driver (newGS108tv2TextcfgDriver) — the driver
// package owns ALL reads and writes of the two managed namespaces, so
// plan/apply state and the composite must never re-implement a decode
// (see internal/client/gs108tv2/read.go + codec.go).
type textcfgDriver interface {
	// Login establishes a fresh emweb session.
	Login(ctx context.Context) error

	// Logout drops the cached session handle (cache invalidation).
	Logout(ctx context.Context) error

	// ReadSwitchFacts returns the fastpath facts extractable from the
	// startup config (serial "" — the text channel cannot read it).
	ReadSwitchFacts(ctx context.Context) (model.SwitchFacts, error)

	// ReadVLANState decodes the STARTUP config into the VLAN state
	// (fresh fetch — no caching — and fail-closed decode).
	ReadVLANState(ctx context.Context) (model.VLANState, error)

	// ApplyVLANState stages the desired state into the startup-config
	// (save → mutate → restore → structural verify; NO reboot).
	ApplyVLANState(ctx context.Context, desired model.VLANState) (gs108tv2.ApplyOutcome, error)

	// ReadPortSettings decodes the STARTUP config's per-port admin
	// settings (interface 0/1..0/8 bodies), all 8 ports.
	ReadPortSettings(ctx context.Context) (map[int]gs108tv2.PortSettings, error)

	// ApplyPortSettings stages the desired per-port admin settings via
	// the same restore → converge flow as the VLAN codec.
	ApplyPortSettings(ctx context.Context, desired map[int]gs108tv2.PortSettings) (gs108tv2.ApplyOutcome, error)

	// RebootAndWait reboots the switch (endpoint-sentinel-guarded) and
	// waits for the staged startup-config to survive it.
	RebootAndWait(ctx context.Context) (gs108tv2.RebootOutcome, error)

	// Fingerprint is the uptime-canonical SHA-256 of the live
	// startup-config: two reads differing only in the "!System Up Time"
	// stamp fingerprint identically.
	Fingerprint(ctx context.Context) (string, error)
}

// newGS108tv2TextcfgDriver builds the production textcfgDriver for the
// gs108tv2 family: the concrete driver satisfies the whole surface.
func newGS108tv2TextcfgDriver(cfg gs108tv2.Config) textcfgDriver {
	return gs108tv2.New(cfg)
}

// Compile-time wiring check: the concrete driver must define the whole
// composite surface.
var _ textcfgDriver = (*gs108tv2.Driver)(nil)

// textcfgSwitchTransport implements switchTransport for model gs108tv2.
type textcfgSwitchTransport struct {
	// driver is the text-config channel (reads + staged apply).
	driver textcfgDriver

	// identity is the NSDP v1 identity adapter for ReadSwitchFacts, or
	// nil when agent_mac is unconfigured (facts fall back to the
	// fastpath/config-file read, whose serial is "" by channel limit).
	identity switchInfoTransport

	// resourceID is the "<model>@<canonical host>" ID, computed once by
	// withTextcfgSwitchTransport (same convention as the HTTP branch).
	resourceID string
}

var _ switchTransport = textcfgSwitchTransport{}

func (t textcfgSwitchTransport) ResourceID() string {
	return t.resourceID
}

// ReadSwitchFacts follows the serial-pin policy: with agent_mac
// configured, identity facts come from NSDP v1 (serial, switch name,
// and firmware as reported by the switch; MAC from the configured
// agent_mac) — the expected_serial_number pin is meaningless without
// it. Without agent_mac, facts come from the config file itself, where
// the MAC (spanning-tree configuration name) and the model/firmware
// annotations are readable but the serial is NOT — documented channel
// limit, NOT an error.
func (t textcfgSwitchTransport) ReadSwitchFacts(ctx context.Context) (model.SwitchFacts, error) {
	if t.identity != nil {
		return t.identity.ReadSwitchFacts(ctx)
	}
	return t.driver.ReadSwitchFacts(ctx)
}

func (t textcfgSwitchTransport) ReadVLANState(ctx context.Context) (model.VLANState, error) {
	return t.driver.ReadVLANState(ctx)
}

// ApplyVLANState performs the staged apply and discards the outcome
// detail — switchTransport's interface shape. Callers that want the
// staged/canonical-divergence diagnostics use ApplyVLANStateDetailed.
func (t textcfgSwitchTransport) ApplyVLANState(ctx context.Context, desired model.VLANState) error {
	_, err := t.ApplyVLANStateDetailed(ctx, desired)
	return err
}

// ApplyVLANStateDetailed performs the staged apply and reports the
// driver's ApplyOutcome: Staged (structural verify passed after the
// transient ingest window) and CanonicalDiverged (the switch
// re-serialized the file through its own normalizer — success plus a
// warning signal, never a failure). The error carries the driver's
// typed failures (ErrRestoreRejected, ErrRestoreDeadline,
// ErrDriftDetected, ErrGrammarLine, ErrMissingSection,
// ErrInvalidDesiredState) unchanged.
func (t textcfgSwitchTransport) ApplyVLANStateDetailed(ctx context.Context, desired model.VLANState) (gs108tv2.ApplyOutcome, error) {
	return t.driver.ApplyVLANState(ctx, desired)
}

// ---------------------------------------------------------------------------
// providerData plumbing: driver cache + transport construction.
// ---------------------------------------------------------------------------

// cachedTextcfgDriver is the text-config counterpart of
// cachedDriverSession: one driver instance per host+password
// fingerprint, reused across operations (the driver self-heals dead
// emweb sessions with fresh logins, so cross-operation reuse is safe).
type cachedTextcfgDriver struct {
	fingerprint string
	driver      textcfgDriver
}

// textcfgDriverForConfig returns the cached text-config driver for the
// current config, building it on first use (lazily, mirroring
// driverForConfig). Tests stub the whole construction by setting
// data.textcfgFactory.
func (d *providerData) textcfgDriverForConfig(ctx context.Context) (textcfgDriver, error) {
	if d == nil {
		return nil, fmt.Errorf("provider is not configured")
	}

	fingerprint := d.textcfgConfigFingerprint()
	if d.cachedTextcfg != nil && d.cachedTextcfg.fingerprint == fingerprint && d.cachedTextcfg.driver != nil {
		return d.cachedTextcfg.driver, nil
	}

	d.invalidateCachedTextcfgDriver(ctx)

	if d.textcfgFactory != nil {
		driver, err := d.textcfgFactory(textcfgDriverRequest{
			Host:     strings.TrimSpace(d.config.Host),
			Password: d.config.Password,
			Timeout:  d.config.RequestTimeout,
		})
		if err != nil {
			return nil, err
		}
		d.cachedTextcfg = &cachedTextcfgDriver{fingerprint: fingerprint, driver: driver}
		return driver, nil
	}

	timeout := time.Duration(d.config.RequestTimeout) * time.Second
	if d.config.RequestTimeout <= 0 {
		timeout = 0 // gs108tv2.New fills its own default (15s)
	}

	driver := newGS108tv2TextcfgDriver(gs108tv2.Config{
		Host:     strings.TrimSpace(d.config.Host),
		Password: d.config.Password,
		Timeout:  timeout,
	})

	d.cachedTextcfg = &cachedTextcfgDriver{
		fingerprint: fingerprint,
		driver:      driver,
	}

	return driver, nil
}

// textcfgDriverRequest carries the provider-side driver shape to the
// (test) factory, decoupled from gs108tv2.Config so a stub factory
// needs no socket-bound config knowledge. Timeout is in whole seconds.
type textcfgDriverRequest struct {
	Host     string
	Password string
	Timeout  int64
}

// invalidateCachedTextcfgDriver drops the cached text-config driver,
// logging the emweb session out first (best effort).
func (d *providerData) invalidateCachedTextcfgDriver(ctx context.Context) {
	if d == nil || d.cachedTextcfg == nil {
		return
	}
	if d.cachedTextcfg.driver != nil {
		_ = d.cachedTextcfg.driver.Logout(ctx)
	}
	d.cachedTextcfg = nil
}

// textcfgConfigFingerprint tracks the fields that shape the emweb
// session: host and password. The restore-wait tuning knobs have no
// provider surface yet (driver defaults; the measured numbers are
// pinned in internal/client/gs108tv2), so nothing else belongs here.
func (d *providerData) textcfgConfigFingerprint() string {
	if d == nil {
		return ""
	}

	return strings.Join([]string{
		strings.TrimSpace(d.config.Host),
		strings.TrimSpace(d.config.Password),
	}, "\x00")
}

// isGS108Tv2Model reports whether the provider config binds the
// FASTPATH text-config family.
func (d *providerData) isGS108Tv2Model() bool {
	return d != nil && strings.EqualFold(strings.TrimSpace(d.config.Model), client.ModelGS108Tv2)
}

// ---------------------------------------------------------------------------
// Provider-port settings / reboot seams on the composite (the resources
// type-assert for these like they do for detailedVLANStateApplier).
// ---------------------------------------------------------------------------

// portSettingsTransport is the port_config READ seam.
type portSettingsTransport interface {
	ReadPortSettings(ctx context.Context) (map[int]gs108tv2.PortSettings, error)
}

// detailedPortSettingsApplier is the port_config DETAILED apply seam
// (mirror of detailedVLANStateApplier): it surfaces the staged-apply
// outcome for the staged/canonical-divergence diagnostics.
type detailedPortSettingsApplier interface {
	ApplyPortSettingsDetailed(ctx context.Context, desired map[int]gs108tv2.PortSettings) (gs108tv2.ApplyOutcome, error)
}

// textcfgRebooter is the reboot_to_apply seam (gs108tv2 only): stage
// first via the detailed applyers, then reboot and wait for the switch
// to come back with the staged startup-config intact.
type textcfgRebooter interface {
	Reboot(ctx context.Context) (gs108tv2.RebootOutcome, error)
}

func (t textcfgSwitchTransport) ReadPortSettings(ctx context.Context) (map[int]gs108tv2.PortSettings, error) {
	return t.driver.ReadPortSettings(ctx)
}

// ApplyPortSettings performs the staged port apply and discards the
// outcome detail (plain-seam shape).
func (t textcfgSwitchTransport) ApplyPortSettings(ctx context.Context, desired map[int]gs108tv2.PortSettings) error {
	_, err := t.ApplyPortSettingsDetailed(ctx, desired)
	return err
}

// ApplyPortSettingsDetailed performs the staged port apply and reports
// the driver's ApplyOutcome (Staged / CanonicalDiverged), with the
// driver's typed failures (ErrUnsupportedAttribute, ErrRestoreRejected,
// ErrRestoreDeadline, ErrDriftDetected, …) carried unchanged.
func (t textcfgSwitchTransport) ApplyPortSettingsDetailed(ctx context.Context, desired map[int]gs108tv2.PortSettings) (gs108tv2.ApplyOutcome, error) {
	return t.driver.ApplyPortSettings(ctx, desired)
}

// Reboot reboots the switch and waits for it to come back with the
// staged startup-config intact (the endpoint-sentinel guard fires
// before any HTTP traffic). The resource layer preflights the sentinel
// BEFORE staging — this is the second, defensive layer.
func (t textcfgSwitchTransport) Reboot(ctx context.Context) (gs108tv2.RebootOutcome, error) {
	return t.driver.RebootAndWait(ctx)
}

// ---------------------------------------------------------------------------
// Routing (milestone 3): the gs108tv2 branches of the transport seams.
// ---------------------------------------------------------------------------

// withTextcfgSwitchTransport runs fn with the composite text-config
// transport, under the SAME device lock and pacing every other
// transport branch uses. When agent_mac is configured the composite's
// identity adapter shares the cached NSDP client (NSDP v1) so the
// serial pin works over the same socket lifecycle as everything else.
func withTextcfgSwitchTransport(ctx context.Context, data *providerData, fn func(switchTransport) error) error {
	if data == nil {
		return fmt.Errorf("provider is not configured")
	}

	if strings.TrimSpace(data.config.Host) == "" {
		return fmt.Errorf(
			"model %s config-channel operations (VLAN state, port configuration, config backup) require the provider attribute host: the text-config channel transfers over the switch's web UI (emweb), which needs the switch's routable address",
			client.ModelGS108Tv2,
		)
	}

	key := data.deviceLockKey()
	mutex := mutexForDevice(key)
	mutex.Lock()
	defer mutex.Unlock()

	if err := waitForDeviceOperation(ctx, key, data.config.RequestSpacing); err != nil {
		return err
	}

	driver, err := data.textcfgDriverForConfig(ctx)
	if err != nil {
		return err
	}

	transport := textcfgSwitchTransport{
		driver:     driver,
		resourceID: data.resourceID(), // gs108tv2@<canonical host>
	}
	if data.agentMAC != "" {
		// The serial pin rides NSDP v1 identity; the composite's
		// identity adapter shares the cached NSDP client. This runs
		// with the same device lock withSwitchTransport holds, so no
		// second pacing round is taken here.
		nsdp, err := data.nsdpClient(ctx)
		if err != nil {
			return fmt.Errorf("build NSDP v1 identity client for the %s serial pin: %w", client.ModelGS108Tv2, err)
		}
		transport.identity = nsdpSwitchTransport{client: nsdp, agentMAC: data.agentMAC}
	}

	if err := fn(transport); err != nil {
		// The gs108tv2 driver self-heals dead emweb sessions with
		// fresh logins (SaveStartupConfig), so there is no
		// ShouldInvalidateSession hook here.
		return err
	}
	return nil
}

// withSwitchIdentityTransport routes ONLY the identity seam
// (netgear_plus_switch data source): stable identity/firmware facts.
// The callback keeps the full switchTransport shape because every
// transport handed through here IS one (ResourceID is part of the
// resolved identity convention); the narrow semantic is enforced by
// which transport implementation reaches the callback, not by the
// static interface.
//
// gs108tv2 handling (milestone 3): config-channel operations (VLAN
// state, config backup) work with host only, but identity (switch
// name, MAC, serial) is NSDP v1's job. With agent_mac this keeps
// today's NSDP-v1-identity behavior; without agent_mac the data source
// refuses exactly as before — switch name and serial are NSDP-only,
// and the identity requirements must not weaken.
func withSwitchIdentityTransport(ctx context.Context, data *providerData, fn func(switchTransport) error) error {
	if data == nil {
		return fmt.Errorf("provider is not configured")
	}

	if !data.isGS108Tv2Model() {
		return withSwitchTransport(ctx, data, func(transport switchTransport) error {
			return fn(transport)
		})
	}

	if data.agentMAC == "" {
		return &providerOperationError{
			summary: "Switch identity requires agent_mac for model gs108tv2",
			detail: fmt.Sprintf(
				"Model %s serves `netgear_plus_vlan_state` and `netgear_plus_switch_config` over its text-config channel via the provider `host`, but this data source's identity facts (switch name, MAC, serial number) are only readable over NSDP v1. Add the provider attribute agent_mac — the value is also the MAC the switch carries in its config's `spanning-tree configuration name` line (see `netgear_plus_switch_config`) — to read identity for this model.",
				client.ModelGS108Tv2,
			),
		}
	}

	// gs108tv2 identity over NSDP v1: unchanged from the pre-milestone
	// NSDP branch (identity GETs are the verified v1 surface).
	return withNSDPClient(ctx, data, func(client nsdpClient) error {
		return fn(nsdpSwitchTransport{
			client:     client,
			agentMAC:   data.agentMAC,
			resourceID: portConfigResourceID(data),
		})
	})
}
