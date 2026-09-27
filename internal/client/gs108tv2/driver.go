package gs108tv2

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/fastpath"
)

// Default operational constants. The restore window numbers match the
// bench observations on GS108Tv2 5.4.2.36 (web.go transient-window
// notes): logins refusals last about ~2 minutes, so the first
// verification attempt waits 90 s and the overall convergence budget
// is 5 minutes at a 15 s poll cadence. Reboot polling borrows the
// gs108ev3 wait-loop cadence (2 s).
const (
	DefaultTimeout             = 15 * time.Second
	DefaultRestoreWaitTimeout  = 5 * time.Minute
	DefaultRestorePollInterval = 15 * time.Second
	DefaultRestoreFirstDelay   = 90 * time.Second
	DefaultRebootWaitTimeout   = 5 * time.Minute
	DefaultRebootPollInterval  = 2 * time.Second
)

// Config configures the GS108Tv2 text-config driver.
type Config struct {
	Host     string
	Password string

	// Timeout is the per-request HTTP timeout (default 15s).
	Timeout time.Duration

	// RestoreWaitTimeout is the post-restore convergence deadline
	// (default 5m).
	RestoreWaitTimeout time.Duration

	// RestorePollInterval is the poll cadence inside the ingest window
	// (default 15s).
	RestorePollInterval time.Duration

	// RestoreFirstDelay is the sleep before the first verification
	// attempt (default 90s; covers the bulk of the ~2min ingest window
	// so most applies converge on their first attempt).
	RestoreFirstDelay time.Duration

	// RebootWaitTimeout is the post-reboot convergence deadline
	// (default 5m).
	RebootWaitTimeout time.Duration

	// RebootPollInterval is the poll cadence inside the reboot window
	// (default 2s; the reboot handshake is faster than the config
	// ingest window).
	RebootPollInterval time.Duration
}

// withDefaults fills unset (non-positive) durations.
func (c Config) withDefaults() Config {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.RestoreWaitTimeout <= 0 {
		c.RestoreWaitTimeout = DefaultRestoreWaitTimeout
	}
	if c.RestorePollInterval <= 0 {
		c.RestorePollInterval = DefaultRestorePollInterval
	}
	if c.RestoreFirstDelay <= 0 {
		c.RestoreFirstDelay = DefaultRestoreFirstDelay
	}
	if c.RebootWaitTimeout <= 0 {
		c.RebootWaitTimeout = DefaultRebootWaitTimeout
	}
	if c.RebootPollInterval <= 0 {
		c.RebootPollInterval = DefaultRebootPollInterval
	}
	return c
}

// Driver speaks GS108Tv2 VLAN state over the emweb text-config
// channel. It is safe for sequential use; the emweb SID is bound to
// the connection that created it, so every logical operation works on
// one session and the wait loop always builds FRESH sessions per poll.
type Driver struct {
	cfg Config

	mu      sync.Mutex
	session *fastpath.WebSession
}

// New builds a driver. Unset durations get their defaults.
func New(cfg Config) *Driver {
	return &Driver{cfg: cfg.withDefaults()}
}

// Login establishes a fresh emweb session. emweb binds the SID to the
// TCP connection that created it, so each call builds a brand-new
// session; there is no session reuse across calls beyond the client's
// keep-alive pool inside the fastpath WebSession.
func (d *Driver) Login(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := fastpath.WebLogin(d.cfg.Host, d.cfg.Password, d.cfg.Timeout)
	if err != nil {
		return fmt.Errorf("gs108tv2: login %s: %w", d.cfg.Host, err)
	}
	d.mu.Lock()
	d.session = s
	d.mu.Unlock()
	return nil
}

// Logout drops the driver's cached session handle. emweb exposes no
// logout endpoint worth calling; the session dies with the server-side
// idle timeout, and the next operation opens a fresh one.
func (d *Driver) Logout(ctx context.Context) error {
	d.mu.Lock()
	d.session = nil
	d.mu.Unlock()
	return ctx.Err()
}

// session returns the live session or nil.
func (d *Driver) sessionHandle() *fastpath.WebSession {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.session
}

// ensureSession logs in when no session is cached.
func (d *Driver) ensureSession(ctx context.Context) error {
	if d.sessionHandle() == nil {
		return d.Login(ctx)
	}
	return ctx.Err()
}

// SaveStartupConfig fetches the current startup-config bytes over a
// session. NO CACHING: every call performs its own arming GET + file
// GET sequence, so the caller always sees the switch's live staging
// state (two resources share this one file; a cached byte copy would
// silently revert the other resource's staging).
func (d *Driver) SaveStartupConfig(ctx context.Context) ([]byte, error) {
	if err := d.ensureSession(ctx); err != nil {
		return nil, err
	}
	raw, err := d.sessionHandle().SaveConfig()
	if err == nil {
		return raw, nil
	}
	// The connection-bound session may have died as a whole (fastpath
	// SaveConfig already self-heals its own stale-SID 404s by
	// re-login, this covers the fully-dead session case). A second
	// failure during the post-restore ingest window stays an error:
	// reads are not expected inside the window and the apply wait loop
	// does its own classification.
	if lerr := d.Login(ctx); lerr != nil {
		return nil, fmt.Errorf("gs108tv2: save startup-config: %v (re-login: %w)", err, lerr)
	}
	raw, err = d.sessionHandle().SaveConfig()
	if err != nil {
		return nil, fmt.Errorf("gs108tv2: save startup-config after re-login: %w", err)
	}
	return raw, nil
}

// Fingerprint is the uptime-canonical SHA-256 identity of the live
// startup-config: two reads that differ only in the "!System Up Time"
// stamp fingerprint identically.
func (d *Driver) Fingerprint(ctx context.Context) (string, error) {
	raw, err := d.SaveStartupConfig(ctx)
	if err != nil {
		return "", err
	}
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		return "", fmt.Errorf("gs108tv2: fingerprint: %w", err)
	}
	return tc.Fingerprint(), nil
}
