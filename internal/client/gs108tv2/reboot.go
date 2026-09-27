package gs108tv2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/fastpath"
)

// ---------------------------------------------------------------------------
// RebootAndWait — endpoint sentinel until phase 0b pins it live.
//
// RebootEndpoint is the emweb URL that triggers a reboot. It is
// UNPINNED by default (empty): phase 0b (live firmware probe / Ghidra
// pass over switchdrvr.bin/emweb) must set the real path AND the real
// POST form shape before this driver will ever reboot a real switch.
// Tests inject a fake path. The POST form below is PROVISIONAL by the
// same token: it mirrors the login POST shape (pwd + image-submit
// coordinates) because that is the shape this driver can already
// speak; the fake defines its own contract.
// ---------------------------------------------------------------------------

// RebootEndpoint is the package-level sentinel: empty means "refuse
// to reboot" (ErrRebootUnavailable), keeping a misconfigured or
// half-pinned deployment from bricking switches. Phase 0b sets it.
var RebootEndpoint = ""

// RebootOutcome reports the guarded reboot result.
type RebootOutcome struct {
	Rebooted    bool
	UptimeReset bool
	Fingerprint string // canonical fingerprint of the startup-config after reboot
}

// ErrRebootUnavailable is the typed refusal when the reboot endpoint
// is not pinned yet. No HTTP is attempted.
type ErrRebootUnavailable struct {
	Detail string
}

func (e *ErrRebootUnavailable) Error() string {
	return "gs108tv2: reboot refused: " + e.Detail
}

// ErrRebootDeadline is the typed end-state of a reboot window that
// never converged within Config.RebootWaitTimeout.
type ErrRebootDeadline struct {
	Wait      time.Duration
	LastClass string // "conn" | "auth" | "fetch" | "parse" | "uptime"
	Cause     error
}

func (e *ErrRebootDeadline) Error() string {
	note := ""
	switch e.LastClass {
	case "conn":
		note = "; connection refusals during the reboot window are expected (drop a few polls)"
	case "auth":
		note = "; post-reboot login refusals are expected while the switch boots"
	case "uptime":
		note = "; the switch answered but its up-time stamp never went below the baseline — the reboot POST may not have taken effect"
	}
	return fmt.Sprintf("gs108tv2: switch did not come back within %s (last failure class %q): %v%s",
		e.Wait, e.LastClass, e.Cause, note)
}

func (e *ErrRebootDeadline) Unwrap() error { return e.Cause }

// ErrRebootConfigDrift is the typed verification failure when the
// canonical startup-config fingerprint changed across the reboot: the
// staged bytes are the source of truth and must survive.
type ErrRebootConfigDrift struct {
	Before, After string
}

func (e *ErrRebootConfigDrift) Error() string {
	return fmt.Sprintf("gs108tv2: startup-config changed across reboot (before %s, after %s): staged content must survive a reboot",
		e.Before, e.After)
}

// RebootAndWait reboots the switch and waits for it to come back with
// the startup-config intact.
//
// Flow:
//  1. RebootEndpoint == "" → ErrRebootUnavailable (zero HTTP traffic);
//  2. baseline: fresh SaveStartupConfig, parse the "!System Up Time"
//     annotation into total seconds, record the canonical Fingerprint;
//  3. POST RebootEndpoint (PROVISIONAL form shape — see file banner);
//  4. poll with fresh Logins per attempt (connection-bound SIDs):
//     connection-refused/timeout and auth-class refusals inside the
//     reboot window are expected and keep polling (same discipline as
//     the restore wait loop); deadline → typed ErrRebootDeadline;
//  5. Login OK → fresh SaveStartupConfig: the up-time annotation must
//     be LOWER than the baseline (the switch really rebooted) and the
//     canonical fingerprint must equal the baseline — the staged
//     startup-config is the source of truth; changing across a reboot
//     is a typed error (ErrRebootConfigDrift);
//  6. return RebootOutcome{Rebooted: true, UptimeReset, Fingerprint}.
func (d *Driver) RebootAndWait(ctx context.Context) (RebootOutcome, error) {
	if strings.TrimSpace(RebootEndpoint) == "" {
		return RebootOutcome{}, &ErrRebootUnavailable{
			Detail: "reboot endpoint not yet pinned for FASTPATH 5.4.2.36; refusing to reboot — pin it in phase 0b before enabling reboot_to_apply",
		}
	}
	if err := ctx.Err(); err != nil {
		return RebootOutcome{}, err
	}

	raw, err := d.SaveStartupConfig(ctx)
	if err != nil {
		return RebootOutcome{}, err
	}
	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		return RebootOutcome{}, fmt.Errorf("gs108tv2: reboot: baseline parse: %w", err)
	}
	baselineUptime, ok := uptimeSecondsFromConfig(tc)
	if !ok {
		return RebootOutcome{}, fmt.Errorf("gs108tv2: reboot: startup-config carries no readable \"!System Up Time\" annotation; refusing to reboot (the reset cannot be verified)")
	}
	baselineFingerprint := tc.Fingerprint()

	if err := d.postReboot(ctx); err != nil {
		return RebootOutcome{}, err
	}

	deadline := time.Now().Add(d.cfg.RebootWaitTimeout)
	lastClass, lastErr := "", error(nil)

	for {
		if err := ctx.Err(); err != nil {
			return RebootOutcome{}, err
		}

		// Fresh login per attempt; connection failures and auth
		// refusals inside the window are expected (either class keeps
		// polling — the deadline error reports the final class).
		if lerr := d.Login(ctx); lerr != nil {
			lastClass, lastErr = "conn", lerr
			var authErr *fastpath.ErrWebAuth
			if errors.As(lerr, &authErr) {
				lastClass = "auth"
			}
			if werr := d.rebootSleep(ctx, deadline, &lastClass, &lastErr); werr != nil {
				return RebootOutcome{}, werr
			}
			continue
		}

		raw, serr := d.sessionHandle().SaveConfig()
		if serr != nil {
			lastClass, lastErr = "fetch", serr
			if werr := d.rebootSleep(ctx, deadline, &lastClass, &lastErr); werr != nil {
				return RebootOutcome{}, werr
			}
			continue
		}
		newTC, perr := fastpath.ParseTextConfig(raw)
		if perr != nil {
			lastClass, lastErr = "parse", perr
			if werr := d.rebootSleep(ctx, deadline, &lastClass, &lastErr); werr != nil {
				return RebootOutcome{}, werr
			}
			continue
		}

		newUptime, uok := uptimeSecondsFromConfig(newTC)
		newFingerprint := newTC.Fingerprint()
		if !uok {
			lastClass, lastErr = "uptime", errors.New("up-time annotation unreadable in the re-fetched config")
			if werr := d.rebootSleep(ctx, deadline, &lastClass, &lastErr); werr != nil {
				return RebootOutcome{}, werr
			}
			continue
		}
		if newUptime >= baselineUptime {
			// The switch is serving a valid config but the up-time
			// stamp never went below baseline: the reboot POST likely
			// did not take effect. Poll on; the deadline error
			// surfaces as class "uptime".
			lastClass, lastErr = "uptime", fmt.Errorf("up-time %ds was not below the baseline %ds", newUptime, baselineUptime)
			if werr := d.rebootSleep(ctx, deadline, &lastClass, &lastErr); werr != nil {
				return RebootOutcome{}, werr
			}
			continue
		}

		// Up time reset — the staged config must have survived it.
		if newFingerprint != baselineFingerprint {
			return RebootOutcome{}, &ErrRebootConfigDrift{
				Before: baselineFingerprint,
				After:  newFingerprint,
			}
		}
		return RebootOutcome{
			Rebooted:    true,
			UptimeReset: true,
			Fingerprint: newFingerprint,
		}, nil
	}
}

// rebootSleep sleeps one poll interval within the reboot budget; past
// it returns ErrRebootDeadline with the live failure context.
func (d *Driver) rebootSleep(ctx context.Context, deadline time.Time, lastClass *string, lastErr *error) error {
	remaining := time.Until(deadline)
	wait := d.cfg.RebootPollInterval
	if remaining <= 0 {
		return &ErrRebootDeadline{Wait: d.cfg.RebootWaitTimeout, LastClass: *lastClass, Cause: *lastErr}
	}
	if wait > remaining {
		wait = remaining
	}
	if err := sleepCtx(ctx, wait); err != nil {
		return err
	}
	if !time.Now().Before(deadline) {
		return &ErrRebootDeadline{Wait: d.cfg.RebootWaitTimeout, LastClass: *lastClass, Cause: *lastErr}
	}
	return nil
}

// postReboot fires the reboot POST.
//
// PROVISIONAL (pinned live in phase 0b): internal/fastpath does not
// expose an arbitrary-POST surface on the session and its cookie jar
// is unexported, so this lane performs its own login POST (the same
// wire shape fastpath.WebLogin speaks: pwd + image-submit
// coordinates over the emweb SID cookie) and posts the reboot form
// with the fresh SID. The form shape mirrors the login POST; the real
// field set and path are phase 0b material. The test fake defines its
// own contract.
func (d *Driver) postReboot(ctx context.Context) error {
	host, err := fastpath.WebTargetHost(d.cfg.Host)
	if err != nil {
		return err
	}
	scheme := "http"
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(d.cfg.Host)), "https://") {
		scheme = "https"
	}

	client := &http.Client{
		Timeout: d.cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // emweb answers in-place
		},
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	login := url.Values{"pwd": {d.cfg.Password}, "login.x": {"5"}, "login.y": {"5"}}
	req, err := http.NewRequest(http.MethodPost, scheme+"://"+host+"/base/main_login.html", strings.NewReader(login.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("gs108tv2: reboot: login: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		return fmt.Errorf("gs108tv2: reboot: login rejected (HTTP %d)", resp.StatusCode)
	}
	sid := ""
	for _, c := range resp.Cookies() {
		if c.Name == "SID" && c.Value != "" {
			sid = c.Value
		}
	}
	if sid == "" {
		// Wrong password answers with the login page again (err_flag
		// fields, no SID cookie); report the page body for context.
		return fmt.Errorf("gs108tv2: reboot: login failed: %s", firstLines(body, 1))
	}

	boot := url.Values{"pwd": {d.cfg.Password}, "login.x": {"5"}, "login.y": {"5"}}
	req, err = http.NewRequest(http.MethodPost, scheme+"://"+host+RebootEndpoint, strings.NewReader(boot.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", "SID="+sid)
	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("gs108tv2: reboot POST failed: %w", err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("gs108tv2: reboot POST rejected (HTTP %d)", resp.StatusCode)
	}
	return nil
}

// firstLines truncates a page body to n lines for error messages.
func firstLines(body []byte, n int) string {
	s := string(body)
	for i := 0; i < n; i++ {
		if idx := strings.IndexByte(s, '\n'); idx >= 0 {
			s = s[:idx]
		} else {
			break
		}
	}
	return s
}

// --- up-time annotation parser ------------------------------------------

// uptimeSecondsFromConfig scans the config for the "!System Up Time"
// annotation and parses its value into total seconds. PROVISIONAL
// format (observed on the bench, pinned in phase 0a/0b):
//
//	!System Up Time          "0 days 0 hrs 5 mins 36 secs"
//
// Returns ok=false when the annotation is missing or unparseable.
func uptimeSecondsFromConfig(tc fastpath.TextConfig) (int, bool) {
	for _, l := range strings.Split(string(tc.Raw), "\n") {
		line := strings.TrimSpace(strings.TrimRight(l, "\r"))
		if !strings.HasPrefix(line, uptimePrefix) {
			continue
		}
		return parseUptimeSeconds(quotedValue(line))
	}
	return 0, false
}

// uptimePrefix marks the up-time annotation line (mirrors the live
// emitter's leading text; leading whitespace is trimmed before the
// comparison).
const uptimePrefix = "!System Up Time"

// parseUptimeSeconds parses "N days N hrs N mins N secs" (in any
// combination, case-insensitive on unit suffixes, optional singulars)
// into total seconds. PROVISIONAL (pinned live in phase 0a).
func parseUptimeSeconds(value string) (int, bool) {
	fields := strings.Fields(value)
	if len(fields) == 0 || len(fields)%2 != 0 {
		return 0, false
	}
	total := 0
	for i := 0; i < len(fields); i += 2 {
		n, err := strconv.Atoi(fields[i])
		if err != nil || n < 0 {
			return 0, false
		}
		unit := strings.ToLower(fields[i+1])
		secs, ok := map[string]int{
			"days": 86400, "day": 86400,
			"hrs": 3600, "hr": 3600, "hours": 3600, "hour": 3600,
			"mins": 60, "min": 60, "minutes": 60, "minute": 60,
			"secs": 1, "sec": 1, "seconds": 1, "second": 1,
		}[unit]
		if !ok {
			return 0, false
		}
		total += n * secs
	}
	return total, true
}
