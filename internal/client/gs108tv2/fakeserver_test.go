package gs108tv2

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Stateful fake emweb switch, test-only. Mirrors the wire shape the
// real GS108Tv2 emitter serves (see internal/fastpath/web_test.go for
// the hand-rolled protocol expectations):
//
//   - POST /base/main_login.html  → SID cookie on correct password
//   - GET  /base/system/http_file_upload.html (arming GET)
//   - GET  /filesystem/startup-config → verbatim current stored bytes
//   - POST /base/system/http_file_download.html (multipart restore)
//
// Transient knobs model the post-restore ingest window and are only
// ARMED once a restore has landed (that is when the window exists on
// the real switch):
//   - RefuseLogins: the next N logins after the restore are refused
//     with a bare 404 (real switch refuses outright in the window).
//   - MangleFetches: the first M config fetches after the restore come
//     back with a corrupted first line ("!x4e47…" for "0x4e47…").
//
// newFakeSwitchServer skips (sandbox convention, like fastpath
// web_test.go) when loopback TCP is denied.
// ---------------------------------------------------------------------------

type fakeSwitch struct {
	t *testing.T

	mu            sync.Mutex
	password      string
	config        []byte
	sessions      map[string]bool
	loginSeq      int
	refuseLogins  int // armed after restore: refuse this many logins
	mangleFetches int // armed after restore: mangle this many file GETs
	restores      int
	uploads       [][]byte // recorded upload payloads (post-mutation storage)
	mangleServed  int
	refuseServed  int

	// restampUptime rewrites the !System Up Time line on every fetch
	// like the live switch's wall-clock stamping.
	restampUptime bool
	restampTick   int

	// mutateOnStore transforms uploads before storing them (canonical
	// divergence / drift knobs).
	mutateOnStore func([]byte) []byte

	// Reboot knobs: on a POST to the injected RebootEndpoint
	// (armReboot sets them), the fake wipes all sessions (fresh logins
	// needed; SID binding is connection-bound anyway), optionally
	// refuses the first N fresh logins (switch-down simulation), and
	// optionally resets the stamp to a LOWER up time or swaps the
	// stored config (file survival / drift knobs).
	rebootCount        int
	rebootRefuseLogins int
	rebootUptimeReset  bool
	rebootSwapConfig   []byte
}

// armReboot arms the reboot behavior set.
func (f *fakeSwitch) armReboot(refuseLogins int, uptimeReset bool, swap []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rebootRefuseLogins, f.rebootUptimeReset, f.rebootSwapConfig = refuseLogins, uptimeReset, append([]byte(nil), swap...)
}

func (f *fakeSwitch) rebootStats() (rebootCount, refuseServed int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rebootCount, f.rebootRefuseLogins
}

// windowArmed gates the transient knobs: a restore or a reboot opens
// the post-mutation window on the real switch.
func (f *fakeSwitch) windowArmed() bool {
	return f.restores > 0 || f.rebootCount > 0
}

func newFakeSwitch(t *testing.T, password string, initial []byte) *fakeSwitch {
	return &fakeSwitch{
		t:        t,
		password: password,
		config:   append([]byte(nil), initial...),
		sessions: map[string]bool{},
	}
}

// setRestamp flips the wall-clock restamping mid-test.
func (f *fakeSwitch) setRestamp(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restampUptime = v
}

// armWindow sets the transient knobs; they only take effect for
// requests after the first restore (the window follows a restore).
func (f *fakeSwitch) armWindow(refuseLogins, mangleFetches int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuseLogins, f.mangleFetches = refuseLogins, mangleFetches
}

func (f *fakeSwitch) storedConfig() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.config...)
}

func (f *fakeSwitch) recordedUploads() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.uploads))
	for i, u := range f.uploads {
		out[i] = append([]byte(nil), u...)
	}
	return out
}

func (f *fakeSwitch) counters() (logins, refuses, mangles, restores int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loginSeq, f.refuseServed, f.mangleServed, f.restores
}

func (f *fakeSwitch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if RebootEndpoint != "" && r.URL.Path == RebootEndpoint && r.Method == http.MethodPost {
		f.handleReboot(w, r)
		return
	}
	switch r.URL.Path {
	case "/base/main_login.html":
		f.handleLogin(w, r)
	case "/base/system/http_file_upload.html":
		if !f.authed(r) {
			bare404(w)
			return
		}
		fmt.Fprint(w, "<html>upload page</html>")
	case "/filesystem/startup-config":
		if !f.authed(r) {
			bare404(w)
			return
		}
		f.handleConfigGet(w)
	case "/base/system/http_file_download.html":
		f.handleRestore(w, r)
	default:
		bare404(w)
	}
}

// handleReboot implements the fake's own reboot contract: authenticated
// POST → sessions wiped (fresh logins needed), optional refuse budget
// armed, optional up-time reset at next fetch, optional config swap
// (file-survival test knob).
func (f *fakeSwitch) handleReboot(w http.ResponseWriter, r *http.Request) {
	if !f.authed(r) {
		bare404(w)
		return
	}
	f.rebootCount++
	f.sessions = map[string]bool{}
	if f.rebootRefuseLogins > 0 {
		f.refuseLogins = f.rebootRefuseLogins // consumed by handleLogin
	}
	if len(f.rebootSwapConfig) > 0 {
		f.config = append([]byte(nil), f.rebootSwapConfig...)
	}
	if f.rebootUptimeReset {
		body := string(f.config)
		body = strings.Replace(body, "0 days 0 hrs 5 mins 36 secs", "0 days 0 hrs 0 mins 3 secs", 1)
		f.config = []byte(body)
	}
	fmt.Fprint(w, `<html>rebooting</html>`)
}

func (f *fakeSwitch) handleLogin(w http.ResponseWriter, r *http.Request) {
	f.loginSeq++
	// Ingest/reboot window: fresh logins refused outright.
	if f.windowArmed() && f.refuseLogins > 0 {
		f.refuseLogins--
		f.refuseServed++
		bare404(w)
		return
	}
	if got := r.PostFormValue("pwd"); got != f.password {
		fmt.Fprint(w, `<INPUT type="hidden" name="err_flag" VALUE="1">`+
			`<INPUT type="hidden" name="err_msg" VALUE="Incorrect password!">`)
		return
	}
	token := fmt.Sprintf("sid%d", len(f.sessions)+1)
	f.sessions[token] = true
	http.SetCookie(w, &http.Cookie{Name: "SID", Value: token, Path: "/"})
	fmt.Fprint(w, "<html>ok</html>")
}

func (f *fakeSwitch) authed(r *http.Request) bool {
	c, err := r.Cookie("SID")
	return err == nil && f.sessions[c.Value]
}

const mangleFrom = "0x4e470x010x00"
const mangleTo = "!x4e470x010x00"

func (f *fakeSwitch) handleConfigGet(w http.ResponseWriter) {
	body := f.config
	if f.windowArmed() && f.mangleFetches > 0 {
		f.mangleFetches--
		f.mangleServed++
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, strings.Replace(string(body), mangleFrom, mangleTo, 1))
		return
	}
	if f.restampUptime {
		body = restampUptime(body, f.restampTick)
		f.restampTick++
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(body)
}

func (f *fakeSwitch) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !f.authed(r) {
		bare404(w)
		return
	}
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		bare404(w)
		return
	}
	file, _, err := r.FormFile(".filename_handle")
	if err != nil {
		bare404(w)
		return
	}
	content, rerr := io.ReadAll(file)
	file.Close()
	if rerr != nil {
		f.t.Errorf("fake: reading upload: %v", rerr)
		bare404(w)
		return
	}
	if f.mutateOnStore != nil {
		content = f.mutateOnStore(content)
	}
	f.config = append([]byte(nil), content...)
	f.uploads = append(f.uploads, append([]byte(nil), content...))
	f.restores++
	fmt.Fprint(w, `<INPUT type="hidden" name="download_status" VALUE="Success">`+
		`<INPUT type="hidden" name="err_flag" VALUE="0">`+
		`<INPUT type="hidden" name="err_msg" VALUE="">`)
}

// restampUptime rewrites the up-time annotation like the switch's wall
// clock: same line shape, different value per tick.
func restampUptime(raw []byte, tick int) []byte {
	needle := "0 days 0 hrs 5 mins 36 secs"
	replacement := fmt.Sprintf("0 days 0 hrs %d mins %d secs", tick, tick*7)
	return []byte(strings.Replace(string(raw), needle, replacement, 1))
}

func bare404(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, "404 Not Found")
}

func (f *fakeSwitch) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	conn, err := net.DialTimeout("tcp", srv.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Skipf("sandbox denies loopback TCP: %v", err)
	}
	_ = conn.Close()
	return srv
}

// fastDriverConfig returns a Config tuned for fake-server tests.
func fastDriverConfig(t *testing.T, srvURL string) Config {
	t.Helper()
	return Config{
		Host:                srvURL,
		Password:            "sekrit",
		Timeout:             2 * time.Second,
		RestoreWaitTimeout:  3 * time.Second,
		RestorePollInterval: 5 * time.Millisecond,
		RestoreFirstDelay:   5 * time.Millisecond,
	}
}
