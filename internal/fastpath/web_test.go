package fastpath

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testTextConfig is a minimal valid NSDP text configuration: the
// 0x4e47-prefixed magic header line plus the description/version
// annotations ValidateTextConfigHeader checks.
const testTextConfig = "0x4e470x010x00GS108Tv2            5.4.2.36            0x000000000x00000000000000\n" +
	"! The line above is the NSDP Text Configuration header. DO NOT EDIT THIS HEADER\n" +
	"!Current Configuration:\n" +
	"!\n" +
	"!System Description \"GS108Tv2\"\n" +
	"!System Software Version \"5.4.2.36\"\n" +
	"!\n" +
	"configure\n" +
	"exit\n"

// newEmwebServer starts the fake switch and skips (per the package's
// sandbox convention) when loopback TCP is denied.
func newEmwebServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	conn, err := net.DialTimeout("tcp", srv.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Skipf("sandbox denies loopback TCP: %v", err)
	}
	_ = conn.Close()
	return srv
}

func TestWebTargetHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://10.0.2.8", "10.0.2.8"},
		{"https://10.0.2.8:443", "10.0.2.8:443"},
		{"http://10.0.2.8:8080", "10.0.2.8:8080"},
		{"10.0.2.8", "10.0.2.8"},
		{"10.0.2.8:8080", "10.0.2.8:8080"},
		{"  http://switch.example  ", "switch.example"},
	}
	for _, c := range cases {
		got, err := WebTargetHost(c.in)
		if err != nil {
			t.Errorf("WebTargetHost(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("WebTargetHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := WebTargetHost("   "); err == nil {
		t.Error("WebTargetHost(whitespace) should error")
	}
}

func TestWebLoginAndSaveConfigFlow(t *testing.T) {
	var armed bool
	var sawSIDOnFile, sawSIDOnArming bool
	srv := newEmwebServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/base/main_login.html":
			if r.Method != http.MethodPost {
				t.Errorf("login method = %s, want POST", r.Method)
			}
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
				t.Errorf("login content-type = %q", ct)
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("login form: %v", err)
			}
			if got := r.PostFormValue("pwd"); got != "sekrit" {
				t.Errorf("pwd = %q, want %q", got, "sekrit")
			}
			if r.PostFormValue("login.x") == "" || r.PostFormValue("login.y") == "" {
				t.Error("login image-button coordinates missing")
			}
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "t0k3n", Path: "/"})
			io.WriteString(w, "<html>ok</html>")
		case "/base/system/http_file_upload.html":
			if r.Method != http.MethodGet {
				t.Errorf("arming method = %s, want GET", r.Method)
			}
			armed = true
			sawSIDOnArming = r.Header.Get("Cookie") == "SID=t0k3n"
			io.WriteString(w, "<html>upload page</html>")
		case "/filesystem/startup-config":
			if !armed {
				t.Error("file GET reached the server before the arming GET")
			}
			sawSIDOnFile = r.Header.Get("Cookie") == "SID=t0k3n"
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, testTextConfig)
		default:
			http.NotFound(w, r)
		}
	})

	sess, err := WebLogin(srv.URL, "sekrit", 5*time.Second)
	if err != nil {
		t.Fatalf("WebLogin: %v", err)
	}
	raw, err := sess.SaveConfig()
	if err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	if string(raw) != testTextConfig {
		t.Errorf("SaveConfig bytes drifted: %d bytes, want %d", len(raw), len(testTextConfig))
	}
	if !sawSIDOnArming || !sawSIDOnFile {
		t.Errorf("session cookie missing: arming=%v file=%v", sawSIDOnArming, sawSIDOnFile)
	}
	tc, err := ParseTextConfig(raw)
	if err != nil {
		t.Fatalf("ParseTextConfig: %v", err)
	}
	if tc.SystemDescription != "GS108Tv2" || tc.SystemSoftwareVersion != "5.4.2.36" {
		t.Errorf("parsed header fields = %q/%q", tc.SystemDescription, tc.SystemSoftwareVersion)
	}
}

func TestWebLoginWrongPassword(t *testing.T) {
	srv := newEmwebServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Re-served login page: no SID cookie, err_flag=1 filled.
		io.WriteString(w, `<INPUT type="hidden" name="err_flag" VALUE="1">`+
			`<INPUT type="hidden" name="err_msg" VALUE="Incorrect password!">`)
	})
	_, err := WebLogin(srv.URL, "wrong", 5*time.Second)
	if err == nil {
		t.Fatal("WebLogin accepted a wrong password")
	}
	var authErr *ErrWebAuth
	if !errors.As(err, &authErr) {
		t.Fatalf("error = %T (%v), want *ErrWebAuth", err, err)
	}
	if authErr.Message != "Incorrect password!" {
		t.Errorf("auth message = %q", authErr.Message)
	}
}

func TestConfigRestoreBrowserFieldSet(t *testing.T) {
	var gotFile []byte
	var gotFilename string
	srv := newEmwebServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/base/main_login.html":
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "t0k3n", Path: "/"})
			io.WriteString(w, "<html>ok</html>")
			return
		}
		if r.URL.Path != "/base/system/http_file_download.html" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("multipart parse: %v", err)
			return
		}
		for field, want := range map[string]string{
			"file_type":       "txtcfg",
			"download_status": "",
			"submt":           "16",
			"cncel":           "",
			"err_flag":        "0",
			"err_msg":         "",
		} {
			if got := r.FormValue(field); got != want {
				t.Errorf("field %s = %q, want %q", field, got, want)
			}
		}
		f, fh, err := r.FormFile(".filename_handle")
		if err != nil {
			t.Errorf(".filename_handle part missing: %v", err)
			return
		}
		defer f.Close()
		gotFile, _ = io.ReadAll(f)
		gotFilename = fh.Filename
		// Success answer: re-served page with hidden status fields.
		io.WriteString(w, `<INPUT type="hidden" name="download_status" VALUE="Success">`+
			`<INPUT type="hidden" name="err_flag" VALUE="0">`+
			`<INPUT type="hidden" name="err_msg" VALUE="">`)
	})

	sess, err := WebLogin(srv.URL, "sekrit", 5*time.Second)
	if err != nil {
		t.Fatalf("WebLogin: %v", err)
	}
	res, err := sess.ConfigRestore([]byte(testTextConfig), "startup-config")
	if err != nil {
		t.Fatalf("ConfigRestore: %v", err)
	}
	if res.Failed() {
		t.Fatalf("restore flagged failed: %s", res.Error())
	}
	if res.DownloadStatus != "Success" {
		t.Errorf("download_status = %q, want %q", res.DownloadStatus, "Success")
	}
	if string(gotFile) != testTextConfig {
		t.Errorf("uploaded payload drifted: %d bytes", len(gotFile))
	}
	if gotFilename != "startup-config" {
		t.Errorf("uploaded filename = %q", gotFilename)
	}
}

func TestConfigRestoreReportsSwitchRejection(t *testing.T) {
	srv := newEmwebServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/base/main_login.html":
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "t0k3n", Path: "/"})
			io.WriteString(w, "<html>ok</html>")
			return
		case "/base/system/http_file_download.html":
			io.WriteString(w, `<INPUT type="hidden" name="err_flag" VALUE="1">`+
				`<INPUT type="hidden" name="err_msg" VALUE="Incompatible text config Firmware revision!">`+
				`<INPUT type="hidden" name="download_status" VALUE="">`)
			return
		}
		http.NotFound(w, r)
	})
	sess, err := WebLogin(srv.URL, "sekrit", 5*time.Second)
	if err != nil {
		t.Fatalf("WebLogin: %v", err)
	}
	res, err := sess.ConfigRestore([]byte(testTextConfig), "startup-config")
	if err != nil {
		t.Fatalf("ConfigRestore: %v", err)
	}
	if !res.Failed() {
		t.Fatal("rejected restore did not report Failed()")
	}
	if want := "Incompatible text config Firmware revision!"; res.Error() != want {
		t.Errorf("Error() = %q, want %q", res.Error(), want)
	}
}

func TestWebGetFile404(t *testing.T) {
	srv := newEmwebServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/base/main_login.html":
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "t0k3n", Path: "/"})
			io.WriteString(w, "<html>ok</html>")
			return
		}
		// The switch answers bare "404 Not Found" bodies, no page.
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "404 Not Found")
	})
	sess, err := WebLogin(srv.URL, "sekrit", 5*time.Second)
	if err != nil {
		t.Fatalf("WebLogin: %v", err)
	}
	_, err = sess.GetFile("image1")
	if err == nil {
		t.Fatal("GetFile on 404 did not error")
	}
	var wse *webStatusError
	if !errors.As(err, &wse) {
		t.Fatalf("error = %T (%v), want *webStatusError", err, err)
	}
	if wse.code != http.StatusNotFound {
		t.Errorf("status code = %d, want 404", wse.code)
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error = %q, want HTTP 404 detail", err)
	}
}

// TestSaveConfigRetriesAfterStaleSession pins the live-measured
// recovery for connection-bound SIDs: a 404 on the file GET means the
// pooled connection was dropped mid-sequence, and a brand-new login
// must transparently rescue the save.
func TestSaveConfigRetriesAfterStaleSession(t *testing.T) {
	var logins, fileGets int
	srv := newEmwebServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/base/main_login.html":
			logins++
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "t0k3n", Path: "/"})
			io.WriteString(w, "<html>ok</html>")
		case "/base/system/http_file_upload.html":
			io.WriteString(w, "<html>upload page</html>")
		case "/filesystem/startup-config":
			fileGets++
			if fileGets == 1 {
				// Stale connection-bound session: bare 404.
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, "404 Not Found")
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, testTextConfig)
		default:
			http.NotFound(w, r)
		}
	})
	sess, err := WebLogin(srv.URL, "sekrit", 5*time.Second)
	if err != nil {
		t.Fatalf("WebLogin: %v", err)
	}
	raw, err := sess.SaveConfig()
	if err != nil {
		t.Fatalf("SaveConfig did not recover from the stale-session 404: %v", err)
	}
	if string(raw) != testTextConfig {
		t.Error("retried save returned the wrong bytes")
	}
	if logins != 2 {
		t.Errorf("logins = %d, want 2 (initial + retry)", logins)
	}
	if fileGets != 2 {
		t.Errorf("file GETs = %d, want 2 (stale 404 + recovered)", fileGets)
	}
}

// TestConfigRestoreNon2xxIsFailed pins that a restore answered by a
// bare 404 (connection-bound session gone) reports failure even though
// the re-served body carries no hidden err_flag.
func TestConfigRestoreNon2xxIsFailed(t *testing.T) {
	srv := newEmwebServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/base/main_login.html":
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "t0k3n", Path: "/"})
			io.WriteString(w, "<html>ok</html>")
			return
		}
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "404 Not Found")
	})
	sess, err := WebLogin(srv.URL, "sekrit", 5*time.Second)
	if err != nil {
		t.Fatalf("WebLogin: %v", err)
	}
	res, err := sess.ConfigRestore([]byte(testTextConfig), "startup-config")
	if err != nil {
		t.Fatalf("ConfigRestore: %v", err)
	}
	if !res.Failed() {
		t.Fatalf("bare-404 restore not reported as failed: %+v", res)
	}
	if !strings.Contains(res.Error(), "404") {
		t.Errorf("Error() = %q, want HTTP 404 detail", res.Error())
	}
}
