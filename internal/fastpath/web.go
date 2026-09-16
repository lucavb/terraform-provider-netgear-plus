package fastpath

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// emweb session client for the FASTPATH switch web UI (GS108Tv2 /
// GS110TPv2-class): bare-password POST login to /base/main_login.html
// (fields `pwd` + the `login` IMAGE button click coordinates), SID
// HttpOnly cookie session, GET /filesystem/<file> (code/txtcfg paths
// via the rollover.js stream), and multipart POST restore via
// /base/system/http_file_download.html (hidden activation token submt
// = 16 per submitform()).
//
// This is the same wire shape a browser session generates; no TFTP
// server is needed for either direction here: the config file BOTH
// saves (GET) and restores (multipart POST) over pure HTTP.
//
// Live-measured operational contracts (GS108Tv2, fw 5.4.2.36,
// 2026-09-16):
//
//   - The SID session is BOUND TO THE TCP CONNECTION THAT CREATED IT.
//     A valid SID presented over a fresh connection answers bare
//     "404 Not Found" (the dispatcher's failed-session tail — the
//     same branch as an expired SID). http.Client keep-alive pooling
//     satisfies the contract; SaveConfig additionally retries once
//     with a brand-new session if the pool drops the connection
//     mid-sequence.
//   - After a restore POST the switch has a ~2-minute transient
//     window: a re-fetch can race the ingest and serve a file whose
//     first header byte is still mid-write (observed "!x4e47…" for
//     "0x4e47…"), and new logins may be refused outright. Callers
//     that read back after a restore should back off and re-login.
//   - Every fetch re-serves the file verbatim EXCEPT the
//     "!System Up Time" annotation, which tracks the switch's wall
//     clock. Byte-for-byte comparisons must exclude that line.
// ---------------------------------------------------------------------------

// WebSession is an authenticated emweb session against one switch.
type WebSession struct {
	host      string // authority (host[:port])
	password  string // kept for mid-session re-login on connection loss
	useTLS    bool
	client    *http.Client
	sid       string
	timeout   time.Duration
	userAgent string
}

// WebLogin performs the main_login.html POST flow and returns the
// session on success. addr is the switch host or URL.
func WebLogin(addr, password string, timeout time.Duration) (*WebSession, error) {
	host, err := WebTargetHost(addr)
	if err != nil {
		return nil, err
	}
	useTLS := strings.HasPrefix(strings.ToLower(strings.TrimSpace(addr)), "https://")
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("web: cookie jar: %w", err)
	}
	s := &WebSession{
		host:     host,
		password: password,
		useTLS:   useTLS,
		client: &http.Client{
			Timeout: timeout,
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // emweb answers in-place
			},
		},
		timeout:   timeout,
		userAgent: "netgear-plus-provider/1.0 (terraform-provider-netgear-plus)",
	}

	// Login POST: form password field `pwd`, image-submit `login.x/y`
	// coordinates sent by every browser. No username: emweb binds to
	// the (single) admin user.
	form := url.Values{
		"pwd":     {password},
		"login.x": {"5"},
		"login.y": {"5"},
	}
	req, err := http.NewRequest(http.MethodPost, s.base()+"/base/main_login.html", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", s.userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("web: login request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("web: login rejected (HTTP %d)", resp.StatusCode)
	}

	sid := ""
	for _, c := range resp.Cookies() {
		if c.Name == "SID" && c.Value != "" {
			sid = c.Value
		}
	}
	if sid == "" {
		// Wrong password answers with the login page again
		// (err_flag=1/err_msg filled); no Set-Cookie SID.
		return nil, errWebAuthFailed(body)
	}
	s.sid = sid
	return s, nil
}

// errWebAuthFailed parses the login page's err_flag / err_msg hidden
// fields and wraps a typed failure.
func errWebAuthFailed(body []byte) error {
	text := string(body)
	flag := fieldsOf(text, "err_flag")
	if flag == "1" {
		msg := fieldsOf(text, "err_msg")
		return &ErrWebAuth{Message: msg}
	}
	return &ErrWebAuth{Message: "no SID cookie granted"}
}

// ErrWebAuth is the typed login failure.
type ErrWebAuth struct{ Message string }

func (e *ErrWebAuth) Error() string {
	if e.Message != "" {
		return "web: login failed: " + e.Message
	}
	return "web: login failed"
}

// fieldsOf extracts VALUE="..." of an INPUT name= field from the
// emweb-served page markup.
func fieldsOf(text, name string) string {
	idx := strings.Index(text, "name=\""+name+"\"")
	if idx < 0 {
		return ""
	}
	valIdx := strings.Index(text[idx:], "VALUE=\"")
	if valIdx < 0 {
		return ""
	}
	from := idx + valIdx + len("VALUE=\"")
	to := strings.Index(text[from:], "\"")
	if to < 0 {
		return ""
	}
	return text[from : from+to]
}

// WebTargetHost normalizes a host/URL into the authority (host or
// host:port) for emweb access. A URL may carry the scheme and/or a
// port; a bare host or host:port is accepted as-is.
func WebTargetHost(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", errors.New("web: empty host")
	}
	if strings.Contains(addr, "://") {
		if u, err := url.Parse(addr); err == nil && u.Host != "" {
			return u.Host, nil
		}
	}
	return addr, nil
}

func (s *WebSession) base() string {
	if s.useTLS {
		return "https://" + s.host
	}
	return "http://" + s.host
}

// get performs a session GET against an absolute switch path and
// returns the status code and full body.
func (s *WebSession) get(path string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, s.base()+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, body, nil
}

// webStatusError is the typed non-2xx answer to a session request.
type webStatusError struct {
	code int
	msg  string
}

func (e *webStatusError) Error() string {
	return fmt.Sprintf("web: HTTP %d: %s", e.code, e.msg)
}

// GetFile streams a FILESYSTEM file — the save path: GET
// /filesystem/startup-config (with the session cookie) returns the
// verbatim text configuration.
func (s *WebSession) GetFile(virtualPath string) ([]byte, error) {
	path := "/filesystem/" + strings.TrimPrefix(virtualPath, "/")
	code, body, err := s.get(path)
	if err != nil {
		return nil, fmt.Errorf("web: GET %s: %w", path, err)
	}
	if code >= 200 && code < 300 {
		return body, nil
	}
	return body, &webStatusError{code: code, msg: path + ": " + failMessage(body)}
}

// SaveConfig fetches the text configuration over the emweb HTTP
// channel, browser-faithful: first GET the "HTTP File Upload" page
// exactly as the browser does before Apply triggers
// window.open("/filesystem/startup-config"), then GET the file
// itself. The firmware handler (ewsFileSetupFilesystemDoc) copies
// nvram:startup-config to "backup-config" and serves that copy as
// text/plain.
//
// emweb binds the SID session to the TCP connection that created it;
// if the pooled connection was dropped between login and the file
// GET, the switch answers bare 404. Session-class status failures
// are retried once on a brand-new login before giving up.
func (s *WebSession) SaveConfig() ([]byte, error) {
	raw, err := s.saveConfigOnce()
	if err == nil {
		return raw, nil
	}
	var wse *webStatusError
	if !errors.As(err, &wse) || !isStaleSessionStatus(wse.code) {
		return nil, err
	}
	fresh, lerr := WebLogin(s.base(), s.password, s.timeout)
	if lerr != nil {
		return nil, fmt.Errorf("web: session went stale mid-download; re-login: %v (original: %v)", lerr, err)
	}
	*s = *fresh
	return s.saveConfigOnce()
}

// isStaleSessionStatus reports whether an HTTP status code means the
// connection-bound SID was not honored (or expired) rather than the
// file itself failing.
func isStaleSessionStatus(code int) bool {
	return code == http.StatusUnauthorized ||
		code == http.StatusForbidden ||
		code == http.StatusNotFound
}

func (s *WebSession) saveConfigOnce() ([]byte, error) {
	// Arming GET: mirrors browser navigation onto the upload page.
	if code, body, err := s.get("/base/system/http_file_upload.html"); err != nil {
		return nil, fmt.Errorf("web: arming GET failed: %w", err)
	} else if code != http.StatusOK {
		return nil, fmt.Errorf("web: arming GET: HTTP %d: %s", code, failMessage(body))
	}
	raw, err := s.GetFile("startup-config")
	if err != nil {
		return nil, err
	}
	return raw, ValidateTextConfigHeader(raw, "", "")
}

// RestoreResult is the parsed emweb answer to a restore POST: the
// http_file_download.html page re-served with its hidden status
// fields updated.
type RestoreResult struct {
	HTTPStatus     int
	ErrFlag        string // "1" = the switch rejected the transfer
	ErrMsg         string
	DownloadStatus string
}

// Failed reports whether the switch flagged the transfer as failed
// or answered a non-2xx page at all: a stale connection-bound
// session yields a bare 404 whose hidden fields never got set, and
// that must not masquerade as success.
func (r *RestoreResult) Failed() bool {
	if r == nil {
		return false
	}
	if r.ErrFlag == "1" {
		return true
	}
	return r.HTTPStatus < 200 || r.HTTPStatus >= 300
}

// Error turns a failed result into an error value.
func (r *RestoreResult) Error() string {
	if r == nil {
		return "<no response>"
	}
	if r.ErrMsg != "" {
		return r.ErrMsg
	}
	if r.DownloadStatus != "" {
		return r.DownloadStatus
	}
	return fmt.Sprintf("HTTP %d", r.HTTPStatus)
}

// ConfigRestore POSTs a text configuration file as the emweb
// http_file_download.html multipart upload (browser-faithful field
// set: file_type, the .filename_handle file, download_status, the
// submt=16 activation token submitform() writes, cncel, err_flag,
// err_msg), and parses the re-served page's status fields.
// filename is the browser-side display name (the switch parses the
// payload, not the name).
func (s *WebSession) ConfigRestore(content []byte, filename string) (*RestoreResult, error) {
	if filename == "" {
		filename = "startup-config"
	}
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	mp := multipart.NewWriter(w)
	_ = mp.WriteField("file_type", "txtcfg")
	_ = mp.WriteField("download_status", "")
	fh, err := mp.CreateFormFile(".filename_handle", filename)
	if err != nil {
		return nil, err
	}
	if _, err := fh.Write(content); err != nil {
		return nil, err
	}
	_ = mp.WriteField("submt", "16")
	_ = mp.WriteField("cncel", "")
	_ = mp.WriteField("err_flag", "0")
	_ = mp.WriteField("err_msg", "")
	if err := mp.Close(); err != nil {
		return nil, err
	}
	if err := w.Flush(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, s.base()+"/base/system/http_file_download.html", &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mp.FormDataContentType())
	req.Header.Set("User-Agent", s.userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("web: config restore: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	res := &RestoreResult{HTTPStatus: resp.StatusCode}
	page := string(body)
	res.ErrFlag = fieldsOf(page, "err_flag")
	res.ErrMsg = fieldsOf(page, "err_msg")
	res.DownloadStatus = fieldsOf(page, "download_status")
	return res, nil
}

func failMessage(body []byte) string {
	const max = 200
	if msg := fieldsOf(string(body), "err_msg"); msg != "" {
		if len(msg) > max {
			msg = msg[:max]
		}
		return msg
	}
	return strings.TrimSpace(string(body[:minInt2(max, len(body))]))
}
