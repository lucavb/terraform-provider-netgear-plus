package gs108ev3

import (
	"context"
	"crypto/md5" //nolint:gosec // Device protocol requires MD5.
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

const (
	defaultTimeout        = 15 * time.Second
	portCount             = 8
	endpointLoginHTM      = "/login.htm"
	endpointLoginCGI      = "/login.cgi"
	endpointLogoutCGI     = "/logout.cgi"
	endpointSwitchInfoHTM = "/switch_info.htm"
	endpointSwitchInfoCGI = "/switch_info.cgi"
	endpointVLANConfigHTM = "/8021qCf.htm"
	endpointVLANConfigCGI = "/8021qCf.cgi"
	endpointVLANMemberHTM = "/8021qMembe.htm"
	endpointVLANMemberCGI = "/8021qMembe.cgi"
	endpointPortPVIDHTM   = "/portPVID.htm"
	endpointPortPVIDCGI   = "/portPVID.cgi"
)

var (
	errAuthenticationFailed = errors.New("authentication failed")
	errSwitchLocked         = errors.New("switch temporarily locked")
	requestPacers           sync.Map
)

type requestPacer struct {
	mu          sync.Mutex
	lastRequest time.Time
}

// Driver implements the GS108Ev3 management surface.
type Driver struct {
	baseURL        *url.URL
	httpClient     *http.Client
	password       string
	host           string
	hash           string
	requestSpacing time.Duration
}

// New constructs a GS108Ev3 driver.
func New(host, password string, timeoutSeconds int64, requestSpacing time.Duration) (*Driver, error) {
	normalizedHost := strings.TrimSpace(host)
	if normalizedHost == "" {
		return nil, fmt.Errorf("host must not be empty")
	}

	if !strings.HasPrefix(normalizedHost, "http://") && !strings.HasPrefix(normalizedHost, "https://") {
		normalizedHost = "http://" + normalizedHost
	}

	baseURL, err := url.Parse(normalizedHost)
	if err != nil {
		return nil, fmt.Errorf("parse host: %w", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}

	timeout := defaultTimeout
	if timeoutSeconds > 0 {
		timeout = time.Duration(timeoutSeconds) * time.Second
	}

	return &Driver{
		baseURL: baseURL,
		httpClient: &http.Client{
			Jar:     jar,
			Timeout: timeout,
		},
		password:       password,
		host:           baseURL.Host,
		requestSpacing: requestSpacing,
	}, nil
}

// Login authenticates and caches the current session hash.
func (d *Driver) Login(ctx context.Context) error {
	loginPage, err := d.tryGET(ctx, endpointLoginHTM, endpointLoginCGI)
	if err != nil {
		return fmt.Errorf("load login page: %w", err)
	}

	rand, err := parseLoginRand(loginPage)
	if err != nil {
		return fmt.Errorf("parse login rand: %w", err)
	}

	form := url.Values{}
	form.Set("password", passwordKDF(d.password, rand))

	body, err := d.postFormRaw(ctx, endpointLoginCGI, form, false)
	if err != nil {
		return fmt.Errorf("submit login: %w", err)
	}

	if errMsg := parseErrorMessage(body); errMsg != "" {
		return loginFailureError(d.host, errMsg)
	}

	if !strings.Contains(body, `top.location.href = "index.htm";`) {
		return fmt.Errorf("%w: login failed: expected redirect script", errAuthenticationFailed)
	}

	if _, err := d.refreshHash(ctx); err != nil {
		return err
	}

	return nil
}

func loginFailureError(host, errMsg string) error {
	msg := strings.TrimSpace(errMsg)
	if isLoginAttemptLockout(msg) {
		return fmt.Errorf(
			"%w: login failed for %s: switch temporarily locked after too many attempts. Close any browser tabs or other clients connected to the switch, verify the password, wait a few minutes for the lockout window to clear, and retry. Firmware message: %s",
			errSwitchLocked,
			host,
			msg,
		)
	}

	return fmt.Errorf("%w: login failed for %s: %s", errAuthenticationFailed, host, msg)
}

func isLoginAttemptLockout(message string) bool {
	normalized := strings.ToLower(strings.TrimSpace(message))
	return strings.Contains(normalized, "maximum number of attempts has been reached") ||
		(strings.Contains(normalized, "wait a few minutes") && strings.Contains(normalized, "attempt"))
}

// Logout clears the current switch session if possible.
func (d *Driver) Logout(ctx context.Context) error {
	d.hash = ""
	_, err := d.getRaw(ctx, endpointLogoutCGI, false)
	return err
}

func (d *Driver) ShouldInvalidateSession(err error) bool {
	return errors.Is(err, errAuthenticationFailed) || errors.Is(err, errSwitchLocked)
}

// ReadSwitchFacts fetches and parses stable switch metadata.
func (d *Driver) ReadSwitchFacts(ctx context.Context) (model.SwitchFacts, error) {
	body, err := d.readSwitchInfoPage(ctx)
	if err != nil {
		return model.SwitchFacts{}, err
	}

	facts, err := parseSwitchFacts(d.host, "gs108ev3", body)
	if err != nil {
		return model.SwitchFacts{}, err
	}

	return facts, nil
}

// ReadVLANState fetches the current full 802.1Q VLAN state.
func (d *Driver) ReadVLANState(ctx context.Context) (model.VLANState, error) {
	hash, err := d.ensureHash(ctx)
	if err != nil {
		return model.VLANState{}, err
	}

	vlanListPage, err := d.tryGETAuthenticated(ctx, endpointVLANMemberHTM, endpointVLANMemberCGI)
	if err != nil {
		return model.VLANState{}, err
	}

	vlanIDs, err := parseCurrentVLANIDs(vlanListPage)
	if err != nil {
		return model.VLANState{}, err
	}

	state := model.VLANState{
		PortCount: portCount,
		VLANs:     make(map[int]model.Vlan, len(vlanIDs)),
		PVIDs:     make(map[int]int, portCount),
	}

	for _, vid := range vlanIDs {
		form := url.Values{}
		form.Set("VLAN_ID", fmt.Sprintf("%d", vid))
		form.Set("hash", hash)

		body, err := d.postFormAuthenticated(ctx, endpointVLANMemberCGI, form)
		if err != nil {
			return model.VLANState{}, fmt.Errorf("read vlan %d membership: %w", vid, err)
		}

		vlan, err := parseVLANMembership(vid, body)
		if err != nil {
			return model.VLANState{}, fmt.Errorf("parse vlan %d membership: %w", vid, err)
		}

		state.VLANs[vid] = vlan
	}

	pvidPage, err := d.tryGETAuthenticated(ctx, endpointPortPVIDHTM, endpointPortPVIDCGI)
	if err != nil {
		return model.VLANState{}, err
	}

	pvids, err := parsePVIDs(pvidPage)
	if err != nil {
		return model.VLANState{}, err
	}
	state.PVIDs = pvids

	return state.Normalize(), nil
}

func (d *Driver) readSwitchInfoPage(ctx context.Context) (string, error) {
	body, err := d.tryGETAuthenticated(ctx, endpointSwitchInfoHTM, endpointSwitchInfoCGI)
	if err != nil {
		return "", err
	}

	if _, err := d.refreshHashFromBody(body); err != nil {
		return "", err
	}

	return body, nil
}

func (d *Driver) ensureHash(ctx context.Context) (string, error) {
	if d.hash != "" {
		return d.hash, nil
	}
	return d.refreshHash(ctx)
}

func (d *Driver) refreshHash(ctx context.Context) (string, error) {
	body, err := d.tryGETAuthenticated(ctx, endpointSwitchInfoHTM, endpointSwitchInfoCGI)
	if err != nil {
		return "", err
	}
	return d.refreshHashFromBody(body)
}

func (d *Driver) refreshHashFromBody(body string) (string, error) {
	hash, err := parseSessionHash(body)
	if err != nil {
		return "", fmt.Errorf("parse session hash: %w", err)
	}
	d.hash = hash
	return hash, nil
}

func (d *Driver) tryGET(ctx context.Context, endpoints ...string) (string, error) {
	var lastErr error
	for _, endpoint := range endpoints {
		body, err := d.getRaw(ctx, endpoint, false)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no endpoints attempted")
	}
	return "", lastErr
}

func (d *Driver) tryGETAuthenticated(ctx context.Context, endpoints ...string) (string, error) {
	var lastErr error
	for _, endpoint := range endpoints {
		body, err := d.getRaw(ctx, endpoint, true)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no endpoints attempted")
	}
	return "", lastErr
}

func (d *Driver) getRaw(ctx context.Context, endpoint string, retryAuth bool) (string, error) {
	if err := d.waitRequestSpacing(ctx); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.resolveURL(endpoint), nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("perform request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	body := string(bodyBytes)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d from %s", resp.StatusCode, endpoint)
	}

	if retryAuth && isRedirectToLogin(body) {
		if err := d.Login(ctx); err != nil {
			return "", err
		}
		return d.getRaw(ctx, endpoint, false)
	}

	return body, nil
}

func (d *Driver) postFormRaw(ctx context.Context, endpoint string, form url.Values, retryAuth bool) (string, error) {
	if err := d.waitRequestSpacing(ctx); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.resolveURL(endpoint), strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("perform request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	body := string(bodyBytes)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d from %s", resp.StatusCode, endpoint)
	}

	if retryAuth && isRedirectToLogin(body) {
		if err := d.Login(ctx); err != nil {
			return "", err
		}
		return d.postFormRaw(ctx, endpoint, form, false)
	}

	return body, nil
}

func (d *Driver) postFormAuthenticated(ctx context.Context, endpoint string, form url.Values) (string, error) {
	if _, err := d.ensureHash(ctx); err != nil {
		return "", err
	}
	return d.postFormRaw(ctx, endpoint, form, true)
}

func (d *Driver) resolveURL(endpoint string) string {
	return d.baseURL.ResolveReference(&url.URL{Path: endpoint}).String()
}

func (d *Driver) waitRequestSpacing(ctx context.Context) error {
	if d.requestSpacing <= 0 {
		return nil
	}

	pacerValue, _ := requestPacers.LoadOrStore(strings.ToLower(strings.TrimSpace(d.host)), &requestPacer{})
	pacer := pacerValue.(*requestPacer)

	pacer.mu.Lock()
	defer pacer.mu.Unlock()

	now := time.Now()
	if !pacer.lastRequest.IsZero() {
		wait := d.requestSpacing - now.Sub(pacer.lastRequest)
		if wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
		}
	}

	pacer.lastRequest = time.Now()
	return nil
}

func passwordKDF(password, rand string) string {
	sum := md5.Sum([]byte(merge(password, rand))) //nolint:gosec // Device protocol requires MD5.
	return hex.EncodeToString(sum[:])
}

func merge(left, right string) string {
	var builder strings.Builder
	builder.Grow(len(left) + len(right))

	maxLen := len(left)
	if len(right) > maxLen {
		maxLen = len(right)
	}

	for idx := 0; idx < maxLen; idx++ {
		if idx < len(left) {
			builder.WriteByte(left[idx])
		}
		if idx < len(right) {
			builder.WriteByte(right[idx])
		}
	}

	return builder.String()
}

func firstValue(doc *goquery.Document, selector, attr string) string {
	value, _ := doc.Find(selector).First().Attr(attr)
	return strings.TrimSpace(value)
}
