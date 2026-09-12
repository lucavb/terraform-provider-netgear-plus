package gs108ev3

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

func TestDriverReadAndApplyVLANState(t *testing.T) {
	t.Parallel()

	server := newTestSwitchServer()
	defer server.Close()

	driver, err := New(server.URL(), "password", 15, 0)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()

	facts, err := driver.ReadSwitchFacts(ctx)
	if err != nil {
		t.Fatalf("ReadSwitchFacts() error = %v", err)
	}
	if facts.SwitchName != "lab-switch" {
		t.Fatalf("unexpected switch facts: %+v", facts)
	}

	current, err := driver.ReadVLANState(ctx)
	if err != nil {
		t.Fatalf("ReadVLANState() error = %v", err)
	}
	if current.PVIDs[1] != 1 || current.PVIDs[8] != 10 {
		t.Fatalf("unexpected initial pvids: %v", current.PVIDs)
	}

	desired := model.VLANState{
		PortCount: 8,
		VLANs: map[int]model.Vlan{
			1: {
				ID: 1,
				Ports: map[int]model.PortMembership{
					1: model.PortMembershipUntagged,
					2: model.PortMembershipUntagged,
					3: model.PortMembershipTagged,
					4: model.PortMembershipTagged,
					5: model.PortMembershipIgnored,
					6: model.PortMembershipIgnored,
					7: model.PortMembershipIgnored,
					8: model.PortMembershipIgnored,
				},
			},
			20: {
				ID: 20,
				Ports: map[int]model.PortMembership{
					1: model.PortMembershipIgnored,
					2: model.PortMembershipIgnored,
					3: model.PortMembershipIgnored,
					4: model.PortMembershipIgnored,
					5: model.PortMembershipUntagged,
					6: model.PortMembershipUntagged,
					7: model.PortMembershipTagged,
					8: model.PortMembershipTagged,
				},
			},
		},
		PVIDs: map[int]int{
			1: 1,
			2: 1,
			3: 1,
			4: 1,
			5: 20,
			6: 20,
			7: 20,
			8: 20,
		},
	}

	if err := driver.ApplyVLANState(ctx, desired); err != nil {
		t.Fatalf("ApplyVLANState() error = %v", err)
	}

	verified, err := driver.ReadVLANState(ctx)
	if err != nil {
		t.Fatalf("ReadVLANState() after apply error = %v", err)
	}
	if !verified.Equal(desired) {
		t.Fatalf("verified state does not match desired:\nverified=%+v\ndesired=%+v", verified, desired)
	}
}

func TestDriverReadConfig(t *testing.T) {
	t.Parallel()

	server := newTestSwitchServer()
	defer server.Close()

	driver, err := New(server.URL(), "password", 15, 0)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	config, err := driver.ReadConfig(context.Background())
	if err != nil {
		t.Fatalf("ReadConfig() error = %v", err)
	}

	_, ok := config.Section("sysname")
	if !ok {
		t.Fatal("ReadConfig() result has no sysname section")
	}

	pvids, err := config.PVIDs()
	if err != nil {
		t.Fatalf("PVIDs() error = %v", err)
	}
	wantPVIDs := []int{1, 1, 1, 1, 10, 10, 10, 10}
	if !slices.Equal(pvids, wantPVIDs) {
		t.Fatalf("PVIDs() = %v, want %v", pvids, wantPVIDs)
	}

	vlans, err := config.VLANs()
	if err != nil {
		t.Fatalf("VLANs() error = %v", err)
	}
	if len(vlans) != 1 {
		t.Fatalf("VLAN count = %d, want 1", len(vlans))
	}
	if got, want := vlans[0].ID, 10; got != want {
		t.Fatalf("vlan ID = %d, want %d", got, want)
	}
	if !slices.Equal(vlans[0].Members, []int{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("vlan 10 members = %v", vlans[0].Members)
	}
	if !slices.Equal(vlans[0].Tagged, []int{1, 2, 3, 4, 6, 7, 8}) {
		t.Fatalf("vlan 10 tagged = %v, want [1 2 3 4 6 7 8]", vlans[0].Tagged)
	}
}

type testSwitchServer struct {
	server *httptest.Server
	mu     sync.Mutex
	hash   string
	vlans  map[int]string
	pvids  map[int]int

	loginAttempts          int
	loginFailuresRemaining int

	sessionGeneration int
	sessionToken      string

	restoredConfig         []byte
	restoredConfigOverride []byte

	downConnections       int
	rebootDownConnections int

	restoreRequests    int
	refusedRestores    int
	refusedConnections int
	lastRestore        restoreRequestRecord
}

// restoreRequestRecord captures how the switch's restore endpoint saw a
// restore request, so tests can verify the exact multipart structure.
type restoreRequestRecord struct {
	valid           bool
	cookieValid     bool
	hashFieldValid  bool
	hash            string
	fileFieldValid  bool
	filename        string
	fileContentType string
	uploaded        []byte
	partCountValid  bool
}

func newTestSwitchServer() *testSwitchServer {
	ts := &testSwitchServer{
		hash:         "deadbeefcafebabe",
		sessionToken: "cookie",
		vlans: map[int]string{
			1:  "11113333",
			10: "22223333",
		},
		pvids: map[int]int{
			1: 1,
			2: 1,
			3: 1,
			4: 1,
			5: 10,
			6: 10,
			7: 10,
			8: 10,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login.htm", ts.handleLoginPage)
	mux.HandleFunc("/login.cgi", ts.handleLogin)
	mux.HandleFunc("/logout.cgi", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/switch_info.htm", ts.withAuth(ts.handleSwitchInfo))
	mux.HandleFunc("/switch_info.cgi", ts.withAuth(ts.handleSwitchInfo))
	mux.HandleFunc("/8021qMembe.htm", ts.withAuth(ts.handleVLANList))
	mux.HandleFunc("/8021qMembe.cgi", ts.withAuth(ts.handleVLANMembership))
	mux.HandleFunc("/portPVID.htm", ts.withAuth(ts.handlePVIDPage))
	mux.HandleFunc("/portPVID.cgi", ts.withAuth(ts.handlePVIDUpdate))
	mux.HandleFunc("/8021qCf.htm", ts.withAuth(ts.handleVLANConfigPage))
	mux.HandleFunc("/8021qCf.cgi", ts.withAuth(ts.handleVLANConfigUpdate))
	mux.HandleFunc("/config_data.bin", ts.withAuth(ts.handleConfigData))
	mux.HandleFunc("/restore_conf.cgi", ts.withAuth(ts.handleRestoreConfig))

	// The restore reboot window is simulated at the connection level:
	// while the switch is "down", incoming connections are dropped before
	// any handler runs.
	ts.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ts.consumeDownConnection() {
			ts.refuseConnection(w)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	return ts
}

func (tss *testSwitchServer) Close() {
	tss.server.Close()
}

func (tss *testSwitchServer) URL() string {
	return tss.server.URL
}

func (tss *testSwitchServer) handleLoginPage(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte(`<html><input id="rand" value="12345678" /><input id="err_msg" value="" /></html>`))
}

func (tss *testSwitchServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	tss.mu.Lock()
	tss.loginAttempts++
	forcedFailure := tss.loginFailuresRemaining > 0
	if forcedFailure {
		tss.loginFailuresRemaining--
	}
	token := tss.sessionToken
	tss.mu.Unlock()

	if forcedFailure || r.Form.Get("password") != passwordKDF("password", "12345678") {
		_, _ = w.Write([]byte(`<html><input id="err_msg" value="Invalid password" /></html>`))
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "GS108SID", Value: token, Path: "/"})
	_, _ = w.Write([]byte(`<html><script>top.location.href = "index.htm";</script></html>`))
}

// setLoginFailures makes the next n login attempts fail before accepting
// logins again.
func (tss *testSwitchServer) setLoginFailures(n int) {
	tss.mu.Lock()
	defer tss.mu.Unlock()
	tss.loginFailuresRemaining = n
}

func (tss *testSwitchServer) loginAttemptCount() int {
	tss.mu.Lock()
	defer tss.mu.Unlock()
	return tss.loginAttempts
}

func (tss *testSwitchServer) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("GS108SID")

		tss.mu.Lock()
		valid := err == nil && cookie.Value == tss.sessionToken
		if !valid && r.URL.Path == "/restore_conf.cgi" {
			tss.refusedRestores++
		}
		tss.mu.Unlock()

		if !valid {
			_, _ = w.Write([]byte(`<html><head><title>Redirect to login</title></head></html>`))
			return
		}
		next(w, r)
	}
}

func (tss *testSwitchServer) handleSwitchInfo(w http.ResponseWriter, _ *http.Request) {
	html := fmt.Sprintf(`<html><body><input id="switch_name" value="lab-switch" /><input name="hash" value="%s" /><table id="tbl1"><tr><td>Switch Name</td><td>lab-switch</td></tr><tr><td>Serial Number</td><td>4AB123456789</td></tr><tr><td>MAC Address</td><td>00:11:22:33:44:55</td></tr><tr><td>Firmware Version</td><td>V2.06.24EN</td></tr><tr><td>Bootloader Version</td><td id="loader">V2.06.03</td></tr></table></body></html>`, tss.hash)
	_, _ = w.Write([]byte(html))
}

func (tss *testSwitchServer) handleVLANList(w http.ResponseWriter, _ *http.Request) {
	tss.mu.Lock()
	defer tss.mu.Unlock()

	var builder strings.Builder
	builder.WriteString(`<html><body><select id="vlanIdOption">`)
	for _, vid := range tss.sortedVLANIDs() {
		builder.WriteString(fmt.Sprintf(`<option value="%d">%d</option>`, vid, vid))
	}
	builder.WriteString(`</select><input id="err_msg" value="" /></body></html>`)
	_, _ = w.Write([]byte(builder.String()))
}

func (tss *testSwitchServer) handleVLANMembership(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	tss.mu.Lock()
	defer tss.mu.Unlock()

	if hidden := r.Form.Get("hiddenMem"); hidden != "" {
		vid, _ := strconv.Atoi(r.Form.Get("VLAN_ID"))
		tss.vlans[vid] = hidden
		_, _ = w.Write([]byte(`<html><input id="err_msg" value="" /></html>`))
		return
	}

	vid, _ := strconv.Atoi(r.Form.Get("VLAN_ID"))
	membership := tss.vlans[vid]
	_, _ = w.Write([]byte(fmt.Sprintf(`<html><input name="VLAN_ID_HD" value="%d" /><input id="hiddenMem" value="%s" /><input id="err_msg" value="" /></html>`, vid, membership)))
}

func (tss *testSwitchServer) handlePVIDPage(w http.ResponseWriter, _ *http.Request) {
	tss.mu.Lock()
	defer tss.mu.Unlock()

	var builder strings.Builder
	builder.WriteString(`<html><body><table>`)
	for port := 1; port <= 8; port++ {
		builder.WriteString(fmt.Sprintf(`<tr class="portID"><td>%d</td><td class="def" sel="input">%d</td><td><input type="hidden" value="%d" /></td></tr>`, port, tss.pvids[port], port))
	}
	builder.WriteString(`</table></body></html>`)
	_, _ = w.Write([]byte(builder.String()))
}

func (tss *testSwitchServer) handlePVIDUpdate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	tss.mu.Lock()
	defer tss.mu.Unlock()

	vid, _ := strconv.Atoi(r.Form.Get("pvid"))
	for port := 1; port <= 8; port++ {
		if r.Form.Get(fmt.Sprintf("port%d", port)) == "checked" {
			tss.pvids[port] = vid
		}
	}

	_, _ = w.Write([]byte(`<html><input id="err_msg" value="" /></html>`))
}

func (tss *testSwitchServer) handleVLANConfigPage(w http.ResponseWriter, _ *http.Request) {
	tss.mu.Lock()
	defer tss.mu.Unlock()

	_, _ = w.Write([]byte(fmt.Sprintf(`<html><body><input name="vlanNum" value="%d" /><input id="err_msg" value="" /></body></html>`, len(tss.vlans))))
}

func (tss *testSwitchServer) handleVLANConfigUpdate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	tss.mu.Lock()
	defer tss.mu.Unlock()

	switch r.Form.Get("ACTION") {
	case "Add":
		vid, _ := strconv.Atoi(r.Form.Get("ADD_VLANID"))
		tss.vlans[vid] = "33333333"
	case "Delete":
		for key, values := range r.Form {
			if !strings.HasPrefix(key, "vlanck") || len(values) == 0 {
				continue
			}
			vid, _ := strconv.Atoi(values[0])
			delete(tss.vlans, vid)
		}
	}

	_, _ = w.Write([]byte(`<html><input id="err_msg" value="" /></html>`))
}

func (tss *testSwitchServer) handleConfigData(w http.ResponseWriter, _ *http.Request) {
	tss.mu.Lock()
	restored := tss.restoredConfig
	tss.mu.Unlock()

	if restored != nil {
		_, _ = w.Write(restored)
		return
	}
	_, _ = w.Write(testConfigBackup())
}

// handleRestoreConfig mirrors the switch's restore endpoint: it verifies the
// exact multipart structure of the upload, stores the restored bytes, kills
// the current session, and (optionally) simulates the reboot window.
func (tss *testSwitchServer) handleRestoreConfig(w http.ResponseWriter, r *http.Request) {
	record := tss.verifyRestoreRequest(r)

	tss.mu.Lock()
	tss.restoreRequests++
	tss.lastRestore = record
	if record.valid {
		if tss.restoredConfigOverride != nil {
			tss.restoredConfig = tss.restoredConfigOverride
		} else {
			tss.restoredConfig = record.uploaded
		}
		tss.downConnections = tss.rebootDownConnections
		tss.rotateSessionLocked()
	}
	tss.mu.Unlock()

	if !record.valid {
		_, _ = w.Write([]byte(`<html><input id="err_msg" value="Invalid restore request" /></html>`))
		return
	}

	// The real switch answers with a splash page and then reboots.
	_, _ = w.Write([]byte(`<html><script>top.location.href = "restore_rebooting.htm";</script></html>`))
}

func (tss *testSwitchServer) verifyRestoreRequest(r *http.Request) restoreRequestRecord {
	var record restoreRequestRecord

	cookie, cookieErr := r.Cookie("GS108SID")
	if cookieErr == nil {
		tss.mu.Lock()
		record.cookieValid = cookie.Value == tss.sessionToken
		tss.mu.Unlock()
	}

	reader, err := r.MultipartReader()
	if err != nil {
		return record
	}

	hashPart, err := reader.NextPart()
	if err != nil || hashPart.FormName() != "hash" || hashPart.FileName() != "" {
		return record
	}
	hashValue, err := io.ReadAll(hashPart)
	if err != nil {
		return record
	}
	record.hash = string(hashValue)

	tss.mu.Lock()
	record.hashFieldValid = record.hash == tss.hash
	tss.mu.Unlock()

	filePart, err := reader.NextPart()
	if err != nil {
		return record
	}
	record.filename = filePart.FileName()
	record.fileContentType = filePart.Header.Get("Content-Type")
	record.fileFieldValid = filePart.FormName() == "fileField" &&
		record.filename == "GS108Ev3.cfg" &&
		record.fileContentType == "application/octet-stream"
	if !record.fileFieldValid {
		return record
	}

	uploaded, err := io.ReadAll(filePart)
	if err != nil {
		return record
	}
	record.uploaded = uploaded

	if _, err := reader.NextPart(); err != io.EOF {
		return record
	}
	record.partCountValid = true

	record.valid = record.cookieValid && record.hashFieldValid && record.fileFieldValid && record.partCountValid
	return record
}

// rebootAfterRestore makes the server drop the next n connections after a
// valid restore, simulating the reboot window before fresh logins work.
func (tss *testSwitchServer) rebootAfterRestore(n int) {
	tss.mu.Lock()
	defer tss.mu.Unlock()
	tss.rebootDownConnections = n
}

// setRestoredConfigOverride makes the server serve different bytes after a
// restore, to exercise the post-restore fingerprint verification failure
// path.
func (tss *testSwitchServer) setRestoredConfigOverride(data []byte) {
	tss.mu.Lock()
	defer tss.mu.Unlock()
	tss.restoredConfigOverride = data
}

// rotateSession invalidates the current GS108SID, like a reboot does.
func (tss *testSwitchServer) rotateSession() {
	tss.mu.Lock()
	defer tss.mu.Unlock()
	tss.rotateSessionLocked()
}

func (tss *testSwitchServer) rotateSessionLocked() {
	tss.sessionGeneration++
	tss.sessionToken = fmt.Sprintf("cookie-%d", tss.sessionGeneration)
}

func (tss *testSwitchServer) restoreRequestCount() int {
	tss.mu.Lock()
	defer tss.mu.Unlock()
	return tss.restoreRequests
}

func (tss *testSwitchServer) refusedRestoreCount() int {
	tss.mu.Lock()
	defer tss.mu.Unlock()
	return tss.refusedRestores
}

func (tss *testSwitchServer) refusedConnectionCount() int {
	tss.mu.Lock()
	defer tss.mu.Unlock()
	return tss.refusedConnections
}

func (tss *testSwitchServer) lastRestoreRecord() restoreRequestRecord {
	tss.mu.Lock()
	defer tss.mu.Unlock()
	return tss.lastRestore
}

func (tss *testSwitchServer) consumeDownConnection() bool {
	tss.mu.Lock()
	defer tss.mu.Unlock()

	if tss.downConnections <= 0 {
		return false
	}
	tss.downConnections--
	tss.refusedConnections++
	return true
}

// refuseConnection drops the TCP connection without a response, like a
// rebooting switch refusing connections.
func (tss *testSwitchServer) refuseConnection(w http.ResponseWriter) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	conn, _, err := hijacker.Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

// testConfigBackup assembles a synthetic FMv2 configuration backup. Real
// backups contain password material and must never be used as test input.
func testConfigBackup() []byte {
	return buildTestConfigBackup("lab-switch", []int{1, 1, 1, 1, 10, 10, 10, 10})
}

func buildTestConfigBackup(name string, pvids []int) []byte {
	var payload []byte
	payload = append(payload, testConfigSection("sysname", []byte(name))...)

	vlanData := make([]byte, 8)
	binary.LittleEndian.PutUint16(vlanData[0:2], 4)
	binary.LittleEndian.PutUint16(vlanData[2:4], 1)
	binary.LittleEndian.PutUint16(vlanData[4:6], 10)
	binary.LittleEndian.PutUint16(vlanData[6:8], 0xEFFF)
	payload = append(payload, testConfigSection("vlan", vlanData)...)

	pvidData := make([]byte, 16)
	for port, pvid := range pvids {
		binary.LittleEndian.PutUint16(pvidData[port*2:], uint16(pvid))
	}
	payload = append(payload, testConfigSection("pvid", pvidData)...)

	data := make([]byte, 8, 8+len(payload))
	copy(data[0:4], "FMv2")
	binary.BigEndian.PutUint16(data[4:6], uint16(len(payload)))

	var sum uint32
	for offset := 0; offset < len(payload); offset += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[offset:]))
	}
	binary.BigEndian.PutUint16(data[6:8], uint16(sum%65535))

	return append(data, payload...)
}

func testConfigSection(name string, data []byte) []byte {
	body := make([]byte, 0, len(name)+1+len(data))
	body = append(body, name...)
	body = append(body, 0)
	body = append(body, data...)

	section := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint16(section[0:2], 1)
	binary.BigEndian.PutUint16(section[2:4], uint16(len(body)))

	return append(section, body...)
}

func (tss *testSwitchServer) sortedVLANIDs() []int {
	ids := make([]int, 0, len(tss.vlans))
	for vid := range tss.vlans {
		ids = append(ids, vid)
	}
	slices.Sort(ids)
	return ids
}

var _ = url.Values{}
