package gs108ev3

import (
	"context"
	"fmt"
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

type testSwitchServer struct {
	server *httptest.Server
	mu     sync.Mutex
	hash   string
	vlans  map[int]string
	pvids  map[int]int
}

func newTestSwitchServer() *testSwitchServer {
	ts := &testSwitchServer{
		hash: "deadbeefcafebabe",
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

	ts.server = httptest.NewServer(mux)
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
	if r.Form.Get("password") != passwordKDF("password", "12345678") {
		_, _ = w.Write([]byte(`<html><input id="err_msg" value="Invalid password" /></html>`))
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "GS108SID", Value: "cookie", Path: "/"})
	_, _ = w.Write([]byte(`<html><script>top.location.href = "index.htm";</script></html>`))
}

func (tss *testSwitchServer) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("GS108SID"); err != nil {
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

func (tss *testSwitchServer) sortedVLANIDs() []int {
	ids := make([]int, 0, len(tss.vlans))
	for vid := range tss.vlans {
		ids = append(ids, vid)
	}
	slices.Sort(ids)
	return ids
}

var _ = url.Values{}
