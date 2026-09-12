package nsdptest

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// startClient launches a fake agent plus a client dialed to it over
// loopback UDP. Start's cleanup closes the agent; the client socket is
// closed here.
func startClient(t *testing.T, opts Options) (*FakeAgent, *nsdp.Client) {
	t.Helper()
	agent := Start(t, opts)
	c, err := agent.DialClient()
	if err != nil {
		t.Fatalf("nsdptest: dial client: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return agent, c
}

// --- Scenario assertions ---------------------------------------------------
//
// Each helper is transport-agnostic: the UDP tests below and the
// in-memory transport test (memconn_test.go) share them.

// assertLoginFlow proves the V2 token math round-trips: the fake derives
// its expected token with the real nsdp.V2LoginToken over its own nonce and
// password, so a Login success means the client computed the identical
// token. The session must stay usable after the login SET rolled the
// fake's nonce: a later authenticated SET passes the refreshed-token
// check.
func assertLoginFlow(t *testing.T, agent *FakeAgent, c *nsdp.Client) {
	t.Helper()
	if err := c.Login(); err != nil {
		t.Fatalf("Login: %v", err)
	}
	name, err := c.GetSystemName()
	if err != nil {
		t.Fatalf("GetSystemName: %v", err)
	}
	if name != "GS108Ev3" {
		t.Fatalf("system name = %q, want %q", name, "GS108Ev3")
	}
	if err := c.SetSystemName("lab-sw"); err != nil {
		t.Fatalf("SetSystemName after login (rolled nonce): %v", err)
	}
	name, err = c.GetSystemName()
	if err != nil {
		t.Fatalf("GetSystemName after set: %v", err)
	}
	if name != "lab-sw" {
		t.Fatalf("read-back name = %q, want %q", name, "lab-sw")
	}
}

// assertAuthFailKnob pins the AuthFail knob: the login token is rejected
// the way the real switch rejects a bad one — status 0x0d, failing tag
// 0x001A — surfacing as *nsdp.ErrStatus whose ExpectedAuth is the honest
// V2 token for the fake's current nonce and its own password.
func assertAuthFailKnob(t *testing.T, agent *FakeAgent, c *nsdp.Client) {
	t.Helper()
	agent.AuthFail = true
	defer func() { agent.AuthFail = false }()
	err := c.Login()
	var es *nsdp.ErrStatus
	if !errors.As(err, &es) {
		t.Fatalf("Login error = %T (%v), want *nsdp.ErrStatus", err, err)
	}
	if es.Status != 0x0d || es.FailingTag != 0x001a {
		t.Fatalf("ErrStatus = status 0x%02x failing tag 0x%04x, want status 0x0d failing tag 0x001a", es.Status, es.FailingTag)
	}
	pw := make([]byte, 20)
	copy(pw, agent.Password())
	want := nsdp.V2LoginToken(agent.Nonce(), agent.MAC(), pw)
	if !bytes.Equal(es.ExpectedAuth, want) {
		t.Fatalf("ExpectedAuth = % x, want the honest V2 token % x", es.ExpectedAuth, want)
	}
}

// assertFactoryBlocks reads every scripted block through the client and
// pins the factory-fresh GS108Ev3 decodings: 0x9400 {admin=1, flow=0},
// 0x0c00 zeros, 0x3800 priority Low(4), the three 5-byte bandwidth tables with no
// limit, mirroring off, QoS port-based, unknown-multicast blocking off,
// the default VLAN tables, and PVID 1 on every port.
func assertFactoryBlocks(t *testing.T, _ *FakeAgent, c *nsdp.Client) {
	t.Helper()
	admin, err := c.GetBlock(0x94, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x94: %v", err)
	}
	adminEntries, ok := admin[0].Decoded.([]nsdp.PortAdminStatusEntry)
	if !ok || len(adminEntries) != 8 {
		t.Fatalf("0x9400 decoded = %#v, want 8 PortAdminStatusEntry", admin[0].Decoded)
	}
	for i, e := range adminEntries {
		if e.Port != byte(i+1) || e.Admin != 1 || e.Flow != 0 {
			t.Fatalf("0x9400 entry %d = %+v, want {port %d, admin 1, flow 0}", i, e, i+1)
		}
	}

	speed, err := c.GetBlock(0x0c, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x0c: %v", err)
	}
	speedEntries, ok := speed[0].Decoded.([]nsdp.SpeedLinkStatus)
	if !ok || len(speedEntries) != 8 {
		t.Fatalf("0x0c00 decoded = %#v, want 8 SpeedLinkStatus", speed[0].Decoded)
	}
	for i, e := range speedEntries {
		if e.Port != byte(i+1) || e.Speed != 0 || e.Flow != 0 {
			t.Fatalf("0x0c00 entry %d = %+v, want {port %d, 0, 0}", i, e, i+1)
		}
	}

	qos, err := c.GetBlock(0x38, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x38: %v", err)
	}
	qosEntries, ok := qos[0].Decoded.([]nsdp.PortQoSEntry)
	if !ok || len(qosEntries) != 8 {
		t.Fatalf("0x3800 decoded = %#v, want 8 PortQoSEntry", qos[0].Decoded)
	}
	for i, e := range qosEntries {
		if e.Port != byte(i+1) || e.Priority != nsdp.QoSPriority(4) {
			t.Fatalf("0x3800 entry %d = %+v, want {port %d, Low(4)}", i, e, i+1)
		}
	}

	for _, tc := range []struct {
		block byte
		tag   uint16
	}{
		{0x4c, nsdp.TagIngressRate},
		{0x50, nsdp.TagEgressRate},
		{0x58, nsdp.TagBroadcastStormRate},
	} {
		attrs, err := c.GetBlock(tc.block, nil)
		if err != nil {
			t.Fatalf("GetBlock 0x%02x: %v", tc.block, err)
		}
		if len(attrs) != 8 {
			t.Fatalf("block 0x%02x00 returned %d TLVs, want 8 (one per port)", tc.block, len(attrs))
		}
		for i, attr := range attrs {
			if attr.Tag != tc.tag {
				t.Fatalf("block 0x%02x00 TLV %d tag = 0x%04x, want 0x%04x", tc.block, i, attr.Tag, tc.tag)
			}
			e, ok := attr.Decoded.(nsdp.BandwidthEntry)
			if !ok {
				t.Fatalf("block 0x%02x00 TLV %d decoded = %#v, want BandwidthEntry", tc.block, i, attr.Decoded)
			}
			if e.Port != byte(i+1) || e.Limit != 0 {
				t.Fatalf("block 0x%02x00 entry %d = %+v, want {port %d, limit 0}", tc.block, i, e, i+1)
			}
		}
	}

	mirror, err := c.GetBlock(0x5c, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x5c: %v", err)
	}
	if m, ok := mirror[0].Decoded.(nsdp.PortMirrorConfig); !ok || m != (nsdp.PortMirrorConfig{DstPort: 0, Reserved: 0, SrcPorts: 0}) {
		t.Fatalf("0x5c00 decoded = %#v, want mirroring off", mirror[0].Decoded)
	}

	qosMode, err := c.GetBlock(0x34, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x34: %v", err)
	}
	if m, ok := qosMode[0].Decoded.(nsdp.QoSMode); !ok || m != nsdp.QoSModePortBased {
		t.Fatalf("0x3400 decoded = %#v, want QoSModePortBased", qosMode[0].Decoded)
	}

	mcast, err := c.GetBlock(0x6c, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x6c: %v", err)
	}
	if b, ok := mcast[0].Decoded.(byte); !ok || b != 0 {
		t.Fatalf("0x6c00 decoded = %#v, want 0 (blocking off)", mcast[0].Decoded)
	}

	pv, err := c.GetBlock(0x24, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x24: %v", err)
	}
	pvEntries, ok := pv[0].Decoded.([]nsdp.PortBasedVLANEntry)
	if !ok || len(pvEntries) != 1 || pvEntries[0] != (nsdp.PortBasedVLANEntry{VLANID: 1, Ports: 0xff}) {
		t.Fatalf("0x2400 decoded = %#v, want the single default VLAN {1, 0xff}", pv[0].Decoded)
	}

	vq, err := c.GetBlock(0x28, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x28: %v", err)
	}
	if len(vq) != 1 || !bytes.Equal(vq[0].Value, []byte{0x00, 0x01, 0xff, 0x00}) {
		t.Fatalf("0x2800 = %d TLVs, first value % x, want one entry {vlan 1, member 0xff, tagged 0x00} under the ROUND 19 wire model", len(vq), vq[0].Value)
	}

	pvid, err := c.GetBlock(0x30, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x30: %v", err)
	}
	pvidEntries, ok := pvid[0].Decoded.([]nsdp.PVIDEntry)
	if !ok || len(pvidEntries) != 8 {
		t.Fatalf("0x3000 decoded = %#v, want 8 PVIDEntry", pvid[0].Decoded)
	}
	for i, e := range pvidEntries {
		if e.Port != byte(i+1) || e.VLANID != 1 {
			t.Fatalf("0x3000 entry %d = %+v, want {port %d, vlan 1}", i, e, i+1)
		}
	}
}

// assertPortConfigReadBack mutates state through the client and reads it
// back: SetPortConfig must land BOTH bytes of the {port, admin, flow}
// payload on the target port only, and the 0x0c00 third byte must mirror
// the flow byte.
func assertPortConfigReadBack(t *testing.T, agent *FakeAgent, c *nsdp.Client) {
	t.Helper()
	if err := c.SetPortConfig(6, true, true); err != nil {
		t.Fatalf("SetPortConfig(6, admin on, flow on): %v", err)
	}
	admin, err := c.GetBlock(0x94, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x94: %v", err)
	}
	entries := admin[0].Decoded.([]nsdp.PortAdminStatusEntry)
	if entries[5].Admin != 1 || entries[5].Flow != 1 {
		t.Fatalf("port 6 admin = %+v, want {admin 1, flow 1}", entries[5])
	}
	for i, e := range entries {
		if i != 5 && (e.Admin != 1 || e.Flow != 0) {
			t.Fatalf("port %d admin = %+v, want {admin 1, flow 0} (untouched)", i+1, e)
		}
	}
	speed, err := c.GetBlock(0x0c, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x0c: %v", err)
	}
	sl := speed[0].Decoded.([]nsdp.SpeedLinkStatus)
	if sl[5].Flow != 1 {
		t.Fatalf("port 6 speed/link = %+v, want flow 1 (mirrors the 0x9400 flow byte)", sl[5])
	}
	state := agent.PortAdminStatus()
	if state[5].Admin != 1 || state[5].Flow != 1 {
		t.Fatalf("agent state port 6 = %+v, want {admin 1, flow 1}", state[5])
	}
	// A second SET flipping only the admin byte: flow must land as
	// written (0), proving both payload bytes round-trip independently.
	if err := c.SetPortConfig(6, false, false); err != nil {
		t.Fatalf("SetPortConfig(6, admin off, flow off): %v", err)
	}
	admin, err = c.GetBlock(0x94, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x94 (2nd): %v", err)
	}
	entries = admin[0].Decoded.([]nsdp.PortAdminStatusEntry)
	if entries[5].Admin != 0 || entries[5].Flow != 0 {
		t.Fatalf("port 6 admin after 2nd SET = %+v, want {admin 0, flow 0}", entries[5])
	}
}

// assertReplyLossScenario pins the live reply-loss quirk: the SET is
// applied but never answered, so the client reports ErrNoReply — yet the
// verify GET shows the applied value (the change DID land).
func assertReplyLossScenario(t *testing.T, agent *FakeAgent, c *nsdp.Client) {
	t.Helper()
	if err := c.Login(); err != nil { // ensure a session before dropping replies
		t.Fatalf("Login: %v", err)
	}
	agent.DropSetReplies = true
	defer func() { agent.DropSetReplies = false }()
	err := c.SetIngressRate(4, nsdp.Bandwidth1M)
	if !errors.Is(err, nsdp.ErrNoReply) {
		t.Fatalf("SetIngressRate error = %v, want ErrNoReply (dropped SET reply)", err)
	}
	attrs, err := c.GetBlock(0x4c, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x4c: %v", err)
	}
	e, ok := attrs[3].Decoded.(nsdp.BandwidthEntry)
	if !ok || e.Port != 4 || e.Limit != uint16(nsdp.Bandwidth1M) {
		t.Fatalf("port 4 ingress after dropped-reply SET = %#v, want {port 4, limit %d}", attrs[3].Decoded, nsdp.Bandwidth1M)
	}
	if got := agent.IngressRates()[3]; got.Limit != uint16(nsdp.Bandwidth1M) {
		t.Fatalf("agent state port 4 ingress = %+v, want limit %d", got, nsdp.Bandwidth1M)
	}
}

// assertSilentNoOpScenario pins the silent no-op quirk: the SET ACKs
// status 0x00 (client sees success) but the value is NOT applied — the
// verify GET still shows the old one.
func assertSilentNoOpScenario(t *testing.T, agent *FakeAgent, c *nsdp.Client) {
	t.Helper()
	if err := c.Login(); err != nil { // ensure a session before silencing SETs
		t.Fatalf("Login: %v", err)
	}
	agent.IgnoreSets = true
	defer func() { agent.IgnoreSets = false }()
	if err := c.SetQoSMode(nsdp.QoSMode8021p); err != nil {
		t.Fatalf("SetQoSMode: %v (want the ACKed no-op to succeed)", err)
	}
	attrs, err := c.GetBlock(0x34, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x34: %v", err)
	}
	if m, ok := attrs[0].Decoded.(nsdp.QoSMode); !ok || m != nsdp.QoSModePortBased {
		t.Fatalf("qos mode after no-op SET = %#v, want the old QoSModePortBased", attrs[0].Decoded)
	}
	if agent.QoSMode() != nsdp.QoSModePortBased {
		t.Fatalf("agent qos mode = %v, want QoSModePortBased (not applied)", agent.QoSMode())
	}
}

// assertVLANTables exercises the two VLAN SET paths: the port-based entry
// updates in place keyed by VLAN id, and the 802.1Q SET value is parsed
// into the logical per-VLAN Tagged/Untagged sets under the ROUND 19
// member/tagged wire model.
func assertVLANTables(t *testing.T, agent *FakeAgent, c *nsdp.Client) {
	t.Helper()
	if err := c.SetPortBasedVLAN(1, []int{1, 2, 3}); err != nil {
		t.Fatalf("SetPortBasedVLAN: %v", err)
	}
	if err := c.Set8021QVLAN(10, []int{1, 2}, []int{3}); err != nil {
		t.Fatalf("Set8021QVLAN: %v", err)
	}
	pv, err := c.GetBlock(0x24, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x24: %v", err)
	}
	pvEntries := pv[0].Decoded.([]nsdp.PortBasedVLANEntry)
	if len(pvEntries) != 1 || pvEntries[0].VLANID != 1 || pvEntries[0].Ports != 0xe0 {
		t.Fatalf("port-based VLAN table = %#v, want VLAN 1 updated to bitmap 0xe0", pvEntries)
	}
	vq, err := c.GetBlock(0x28, nil)
	if err != nil {
		t.Fatalf("GetBlock 0x28: %v", err)
	}
	if len(vq) != 2 { // default VLAN 1 + the new VLAN 10
		t.Fatalf("802.1q table = %d TLVs, want 2", len(vq))
	}
	if !bytes.Equal(vq[1].Value, []byte{0x00, 0x0a, 0xe0, 0xc0}) {
		t.Fatalf("802.1q VLAN 10 entry = % x, want {vlan 10, member 0xe0, tagged 0xc0} under the ROUND 19 wire model", vq[1].Value)
	}
	stored := agent.VLAN8021Q()
	if len(stored) != 2 || stored[1] != (VLAN8021QEntry{VLANID: 10, Tagged: 0xc0, Untagged: 0x20}) {
		t.Fatalf("agent 802.1q state = %#v, want VLAN 10 {Tagged 0xc0, Untagged 0x20} as the logical parsed sets", stored)
	}
}

// assert8021QRoundTrip exercises the typed table surfaces: the
// Set8021QVLAN/Get8021QVLANs round-trip (ROUND 19 member/tagged wire
// model), the SetPVID/GetPVIDs round-trip, Delete8021QVLAN, and the
// live-proven idempotent re-delete. The probe shape mirrors nsdp-gaps.sh
// stage 2 (asymmetric membership: port 3 tagged, port 5 untagged on
// VLAN 999). Ends with the table back at factory state.
func assert8021QRoundTrip(t *testing.T, agent *FakeAgent, c *nsdp.Client) {
	t.Helper()
	if err := c.Set8021QVLAN(999, []int{3}, []int{5}); err != nil {
		t.Fatalf("Set8021QVLAN(999, [3], [5]): %v", err)
	}
	table, err := c.Get8021QVLANs()
	if err != nil {
		t.Fatalf("Get8021QVLANs: %v", err)
	}
	var m *nsdp.VLAN8021QMembership
	for i := range table {
		if table[i].VLANID == 999 {
			m = &table[i]
		}
	}
	if m == nil {
		t.Fatalf("VLAN 999 missing from the 802.1q table: %+v", table)
	}
	if m.Tagged != nsdp.PortBitmap([]int{3}) || m.Untagged != nsdp.PortBitmap([]int{5}) {
		t.Fatalf("VLAN 999 = %+v, want {Tagged 0x20, Untagged 0x08} (GAP-1 default roles)", *m)
	}
	if tp := m.TaggedPorts(); len(tp) != 1 || tp[0] != 3 {
		t.Fatalf("TaggedPorts() = %v, want [3]", tp)
	}
	if up := m.UntaggedPorts(); len(up) != 1 || up[0] != 5 {
		t.Fatalf("UntaggedPorts() = %v, want [5]", up)
	}
	for _, e := range table {
		if e.VLANID == 1 && (e.Tagged != 0x00 || e.Untagged != 0xff) {
			t.Fatalf("factory VLAN 1 = %+v, want untouched {Tagged 0x00, Untagged 0xff}", e)
		}
	}
	if got := nsdp.NewVLAN8021QMembership(999, m.TaggedPorts(), m.UntaggedPorts()); got != *m {
		t.Fatalf("membership helper round-trip = %+v, want %+v", got, *m)
	}

	// Delete + the live-proven idempotent re-delete of a missing VLAN.
	if err := c.Delete8021QVLAN(999); err != nil {
		t.Fatalf("Delete8021QVLAN(999): %v", err)
	}
	if err := c.Delete8021QVLAN(999); err != nil {
		t.Fatalf("Delete8021QVLAN(999) re-delete (idempotent no-op): %v", err)
	}
	table, err = c.Get8021QVLANs()
	if err != nil {
		t.Fatalf("Get8021QVLANs after delete: %v", err)
	}
	for _, e := range table {
		if e.VLANID == 999 {
			t.Fatalf("802.1q table after delete still carries VLAN 999: %+v", table)
		}
		if e.VLANID == 1 && (e.Tagged != 0x00 || e.Untagged != 0xff) {
			t.Fatalf("factory VLAN 1 = %+v after delete, want untouched {Tagged 0x00, Untagged 0xff}", e)
		}
	}

	// PVID round-trip: set port 3 -> 999, read back, restore factory 1.
	if err := c.SetPVID(3, 999); err != nil {
		t.Fatalf("SetPVID(3, 999): %v", err)
	}
	pvids, err := c.GetPVIDs()
	if err != nil {
		t.Fatalf("GetPVIDs: %v", err)
	}
	if len(pvids) != 8 {
		t.Fatalf("GetPVIDs returned %d entries, want 8 (one per port)", len(pvids))
	}
	var p3 *nsdp.PVIDEntry
	for i := range pvids {
		if pvids[i].Port == 3 {
			p3 = &pvids[i]
		}
	}
	if p3 == nil || p3.VLANID != 999 {
		t.Fatalf("port 3 PVID after SetPVID = %+v, want {port 3, vlan 999}", p3)
	}
	if err := c.SetPVID(3, 1); err != nil {
		t.Fatalf("SetPVID(3, 1) restore: %v", err)
	}
	pvids, err = c.GetPVIDs()
	if err != nil {
		t.Fatalf("GetPVIDs after restore: %v", err)
	}
	for _, e := range pvids {
		if e.Port == 3 && e.VLANID != 1 {
			t.Fatalf("port 3 PVID after restore = %+v, want vlan 1", e)
		}
	}
}

// assertMembershipDropVisibility replays the REAL firmware behavior
// observed on the casalta GS108Ev3 (ROUND 19, 2026-09-12): with the
// fake's Reply8021QMembershipDropped knob set, a 0x2800 SET replies OK
// but the VLAN is stored with EMPTY membership — so Get8021QVLANs
// reports a membership that DISAGREES with what was written.
//
// CONTRACT: a verify-corrective layer built on this surface converts
// that disagreement into a typed drift error — the silent membership
// drop can never masquerade as a successful apply, because the
// readback visibly contradicts the write. Ends with the knob cleared
// and VLAN 999 gone.
func assertMembershipDropVisibility(t *testing.T, agent *FakeAgent, c *nsdp.Client) {
	t.Helper()
	agent.Reply8021QMembershipDropped = true
	defer func() { agent.Reply8021QMembershipDropped = false }()

	// The corrected stage-2 probe shape: members {3,5}, tagged {3}.
	if err := c.Set8021QVLAN(999, []int{3}, []int{5}); err != nil {
		t.Fatalf("Set8021QVLAN(999, [3], [5]) under the drop knob: %v", err)
	}
	table, err := c.Get8021QVLANs()
	if err != nil {
		t.Fatalf("Get8021QVLANs (dropped membership): %v", err)
	}
	var m *nsdp.VLAN8021QMembership
	for i := range table {
		if table[i].VLANID == 999 {
			m = &table[i]
		}
	}
	if m == nil {
		t.Fatalf("VLAN 999 missing from the dropped-membership read: %+v", table)
	}
	// WROTE Tagged={3} (0x20), Untagged={5} (0x08); the drop must report
	// the VLAN present but EMPTY — the disagreement is the observable
	// signal a drift detector needs.
	if m.Tagged != 0x00 || m.Untagged != 0x00 {
		t.Fatalf("dropped-membership read = %+v, want VLAN 999 present with empty membership (Tagged 0x00, Untagged 0x00)", *m)
	}
	// The stored state holds the dropped (empty) entry — exactly what
	// the real switch kept: the VLAN id, minus the membership.
	stored := agent.VLAN8021Q()
	var s *VLAN8021QEntry
	for i := range stored {
		if stored[i].VLANID == 999 {
			s = &stored[i]
		}
	}
	if s == nil || s.Tagged != 0x00 || s.Untagged != 0x00 {
		t.Fatalf("agent stored state = %+v, want VLAN 999 stored empty (id kept, membership dropped)", stored)
	}

	// Knob cleared: the SET lands as written again (recovery).
	agent.Reply8021QMembershipDropped = false
	if err := c.Set8021QVLAN(999, []int{3}, []int{5}); err != nil {
		t.Fatalf("Set8021QVLAN(999, [3], [5]) after knob cleared: %v", err)
	}
	table, err = c.Get8021QVLANs()
	if err != nil {
		t.Fatalf("Get8021QVLANs (knob cleared): %v", err)
	}
	for i := range table {
		if table[i].VLANID == 999 {
			m = &table[i]
		}
	}
	if m == nil || m.Tagged != nsdp.PortBitmap([]int{3}) || m.Untagged != nsdp.PortBitmap([]int{5}) {
		t.Fatalf("VLAN 999 after knob cleared = %+v, want the written membership back (Tagged 0x20, Untagged 0x08)", table)
	}
	if err := c.Delete8021QVLAN(999); err != nil {
		t.Fatalf("Delete8021QVLAN(999) cleanup: %v", err)
	}
}

// assertIdentity reads the identity surface end-to-end against the
// agent's scripted strings: the multi-tag GET must decode product name,
// model code, firmware and system name, and the block-0x78 serial read
// must parse and trim the 21-byte blob. want carries the expected
// identity; its SerialNumber AND SystemName fields are overwritten from
// the agent — the single source of truth (earlier scenario asserts may
// have renamed the switch under the shared in-memory session).
func assertIdentity(t *testing.T, agent *FakeAgent, c *nsdp.Client, want nsdp.SwitchIdentity) {
	t.Helper()
	want.SerialNumber = agent.SerialNumber()
	want.SystemName = agent.SystemName()
	id, err := c.GetIdentity()
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if id != want {
		t.Fatalf("GetIdentity = %+v, want %+v", id, want)
	}
}

// --- UDP-transport tests (the deliverable suite) ---------------------------
//
// These run the client and the fake agent over real loopback UDP sockets.
// NOTE: development sandboxes that deny loopback network sends fail these
// with EPERM ("sendto: operation not permitted") — that is the sandbox,
// not the code: the identical scenario logic also runs over the in-memory
// transport in memconn_test.go, and the UDP suite passes on machines where
// loopback is permitted.

func TestLoginSuccess(t *testing.T) {
	agent, c := startClient(t, Options{Password: "hunter2"})
	assertLoginFlow(t, agent, c)
}

func TestLoginAuthFail(t *testing.T) {
	agent, c := startClient(t, Options{})
	assertAuthFailKnob(t, agent, c)
}

// TestLoginWrongPassword drives the raw seam directly (no DialClient): a
// client built with nsdp.NewClientWithConn over its own loopback socket
// and the WRONG password must be rejected with the auth-mismatch reply,
// whose ExpectedAuth carries the token for the SWITCH's password and the
// nonce the client fetched (no roll: the login SET failed).
func TestLoginWrongPassword(t *testing.T) {
	agent := Start(t, Options{Password: "right-pw"})
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind client socket: %v", err)
	}
	defer conn.Close()
	c, err := nsdp.NewClientWithConn(conn, agent.MAC(), agent.Addr(), "wrong-pw")
	if err != nil {
		t.Fatalf("NewClientWithConn: %v", err)
	}
	err = c.Login()
	var es *nsdp.ErrStatus
	if !errors.As(err, &es) {
		t.Fatalf("Login error = %T (%v), want *nsdp.ErrStatus", err, err)
	}
	if es.Status != 0x0d || es.FailingTag != 0x001a {
		t.Fatalf("ErrStatus = status 0x%02x failing tag 0x%04x, want status 0x0d failing tag 0x001a", es.Status, es.FailingTag)
	}
	// ExpectedAuth = the token for the switch's own password under the
	// nonce the client fetched in the login handshake.
	pw := make([]byte, 20)
	copy(pw, "right-pw")
	want := nsdp.V2LoginToken(agent.Nonce(), agent.MAC(), pw)
	if !bytes.Equal(es.ExpectedAuth, want) {
		t.Fatalf("ExpectedAuth = % x, want token for the switch password % x", es.ExpectedAuth, want)
	}
}

func TestGetBlockFactoryState(t *testing.T) {
	agent, c := startClient(t, Options{})
	assertFactoryBlocks(t, agent, c)
}

func TestSetPortConfigReadBack(t *testing.T) {
	agent, c := startClient(t, Options{Password: "hunter2"})
	assertPortConfigReadBack(t, agent, c)
}

func TestSetReplyLossScenario(t *testing.T) {
	agent, c := startClient(t, Options{Password: "hunter2"})
	assertReplyLossScenario(t, agent, c)
}

func TestSetSilentNoOpScenario(t *testing.T) {
	agent, c := startClient(t, Options{Password: "hunter2"})
	assertSilentNoOpScenario(t, agent, c)
}

func TestSetVLANTables(t *testing.T) {
	agent, c := startClient(t, Options{Password: "hunter2"})
	assertVLANTables(t, agent, c)
}

func Test8021QVLANRoundTrip(t *testing.T) {
	agent, c := startClient(t, Options{Password: "hunter2"})
	assert8021QRoundTrip(t, agent, c)
}

func Test8021QMembershipDropVisibility(t *testing.T) {
	agent, c := startClient(t, Options{Password: "hunter2"})
	assertMembershipDropVisibility(t, agent, c)
}

// TestIdentityReadBack scripts a full identity and reads it back over
// pure NSDP GETs — the switch-data-source surface.
func TestIdentityReadBack(t *testing.T) {
	agent, c := startClient(t, Options{
		Password:     "hunter2",
		ProductName:  "GS108Ev3",
		ModelCode:    0x000a,
		Firmware1:    "9.9.9",
		SerialNumber: "UH77B5R033EE",
	})
	assertIdentity(t, agent, c, nsdp.SwitchIdentity{
		ProductName:     "GS108Ev3",
		ModelCode:       0x000a,
		FirmwareVersion: "9.9.9",
		SystemName:      "GS108Ev3", // factory
	})
}

// TestIdentityFirmwareFallback: with tag 0x000d answered EMPTY (via the
// raw Attrs escape hatch, which overrides the seeded identity), the
// firmware version must fall back to tag 0x000e.
func TestIdentityFirmwareFallback(t *testing.T) {
	agent, c := startClient(t, Options{
		Firmware2: "7.7.7",
		Attrs:     map[byte][]byte{byte(nsdp.TagFirmware1): {}},
	})
	assertIdentity(t, agent, c, nsdp.SwitchIdentity{
		ProductName:     "GS108Ev3",
		ModelCode:       0x0100,
		FirmwareVersion: "7.7.7", // 0x000d empty -> 0x000e
		SystemName:      "GS108Ev3",
	})
}
