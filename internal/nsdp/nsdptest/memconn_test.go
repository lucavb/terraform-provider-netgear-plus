package nsdptest

import (
	"testing"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// In-memory session helpers: the scenario assertions of agent_test.go
// run against BOTH transports — loopback UDP there, the in-memory
// memConn here — so the FakeAgent's protocol logic is verified even on
// machines whose sandbox denies loopback sends, and the real socket
// path is verified where loopback is permitted. (memConn itself lives
// in memconn.go alongside the exported MemConnPair/StartOverConn.)

// startMemSession starts the fake agent over one end of an in-memory conn
// pair and returns it with a client dialed to it over the other end.
func startMemSession(t *testing.T, opts Options) (*FakeAgent, *nsdp.Client) {
	t.Helper()
	return startMemSessionWait(t, opts, 0)
}

// startMemSessionWait is startMemSession with an optional shrunken
// response window (nsdp.WithWait): failure-path scenarios burn the
// retry schedule against a silent block, and the 800ms default would
// cost 14 × 800ms per silent request.
func startMemSessionWait(t *testing.T, opts Options, wait time.Duration) (*FakeAgent, *nsdp.Client) {
	t.Helper()
	mac := opts.MAC
	if mac == nil {
		mac = defaultAgentMAC
	}
	password := opts.Password
	if password == "" {
		password = "password"
	}
	agentConn, clientConn := memConnPair()
	agent := newAgentOverConn(agentConn, mac, password, opts)
	go agent.serve()
	t.Cleanup(func() {
		agent.Close()
		clientConn.Close()
	})
	clientOpts := []nsdp.ClientOption{}
	if wait > 0 {
		clientOpts = append(clientOpts, nsdp.WithWait(wait))
	}
	c, err := nsdp.NewClientWithConn(clientConn, agent.MAC(), agent.Addr(), password, clientOpts...)
	if err != nil {
		t.Fatalf("nsdptest: NewClientWithConn: %v", err)
	}
	return agent, c
}

// TestFakeAgentProtocolInMemory walks the full scenario surface over the
// in-memory transport: login + token refresh, the AuthFail rejection with
// the honest ExpectedAuth, every scripted factory block, the port-status
// SET→read-back, the reply-loss and silent-no-op quirks, the VLAN
// tables, the typed 802.1Q/PVID round-trips, the GAP-1 role-mismatch
// visibility, and the identity read. (Mirrors the UDP suite; see
// agent_test.go for the per-scenario docs.)
func TestFakeAgentProtocolInMemory(t *testing.T) {
	agent, c := startMemSession(t, Options{Password: "hunter2"})

	assertLoginFlow(t, agent, c)
	assertAuthFailKnob(t, agent, c)
	assertFactoryBlocks(t, agent, c)
	assertPortConfigReadBack(t, agent, c)
	assertReplyLossScenario(t, agent, c)
	assertSilentNoOpScenario(t, agent, c)
	assertVLANTables(t, agent, c)
	assert8021QRoundTrip(t, agent, c)
	assertMembershipDropVisibility(t, agent, c)
	assertIdentity(t, agent, c, nsdp.SwitchIdentity{
		ProductName:     "GS108Ev3",
		ModelCode:       0x0100,
		FirmwareVersion: "V2.06.24",
		SystemName:      "GS108Ev3", // factory default identity values
	})
}

// TestScriptedTablesAndSilentBlockInMemory walks the Options per-port
// table scripting (including the block-0x10 traffic statistics, which
// have no wire SET path) and the SilentBlock knob over the in-memory
// transport — the sandbox-proof counterpart of the UDP entries in
// agent_test.go (same assertions, same docs).
func TestScriptedTablesAndSilentBlockInMemory(t *testing.T) {
	agent, c := startMemSessionWait(t, scriptedTablesOptions(), 5*time.Millisecond)
	assertScriptedPerPortTables(t, agent, c)
	assertSilentBlockKnob(t, agent, c)
}
