package provider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// newNSDPSelectedTestData returns a providerData whose transport
// selection is NSDP (agent_mac set, no host) — the dual-transport
// resources run over nsdpSwitchTransport against the given fake.
func newNSDPSelectedTestData(fake *fakeSwitch) *providerData {
	data := newPortConfigTestData(fake) // agentMAC + nsdpFactory, no host
	data.config.Host = ""
	return data
}

// newHTTPSelectedTestData returns a providerData whose transport
// selection is HTTP (host set, no agent_mac). The HTTP driver is the
// stubDriver test double, not the NSDP fake.
func newHTTPSelectedTestData() *providerData {
	return &providerData{
		config: client.Config{Host: "http://192.0.2.10:80", RequestSpacing: time.Millisecond},
		driverFactory: func(client.Config) (client.Driver, error) {
			return &stubDriver{}, nil
		},
	}
}

// ---------------------------------------------------------------------------
// Identity mapping (ReadSwitchFacts over NSDP)
// ---------------------------------------------------------------------------

func TestNSDPSwitchTransportReadSwitchFactsMapsIdentity(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	transport := nsdpSwitchTransport{client: fake, agentMAC: "8c:3b:ad:25:1b:88"}

	facts, err := transport.ReadSwitchFacts(context.Background())
	if err != nil {
		t.Fatalf("ReadSwitchFacts() error = %v", err)
	}

	if got, want := facts.Model, "GS108Ev3"; got != want {
		t.Fatalf("facts.Model = %q, want the reported product name %q", got, want)
	}
	if got, want := facts.SwitchName, "fake"; got != want {
		t.Fatalf("facts.SwitchName = %q, want the system name %q", got, want)
	}
	if got, want := facts.SerialNumber, "UH77B5R033EE"; got != want {
		t.Fatalf("facts.SerialNumber = %q, want %q", got, want)
	}
	if got, want := facts.MACAddress, "8c:3b:ad:25:1b:88"; got != want {
		t.Fatalf("facts.MACAddress = %q, want the configured agent_mac %q", got, want)
	}
	if got, want := facts.FirmwareVersion, "V2.06.24"; got != want {
		t.Fatalf("facts.FirmwareVersion = %q, want %q", got, want)
	}

	// No NSDP source: bootloader is documented absent, host does not
	// exist over NSDP. Both must be empty, never invented.
	if facts.BootloaderVersion != "" {
		t.Fatalf("facts.BootloaderVersion = %q, want empty (no NSDP source)", facts.BootloaderVersion)
	}
	if facts.Host != "" {
		t.Fatalf("facts.Host = %q, want empty (NSDP has no host notion)", facts.Host)
	}
}

func TestNSDPSwitchTransportReadSwitchFactsRequiresSerial(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.serialNumber = "" // identity answered without a serial
	transport := nsdpSwitchTransport{client: fake, agentMAC: "8c:3b:ad:25:1b:88"}

	if _, err := transport.ReadSwitchFacts(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "serial number") {
		t.Fatalf("ReadSwitchFacts() without a serial error = %v, want typed serial error (mirrors the HTTP path)", err)
	}
}

func TestNSDPSwitchTransportReadSwitchFactsCarriesNoEngineModeGuard(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.engineMode = 1 // port-based mode: identity GETs must still work
	transport := nsdpSwitchTransport{client: fake, agentMAC: "8c:3b:ad:25:1b:88"}

	if _, err := transport.ReadSwitchFacts(context.Background()); err != nil {
		t.Fatalf("identity reads are harmless GETs in every engine mode, error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// VLAN state decode (ReadVLANState over NSDP)
// ---------------------------------------------------------------------------

// factory8021QState is the NSDP wire shape of a factory-fresh switch in
// an 802.1Q engine mode: VLAN 1 untagged everywhere, PVID 1 per port.
func factory8021QState() model.VLANState {
	return model.VLANState{
		PortCount: 8,
		VLANs: map[int]model.Vlan{
			1: {ID: 1, Ports: map[int]model.PortMembership{
				1: model.PortMembershipUntagged, 2: model.PortMembershipUntagged,
				3: model.PortMembershipUntagged, 4: model.PortMembershipUntagged,
				5: model.PortMembershipUntagged, 6: model.PortMembershipUntagged,
				7: model.PortMembershipUntagged, 8: model.PortMembershipUntagged,
			}},
		},
		PVIDs: map[int]int{1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1},
	}
}

func TestNSDPSwitchTransportReadVLANStateDecodesTable(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.engineMode = 3
	fake.vlan8021Q = []nsdp.VLAN8021QMembership{
		{VLANID: 1, Tagged: 0x00, Untagged: 0xff},
		{VLANID: 999, Tagged: nsdp.PortBitmap([]int{3}), Untagged: nsdp.PortBitmap([]int{5})},
	}
	fake.pvid[3] = 999

	transport := nsdpSwitchTransport{client: fake, agentMAC: "8c:3b:ad:25:1b:88"}
	state, err := transport.ReadVLANState(context.Background())
	if err != nil {
		t.Fatalf("ReadVLANState() error = %v", err)
	}

	if got, want := state.VLANs[999].Ports[3], model.PortMembershipTagged; got != want {
		t.Fatalf("VLAN 999 port 3 = %s, want tagged", got)
	}
	if got, want := state.VLANs[999].Ports[5], model.PortMembershipUntagged; got != want {
		t.Fatalf("VLAN 999 port 5 = %s, want untagged", got)
	}
	if got, want := state.VLANs[999].Ports[1], model.PortMembershipIgnored; got != want {
		t.Fatalf("VLAN 999 port 1 (in neither bitmap) = %s, want ignored", got)
	}
	if got, want := state.PVIDs[3], 999; got != want {
		t.Fatalf("port 3 PVID = %d, want 999", got)
	}
	if got, want := state.PVIDs[4], 1; got != want {
		t.Fatalf("port 4 PVID = %d, want 1", got)
	}

	// Mirror of the HTTP shape: normalized, all 8 ports present per VLAN.
	if got, want := len(state.VLANs[999].Ports), 8; got != want {
		t.Fatalf("VLAN 999 carries %d port entries, want %d (normalized)", got, want)
	}
}

func TestNSDPSwitchTransportReadVLANStateRejectsBothBitmaps(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.engineMode = 3
	fake.vlan8021Q = []nsdp.VLAN8021QMembership{
		{VLANID: 1, Tagged: 0x00, Untagged: 0xff},
		{VLANID: 999, Tagged: 0x08, Untagged: 0x08}, // port 3 in BOTH roles: invalid wire state
	}

	transport := nsdpSwitchTransport{client: fake, agentMAC: "8c:3b:ad:25:1b:88"}
	_, err := transport.ReadVLANState(context.Background())
	if err == nil || !strings.Contains(err.Error(), "both the tagged and untagged bitmaps") {
		t.Fatalf("ReadVLANState(both bitmaps) error = %v, want typed both-bitmaps error (never a silent pick)", err)
	}
}

func TestNSDPSwitchTransportReadVLANStateRejectsShortPVIDTable(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.engineMode = 3
	fake.pvidTableOverride = []nsdp.PVIDEntry{ // 7 entries: one port missing
		{Port: 1, VLANID: 1}, {Port: 2, VLANID: 1}, {Port: 3, VLANID: 1},
		{Port: 4, VLANID: 1}, {Port: 5, VLANID: 1}, {Port: 6, VLANID: 1},
		{Port: 7, VLANID: 1},
	}

	transport := nsdpSwitchTransport{client: fake, agentMAC: "8c:3b:ad:25:1b:88"}
	_, err := transport.ReadVLANState(context.Background())
	if err == nil || !strings.Contains(err.Error(), "7 entries, want exactly 8") {
		t.Fatalf("ReadVLANState(short PVID table) error = %v, want typed short-table error (never a silent default)", err)
	}
}

func TestNSDPSwitchTransportReadVLANStateRejectsOutOfRangePVIDPort(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.engineMode = 3
	fake.pvidTableOverride = []nsdp.PVIDEntry{
		{Port: 1, VLANID: 1}, {Port: 2, VLANID: 1}, {Port: 3, VLANID: 1},
		{Port: 4, VLANID: 1}, {Port: 5, VLANID: 1}, {Port: 6, VLANID: 1},
		{Port: 7, VLANID: 1}, {Port: 9, VLANID: 1}, // out of range
	}

	transport := nsdpSwitchTransport{client: fake, agentMAC: "8c:3b:ad:25:1b:88"}
	_, err := transport.ReadVLANState(context.Background())
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("ReadVLANState(out-of-range PVID port) error = %v, want typed range error", err)
	}
}

// ---------------------------------------------------------------------------
// Engine-mode guard (802.1Q path, roles reversed vs. port_based_vlan)
// ---------------------------------------------------------------------------

func TestNSDPSwitchTransportEngineModeGuard(t *testing.T) {
	t.Parallel()

	for _, mode := range []nsdp.VLANEngineMode{0, 1, 2} {
		fake := newFakeSwitch()
		fake.engineMode = mode
		transport := nsdpSwitchTransport{client: fake, agentMAC: "8c:3b:ad:25:1b:88"}

		_, err := transport.ReadVLANState(context.Background())
		if err == nil {
			t.Fatalf("engine mode %d: ReadVLANState must refuse", byte(mode))
		}

		var opErr *providerOperationError
		if !asProviderOperationError(err, &opErr) || opErr.summary != "Refusing to manage 802.1Q VLAN state over NSDP" {
			t.Fatalf("engine mode %d: error should be the typed refusal, got %v", byte(mode), err)
		}
		if !strings.Contains(opErr.detail, "netgear_plus_port_based_vlan") {
			t.Fatalf("engine mode %d: refusal should point at netgear_plus_port_based_vlan, got: %s", byte(mode), opErr.detail)
		}
		if len(fake.calls) != 0 {
			t.Fatalf("engine mode %d: refusal must send zero SETs, got %v", byte(mode), fake.callStrings())
		}
	}

	for _, mode := range []nsdp.VLANEngineMode{3, 4} {
		fake := newFakeSwitch()
		fake.engineMode = mode
		transport := nsdpSwitchTransport{client: fake, agentMAC: "8c:3b:ad:25:1b:88"}

		if _, err := transport.ReadVLANState(context.Background()); err != nil {
			t.Fatalf("engine mode %d (802.1q): ReadVLANState must be allowed, error = %v", byte(mode), err)
		}
	}
}

func asProviderOperationError(err error, target **providerOperationError) bool {
	opErr, ok := err.(*providerOperationError)
	if !ok {
		return false
	}
	*target = opErr
	return true
}

// ---------------------------------------------------------------------------
// Transport selection (withSwitchTransport)
// ---------------------------------------------------------------------------

func TestSwitchTransportSelectionHostOnlyUsesHTTP(t *testing.T) {
	t.Parallel()

	data := newHTTPSelectedTestData()

	err := withSwitchTransport(context.Background(), data, func(transport switchTransport) error {
		if _, ok := transport.(httpSwitchTransport); !ok {
			t.Fatalf("host-only selection must yield httpSwitchTransport, got %T", transport)
		}
		if got, want := transport.ResourceID(), "gs108ev3@192.0.2.10"; got != want {
			t.Fatalf("HTTP resource ID = %q, want %q", got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withSwitchTransport(host only) error = %v", err)
	}
}

func TestSwitchTransportSelectionAgentMACOnlyUsesNSDP(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.engineMode = 3
	data := newNSDPSelectedTestData(fake)

	err := withSwitchTransport(context.Background(), data, func(transport switchTransport) error {
		if _, ok := transport.(nsdpSwitchTransport); !ok {
			t.Fatalf("agent_mac-only selection must yield nsdpSwitchTransport, got %T", transport)
		}
		if got, want := transport.ResourceID(), "nsdp@8c:3b:ad:25:1b:88"; got != want {
			t.Fatalf("NSDP resource ID = %q, want %q", got, want)
		}
		// The transport is fully functional through the fake.
		if _, err := transport.ReadVLANState(context.Background()); err != nil {
			t.Fatalf("ReadVLANState through the selected NSDP transport failed: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withSwitchTransport(agent_mac only) error = %v", err)
	}
}

func TestSwitchTransportSelectionBothPrefersNSDP(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.engineMode = 3
	data := newNSDPSelectedTestData(fake)
	data.config.Host = "http://192.0.2.10:80" // both configured

	err := withSwitchTransport(context.Background(), data, func(transport switchTransport) error {
		if _, ok := transport.(nsdpSwitchTransport); !ok {
			t.Fatalf("both set must prefer nsdpSwitchTransport, got %T", transport)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withSwitchTransport(both) error = %v", err)
	}
}

func TestSwitchTransportSelectionNeitherKeepsHistoricalError(t *testing.T) {
	t.Parallel()

	data := &providerData{config: client.Config{RequestSpacing: time.Millisecond}}

	err := withSwitchTransport(context.Background(), data, func(switchTransport) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "HTTP resources require the provider attribute host") {
		t.Fatalf("neither-set selection error = %v, want the historical host error", err)
	}
}
