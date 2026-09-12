package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// ---------------------------------------------------------------------------
// Fake switch: a method-level NSDP switch implementing the nsdpClient
// interface. It carries live per-port state (factory defaults unless
// mutated), scripts block GET results, records every SET call, and exposes
// the wire quirks the resource must survive: lost SET replies
// (DropSetReplies — the SET applies but the reply never arrives), silent
// no-ops (IgnoreSets — the SET is accepted but the state never mutates),
// and auth rejections (AuthFailOnSet — status 0x0d).
// ---------------------------------------------------------------------------

type fakeSwitchCall struct {
	Method string // "SetPortConfig" | "SetQoSPriority" | "SetIngressRate" | "SetEgressRate" | "SetQoSMode" | "SetBlockUnknownMulticast" | "SetPortMirroring" | "SetPortBasedVLAN"
	Port   int
	Admin  bool // SetPortConfig target admin value
	Flow   bool // SetPortConfig target flow value
	QoS    nsdp.QoSPriority
	Rate   nsdp.BandwidthLimit

	// Switch settings / port-based VLAN SETs.
	Mode      nsdp.QoSMode // SetQoSMode
	Blocked   bool         // SetBlockUnknownMulticast
	MirrorDst int          // SetPortMirroring destination port (0 = disabled)
	MirrorSrc []int        // SetPortMirroring sorted source ports
	VLANID    int          // SetPortBasedVLAN / Set8021QVLAN / Delete8021QVLAN
	VLANPorts []int        // SetPortBasedVLAN sorted ports
	Tagged    []int        // Set8021QVLAN sorted tagged ports
	Untagged  []int        // Set8021QVLAN sorted untagged ports
	// SetPVID reuses Port + VLANID.
}

func (c fakeSwitchCall) String() string {
	switch c.Method {
	case "SetPortConfig":
		return fmt.Sprintf("SetPortConfig(port=%d, admin=%t, flow=%t)", c.Port, c.Admin, c.Flow)
	case "SetQoSPriority":
		return fmt.Sprintf("SetQoSPriority(port=%d, priority=%d)", c.Port, c.QoS)
	case "SetIngressRate":
		return fmt.Sprintf("SetIngressRate(port=%d, limit=%d)", c.Port, c.Rate)
	case "SetEgressRate":
		return fmt.Sprintf("SetEgressRate(port=%d, limit=%d)", c.Port, c.Rate)
	case "SetQoSMode":
		return fmt.Sprintf("SetQoSMode(mode=%d)", byte(c.Mode))
	case "SetBlockUnknownMulticast":
		return fmt.Sprintf("SetBlockUnknownMulticast(blocked=%t)", c.Blocked)
	case "SetPortMirroring":
		return fmt.Sprintf("SetPortMirroring(dst=%d, src=%v)", c.MirrorDst, c.MirrorSrc)
	case "SetPortBasedVLAN":
		return fmt.Sprintf("SetPortBasedVLAN(vlan=%d, ports=%v)", c.VLANID, c.VLANPorts)
	case "Set8021QVLAN":
		return fmt.Sprintf("Set8021QVLAN(vlan=%d, tagged=%v, untagged=%v)", c.VLANID, c.Tagged, c.Untagged)
	case "Delete8021QVLAN":
		return fmt.Sprintf("Delete8021QVLAN(vlan=%d)", c.VLANID)
	case "SetPVID":
		return fmt.Sprintf("SetPVID(port=%d, vlan=%d)", c.Port, c.VLANID)
	}
	return fmt.Sprintf("%s(port=%d)", c.Method, c.Port)
}

type fakeSwitch struct {
	// Live per-port state, indexed 1..8 (index 0 unused).
	admin   [9]bool
	flow    [9]bool
	qos     [9]nsdp.QoSPriority
	ingress [9]nsdp.BandwidthLimit
	egress  [9]nsdp.BandwidthLimit

	// Live global switch settings state.
	qosMode               nsdp.QoSMode
	blockUnknownMulticast bool
	mirrorDst             int   // 0 = mirroring disabled
	mirrorSrcPorts        []int // sorted; empty when mirroring disabled

	// Live VLAN engine mode (knob for the port-based VLAN guard) and
	// port-based VLAN table (vlan id → sorted ports).
	engineMode nsdp.VLANEngineMode
	pbvlans    map[int][]int

	// Live 802.1Q VLAN table (block 0x28) and PVID table (block 0x30),
	// stored in wire form: one membership per VLAN, PVID per port
	// (indexed 1..8, index 0 unused). Defaults mirror the factory:
	// VLAN 1 untagged on all ports, PVID 1 everywhere.
	vlan8021Q []nsdp.VLAN8021QMembership
	pvid      [9]int

	// Live identity (GETs only, no login), mirroring nsdptest's
	// lab-plausible defaults.
	productName  string
	modelCode    uint16
	firmware     string
	serialNumber string
	systemName   string

	// Reply8021QMembershipDropped mirrors nsdptest's knob: a 0x2800 SET
	// replies OK but the VLAN is stored with EMPTY membership —
	// replaying the real firmware behavior observed on the casalta
	// GS108Ev3 (ROUND 19, 2026-09-12: a SET whose tagged bits are not
	// a subset of its member bits is silently dropped, membership and
	// all, reply OK).
	Reply8021QMembershipDropped bool

	// pvidTableOverride, when non-nil, makes GetPVIDs return exactly
	// this (short/corrupt tables for typed-error tests).
	pvidTableOverride []nsdp.PVIDEntry

	// Every SET invocation, in order.
	calls []fakeSwitchCall

	// Knobs.
	IgnoreSets     bool         // SETs "succeed" but state never mutates (silent no-op)
	DropSetReplies map[int]bool // 1-based SET call number → reply lost, state still mutates
	AuthFailOnSet  bool         // every SET returns auth status 0x0d, state never mutates
	GetBlockErr    error        // every GetBlock fails with this error
}

func newFakeSwitch() *fakeSwitch {
	f := &fakeSwitch{
		DropSetReplies: make(map[int]bool),
	}
	f.resetFactoryDefaults()
	return f
}

// resetFactoryDefaults mirrors the factory: admin enabled, flow off, QoS
// low (4), no rate limits (0), QoS mode port-based, unknown multicast not
// blocked, mirroring disabled, VLAN engine port-based, port-based VLAN
// table = {VLAN 1 → all 8 ports} — on all 8 ports.
func (f *fakeSwitch) resetFactoryDefaults() {
	for port := 1; port <= 8; port++ {
		f.admin[port] = true
		f.flow[port] = false
		f.qos[port] = 4
		f.ingress[port] = nsdp.BandwidthNone
		f.egress[port] = nsdp.BandwidthNone
	}
	f.qosMode = nsdp.QoSModePortBased
	f.blockUnknownMulticast = false
	f.mirrorDst = 0
	f.mirrorSrcPorts = nil
	f.engineMode = 1 // nsdp.VLANEngineMode port-based
	f.pbvlans = map[int][]int{1: {1, 2, 3, 4, 5, 6, 7, 8}}
	f.vlan8021Q = []nsdp.VLAN8021QMembership{{VLANID: 1, Tagged: 0x00, Untagged: 0xff}}
	for port := 1; port <= 8; port++ {
		f.pvid[port] = 1
	}
	f.productName = "GS108Ev3"
	f.modelCode = 0x0100
	f.firmware = "V2.06.24"
	f.serialNumber = "UH77B5R033EE"
	f.systemName = "fake"
	f.Reply8021QMembershipDropped = false
	f.pvidTableOverride = nil
}

func (f *fakeSwitch) record(call fakeSwitchCall) {
	f.calls = append(f.calls, call)
}

// setReplyOutcome answers whether the just-recorded SET earned an error
// return, honoring the reply-loss and auth knobs.
func (f *fakeSwitch) setReplyOutcome(callNumber int) error {
	if f.AuthFailOnSet {
		return &nsdp.ErrStatus{Status: nsdpStatusAuthFailure, FailingTag: nsdpAuthTagV2, Source: "SET"}
	}
	if f.DropSetReplies[callNumber] {
		return fmt.Errorf("set raw tag: no response to SET request: %w", nsdp.ErrNoReply)
	}
	return nil
}

func (f *fakeSwitch) Close() error                 { return nil }
func (f *fakeSwitch) Login() error                 { return nil }
func (f *fakeSwitch) GetAttr(byte) ([]byte, error) { return nil, nil }
func (f *fakeSwitch) GetAttrs(...byte) (map[byte][]byte, error) {
	return nil, nil
}
func (f *fakeSwitch) GetSystemName() (string, error) { return "fake", nil }
func (f *fakeSwitch) SetSystemName(string) error     { return nil }
func (f *fakeSwitch) SetRaw(uint16, []byte) error    { return nil }

func (f *fakeSwitch) GetBlock(blockID byte, _ []byte) ([]nsdp.Attr, error) {
	if f.GetBlockErr != nil {
		return nil, f.GetBlockErr
	}

	switch blockID {
	case nsdpBlockPortConfig:
		// Live shape: one whole-table Attr decoding to the entry slice.
		entries := make([]nsdp.PortAdminStatusEntry, 0, 8)
		for port := 1; port <= 8; port++ {
			admin, flow := byte(0), byte(0)
			if f.admin[port] {
				admin = 1
			}
			if f.flow[port] {
				flow = 1
			}
			entries = append(entries, nsdp.PortAdminStatusEntry{Port: byte(port), Admin: admin, Flow: flow})
		}
		return []nsdp.Attr{{Tag: nsdp.TagPortAdminStatus, Name: "port admin status", Decoded: entries}}, nil
	case nsdpBlockPortQoS:
		entries := make([]nsdp.PortQoSEntry, 0, 8)
		for port := 1; port <= 8; port++ {
			entries = append(entries, nsdp.PortQoSEntry{Port: byte(port), Priority: f.qos[port]})
		}
		return []nsdp.Attr{{Tag: nsdp.TagPortBasedQoS, Name: "port based qos (per port)", Decoded: entries}}, nil
	case nsdpBlockIngressRate, nsdpBlockEgressRate:
		// Live shape: ONE 5-byte TLV per port — one Attr per entry.
		attrs := make([]nsdp.Attr, 0, 8)
		tag := nsdp.TagIngressRate
		if blockID == nsdpBlockEgressRate {
			tag = nsdp.TagEgressRate
		}
		for port := 1; port <= 8; port++ {
			limit := f.ingress[port]
			if blockID == nsdpBlockEgressRate {
				limit = f.egress[port]
			}
			attrs = append(attrs, nsdp.Attr{
				Tag:  tag,
				Name: "rate limit (per port)",
				Decoded: nsdp.BandwidthEntry{
					Port:  byte(port),
					Limit: uint16(limit),
				},
			})
		}
		return attrs, nil
	case nsdpBlockQoSMode:
		// Tagged scalar enum in the switch settings file.
		return []nsdp.Attr{{Tag: nsdp.TagQoSMode, Name: "qos mode", Decoded: f.qosMode}}, nil
	case nsdpBlockUnknownMulticast:
		blocked := byte(0)
		if f.blockUnknownMulticast {
			blocked = 1
		}
		return []nsdp.Attr{{Tag: nsdp.TagBlockUnknownMulticast, Name: "block unknown multicast", Decoded: blocked}}, nil
	case nsdpBlockPortMirroring:
		return []nsdp.Attr{{Tag: nsdp.TagPortMirroring, Name: "port mirroring", Decoded: nsdp.PortMirrorConfig{
			DstPort:  byte(f.mirrorDst),
			Reserved: 0,
			SrcPorts: nsdp.PortBitmap(f.mirrorSrcPorts),
		}}}, nil
	case nsdpBlockVLANEngineMode:
		return []nsdp.Attr{{Tag: nsdp.TagVLANEngineMode, Name: "vlan engine mode", Decoded: f.engineMode}}, nil
	case nsdpBlockPortBasedVLAN:
		// Live shape: one 3-byte entry per TLV — one Attr per VLAN.
		ids := make([]int, 0, len(f.pbvlans))
		for id := range f.pbvlans {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		attrs := make([]nsdp.Attr, 0, len(ids))
		for _, id := range ids {
			attrs = append(attrs, nsdp.Attr{
				Tag:  nsdp.TagPortBasedVLAN,
				Name: "port based vlan",
				Decoded: []nsdp.PortBasedVLANEntry{
					{VLANID: uint16(id), Ports: nsdp.PortBitmap(f.pbvlans[id])},
				},
			})
		}
		return attrs, nil
	}

	return nil, fmt.Errorf("fakeSwitch: unsupported block 0x%02x00", blockID)
}

func (f *fakeSwitch) SetPortConfig(port int, admin, flow bool) error {
	f.record(fakeSwitchCall{Method: "SetPortConfig", Port: port, Admin: admin, Flow: flow})
	if !f.IgnoreSets && !f.AuthFailOnSet {
		f.admin[port], f.flow[port] = admin, flow
	}
	return f.setReplyOutcome(len(f.calls))
}

func (f *fakeSwitch) SetQoSPriority(port int, priority nsdp.QoSPriority) error {
	f.record(fakeSwitchCall{Method: "SetQoSPriority", Port: port, QoS: priority})
	if !f.IgnoreSets && !f.AuthFailOnSet {
		f.qos[port] = priority
	}
	return f.setReplyOutcome(len(f.calls))
}

func (f *fakeSwitch) SetIngressRate(port int, limit nsdp.BandwidthLimit) error {
	f.record(fakeSwitchCall{Method: "SetIngressRate", Port: port, Rate: limit})
	if !f.IgnoreSets && !f.AuthFailOnSet {
		f.ingress[port] = limit
	}
	return f.setReplyOutcome(len(f.calls))
}

func (f *fakeSwitch) SetEgressRate(port int, limit nsdp.BandwidthLimit) error {
	f.record(fakeSwitchCall{Method: "SetEgressRate", Port: port, Rate: limit})
	if !f.IgnoreSets && !f.AuthFailOnSet {
		f.egress[port] = limit
	}
	return f.setReplyOutcome(len(f.calls))
}

func (f *fakeSwitch) SetQoSMode(mode nsdp.QoSMode) error {
	f.record(fakeSwitchCall{Method: "SetQoSMode", Mode: mode})
	if !f.IgnoreSets && !f.AuthFailOnSet {
		f.qosMode = mode
	}
	return f.setReplyOutcome(len(f.calls))
}

func (f *fakeSwitch) SetBlockUnknownMulticast(blocked bool) error {
	f.record(fakeSwitchCall{Method: "SetBlockUnknownMulticast", Blocked: blocked})
	if !f.IgnoreSets && !f.AuthFailOnSet {
		f.blockUnknownMulticast = blocked
	}
	return f.setReplyOutcome(len(f.calls))
}

func (f *fakeSwitch) SetPortMirroring(destPort int, srcPorts []int) error {
	f.record(fakeSwitchCall{Method: "SetPortMirroring", MirrorDst: destPort, MirrorSrc: sortedIntPorts(srcPorts)})
	if !f.IgnoreSets && !f.AuthFailOnSet {
		f.mirrorDst = destPort
		f.mirrorSrcPorts = sortedIntPorts(srcPorts)
	}
	return f.setReplyOutcome(len(f.calls))
}

func (f *fakeSwitch) SetPortBasedVLAN(vlanID int, ports []int) error {
	f.record(fakeSwitchCall{Method: "SetPortBasedVLAN", VLANID: vlanID, VLANPorts: sortedIntPorts(ports)})
	if !f.IgnoreSets && !f.AuthFailOnSet {
		f.pbvlans[vlanID] = sortedIntPorts(ports)
	}
	return f.setReplyOutcome(len(f.calls))
}

// Get8021QVLANs reports the stored table (the logical Tagged/Untagged
// sets, decoded and re-encoded by the library under the ROUND 19
// member/tagged wire model).
func (f *fakeSwitch) Get8021QVLANs() ([]nsdp.VLAN8021QMembership, error) {
	if f.GetBlockErr != nil {
		return nil, f.GetBlockErr
	}
	out := make([]nsdp.VLAN8021QMembership, 0, len(f.vlan8021Q))
	out = append(out, f.vlan8021Q...)
	return out, nil
}

func (f *fakeSwitch) GetPVIDs() ([]nsdp.PVIDEntry, error) {
	if f.GetBlockErr != nil {
		return nil, f.GetBlockErr
	}
	if f.pvidTableOverride != nil {
		return append([]nsdp.PVIDEntry(nil), f.pvidTableOverride...), nil
	}
	out := make([]nsdp.PVIDEntry, 0, 8)
	for port := 1; port <= 8; port++ {
		out = append(out, nsdp.PVIDEntry{Port: byte(port), VLANID: uint16(f.pvid[port])})
	}
	return out, nil
}

func (f *fakeSwitch) GetIdentity() (nsdp.SwitchIdentity, error) {
	if f.GetBlockErr != nil {
		return nsdp.SwitchIdentity{}, f.GetBlockErr
	}
	return nsdp.SwitchIdentity{
		ProductName:     f.productName,
		ModelCode:       f.modelCode,
		FirmwareVersion: f.firmware,
		SerialNumber:    f.serialNumber,
		SystemName:      f.systemName,
	}, nil
}

func (f *fakeSwitch) Set8021QVLAN(vlanID int, taggedPorts, untaggedPorts []int) error {
	f.record(fakeSwitchCall{
		Method:   "Set8021QVLAN",
		VLANID:   vlanID,
		Tagged:   sortedIntPorts(taggedPorts),
		Untagged: sortedIntPorts(untaggedPorts),
	})
	if !f.IgnoreSets && !f.AuthFailOnSet {
		membership := nsdp.NewVLAN8021QMembership(vlanID, taggedPorts, untaggedPorts)
		if f.Reply8021QMembershipDropped {
			// Replay the live-observed firmware behavior (casalta,
			// ROUND 19, 2026-09-12): reply OK but store the VLAN with
			// EMPTY membership.
			membership.Tagged, membership.Untagged = 0, 0
		}
		replaced := false
		for i := range f.vlan8021Q {
			if int(f.vlan8021Q[i].VLANID) == vlanID {
				f.vlan8021Q[i] = membership
				replaced = true
				break
			}
		}
		if !replaced {
			f.vlan8021Q = append(f.vlan8021Q, membership)
		}
	}
	return f.setReplyOutcome(len(f.calls))
}

func (f *fakeSwitch) Delete8021QVLAN(vlanID int) error {
	f.record(fakeSwitchCall{Method: "Delete8021QVLAN", VLANID: vlanID})
	if !f.IgnoreSets && !f.AuthFailOnSet {
		for i := range f.vlan8021Q {
			if int(f.vlan8021Q[i].VLANID) == vlanID {
				f.vlan8021Q = append(f.vlan8021Q[:i], f.vlan8021Q[i+1:]...)
				break
			}
		}
	}
	return f.setReplyOutcome(len(f.calls))
}

func (f *fakeSwitch) SetPVID(port, vlanID int) error {
	f.record(fakeSwitchCall{Method: "SetPVID", Port: port, VLANID: vlanID})
	if !f.IgnoreSets && !f.AuthFailOnSet {
		f.pvid[port] = vlanID
	}
	return f.setReplyOutcome(len(f.calls))
}

func (f *fakeSwitch) callStrings() []string {
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.String())
	}
	return out
}

// sortedIntPorts returns a sorted copy of ports (the recorded/mutated
// state always renders port lists in one canonical order).
func sortedIntPorts(ports []int) []int {
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)
	return sorted
}

// ---------------------------------------------------------------------------
// Direct-drive helpers: hand-built framework Plan/State values, so the CRUD
// methods run without Terraform core (mirroring providerConfigureRequest).
// ---------------------------------------------------------------------------

func newPortConfigTestData(fake *fakeSwitch) *providerData {
	return &providerData{
		config:    client.Config{Password: "secret", RequestSpacing: time.Millisecond},
		agentMAC:  "8c:3b:ad:25:1b:88",
		deviceKey: "8c:3b:ad:25:1b:88",
		nsdpFactory: func(nsdp.Options) (nsdpClient, error) {
			return fake, nil
		},
	}
}

func portConfigSchema(t *testing.T) rschema.Schema {
	t.Helper()

	var resp resource.SchemaResponse
	(&portConfigResource{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if diags := resp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatalf("schema validation returned errors: %v", diags)
	}
	return resp.Schema
}

func portConfigRawValue(t *testing.T, schema rschema.Schema, model portConfigResourceModel) tftypes.Value {
	t.Helper()

	var value attr.Value
	if diags := tfsdk.ValueFrom(context.Background(), model, schema.Type(), &value); diags.HasError() {
		t.Fatalf("tfsdk.ValueFrom(model) failed: %v", diags)
	}
	raw, err := value.ToTerraformValue(context.Background())
	if err != nil {
		t.Fatalf("ToTerraformValue() error = %v", err)
	}
	return raw
}

func portConfigTestPlan(t *testing.T, ports []portConfigPortModel) tfsdk.Plan {
	t.Helper()

	schema := portConfigSchema(t)
	model := portConfigResourceModel{ID: types.StringNull(), Ports: ports}
	return tfsdk.Plan{Raw: portConfigRawValue(t, schema, model), Schema: schema}
}

func portConfigTestState(t *testing.T, model portConfigResourceModel) tfsdk.State {
	t.Helper()

	schema := portConfigSchema(t)
	return tfsdk.State{Raw: portConfigRawValue(t, schema, model), Schema: schema}
}

func statePortConfigModel(t *testing.T, state tfsdk.State) portConfigResourceModel {
	t.Helper()

	var model portConfigResourceModel
	if diags := state.Get(context.Background(), &model); diags.HasError() {
		t.Fatalf("reading state into model failed: %v", diags)
	}
	return model
}

// factoryDefaultPortModels returns the 8-entry all-defaults plan (factory
// values spelled out, as Terraform would after applying schema defaults).
func factoryDefaultPortModels() []portConfigPortModel {
	ports := make([]portConfigPortModel, 0, portConfigPortCount)
	for port := 1; port <= portConfigPortCount; port++ {
		ports = append(ports, portConfigPortModel{
			Port:        types.Int64Value(int64(port)),
			Enabled:     types.BoolValue(defaultPortEnabled),
			FlowControl: types.BoolValue(defaultPortFlowControl),
			QoSPriority: types.StringValue(defaultPortQoSPriority),
			IngressRate: types.StringValue(defaultPortRateLimit),
			EgressRate:  types.StringValue(defaultPortRateLimit),
		})
	}
	return ports
}

func createPortConfig(t *testing.T, data *providerData, ports []portConfigPortModel) resource.CreateResponse {
	t.Helper()

	r := &portConfigResource{}
	r.data = data
	plan := portConfigTestPlan(t, ports)
	req := resource.CreateRequest{Plan: plan}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: plan.Schema}}
	r.Create(context.Background(), req, &resp)
	return resp
}

func updatePortConfig(t *testing.T, data *providerData, ports []portConfigPortModel, prior portConfigResourceModel) resource.UpdateResponse {
	t.Helper()

	r := &portConfigResource{}
	r.data = data
	plan := portConfigTestPlan(t, ports)
	req := resource.UpdateRequest{
		Config: tfsdk.Config{Raw: plan.Raw, Schema: plan.Schema},
		Plan:   plan,
		State:  portConfigTestState(t, prior),
	}
	resp := resource.UpdateResponse{State: tfsdk.State{Schema: plan.Schema}}
	r.Update(context.Background(), req, &resp)
	return resp
}

func hasWarningWithSummary(diags diag.Diagnostics, wantSummary string) bool {
	for _, d := range diags {
		if d.Severity() == diag.SeverityWarning && d.Summary() == wantSummary {
			return true
		}
	}
	return false
}

func diagnosticsDetailText(diags diag.Diagnostics) string {
	var sb strings.Builder
	for _, d := range diags {
		sb.WriteString(d.Summary())
		sb.WriteString(" ")
		sb.WriteString(d.Detail())
		sb.WriteString(" ")
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Schema and expand validation
// ---------------------------------------------------------------------------

func TestPortConfigSchemaShape(t *testing.T) {
	t.Parallel()

	schema := portConfigSchema(t)

	if _, ok := schema.Attributes["id"]; !ok {
		t.Fatal("schema should expose computed id attribute")
	}
	block, ok := schema.Blocks["ports"]
	if !ok {
		t.Fatal("schema should expose ports block")
	}
	listBlock, ok := block.(rschema.ListNestedBlock)
	if !ok {
		t.Fatalf("ports block type = %T, want resource/schema.ListNestedBlock", block)
	}
	if len(listBlock.Validators) == 0 {
		t.Fatal("ports block must pin the exact entry count (8)")
	}

	nested := listBlock.NestedObject.Attributes
	for _, name := range []string{"port", "enabled", "flow_control", "qos_priority", "ingress_rate", "egress_rate"} {
		if _, ok := nested[name]; !ok {
			t.Fatalf("ports block should include %s attribute", name)
		}
	}

	port := nested["port"].(rschema.Int64Attribute)
	if !port.Required || len(port.Validators) == 0 {
		t.Fatal("port must be Required with a range validator")
	}
	enabled := nested["enabled"].(rschema.BoolAttribute)
	if enabled.Default == nil {
		t.Fatal("enabled must carry its factory default (true)")
	}
	flow := nested["flow_control"].(rschema.BoolAttribute)
	if flow.Default == nil {
		t.Fatal("flow_control must carry its factory default (false)")
	}
	qos := nested["qos_priority"].(rschema.StringAttribute)
	if qos.Default == nil || len(qos.Validators) == 0 {
		t.Fatal("qos_priority must carry its factory default and the OneOf validator")
	}
	ingress := nested["ingress_rate"].(rschema.StringAttribute)
	if ingress.Default == nil || len(ingress.Validators) == 0 {
		t.Fatal("ingress_rate must carry its factory default and the OneOf validator")
	}
	egress := nested["egress_rate"].(rschema.StringAttribute)
	if egress.Default == nil || len(egress.Validators) == 0 {
		t.Fatal("egress_rate must carry its factory default and the OneOf validator")
	}
}

func TestExpandPortConfigsRejectsIncompletePortSet(t *testing.T) {
	t.Parallel()

	seven := factoryDefaultPortModels()[:7]
	if _, err := expandPortConfigs(context.Background(), portConfigResourceModel{Ports: seven}); err == nil ||
		!strings.Contains(err.Error(), "missing port numbers [8]") {
		t.Fatalf("expandPortConfigs() with 7 entries error = %v, want missing port list", err)
	}

	dup := factoryDefaultPortModels()
	dup[3] = portConfigPortModel{ // index 3 becomes a second port 3 → port 4 goes missing
		Port:        types.Int64Value(3),
		Enabled:     types.BoolValue(true),
		FlowControl: types.BoolValue(false),
		QoSPriority: types.StringValue("low"),
		IngressRate: types.StringValue("none"),
		EgressRate:  types.StringValue("none"),
	}
	_, err := expandPortConfigs(context.Background(), portConfigResourceModel{Ports: dup})
	if err == nil {
		t.Fatal("expandPortConfigs() must reject a duplicated port number")
	}
	if !strings.Contains(err.Error(), "duplicated port numbers [3]") || !strings.Contains(err.Error(), "missing port numbers [4]") {
		t.Fatalf("expandPortConfigs() error should list duplicated and missing ports, got: %v", err)
	}
}

func TestExpandPortConfigsRejectsPortOutOfRange(t *testing.T) {
	t.Parallel()

	ports := factoryDefaultPortModels()
	ports[0] = portConfigPortModel{
		Port:        types.Int64Value(9),
		Enabled:     types.BoolValue(true),
		FlowControl: types.BoolValue(false),
		QoSPriority: types.StringValue("low"),
		IngressRate: types.StringValue("none"),
		EgressRate:  types.StringValue("none"),
	}
	if _, err := expandPortConfigs(context.Background(), portConfigResourceModel{Ports: ports}); err == nil ||
		!strings.Contains(err.Error(), "out of range") {
		t.Fatalf("expandPortConfigs() with port 9 error = %v, want out-of-range error", err)
	}
}

func TestExpandPortConfigsRejectsBadEnumValues(t *testing.T) {
	t.Parallel()

	qos := factoryDefaultPortModels()
	qos[4].QoSPriority = types.StringValue("urgent")
	if _, err := expandPortConfigs(context.Background(), portConfigResourceModel{Ports: qos}); err == nil ||
		!strings.Contains(err.Error(), "qos_priority") {
		t.Fatalf("expandPortConfigs() with bad qos error = %v, want qos_priority named", err)
	}

	ingress := factoryDefaultPortModels()
	ingress[6].IngressRate = types.StringValue("100m")
	if _, err := expandPortConfigs(context.Background(), portConfigResourceModel{Ports: ingress}); err == nil ||
		!strings.Contains(err.Error(), "ingress_rate") {
		t.Fatalf("expandPortConfigs() with bad ingress rate error = %v, want ingress_rate named", err)
	}

	egress := factoryDefaultPortModels()
	egress[7].EgressRate = types.StringValue("fast")
	if _, err := expandPortConfigs(context.Background(), portConfigResourceModel{Ports: egress}); err == nil ||
		!strings.Contains(err.Error(), "egress_rate") {
		t.Fatalf("expandPortConfigs() with bad egress rate error = %v, want egress_rate named", err)
	}
}

func TestExpandPortConfigsNormalizesNullDefaults(t *testing.T) {
	t.Parallel()

	ports := make([]portConfigPortModel, 0, portConfigPortCount)
	for port := 1; port <= portConfigPortCount; port++ {
		ports = append(ports, portConfigPortModel{
			Port: types.Int64Value(int64(port)),
			// Everything else null: expand must apply the factory
			// defaults the schema descriptions advertise.
		})
	}

	configs, err := expandPortConfigs(context.Background(), portConfigResourceModel{Ports: ports})
	if err != nil {
		t.Fatalf("expandPortConfigs() with null defaults error = %v", err)
	}
	for port := 1; port <= portConfigPortCount; port++ {
		cfg := configs[port]
		if !cfg.Enabled || cfg.FlowControl || cfg.QoSPriority != 4 ||
			cfg.IngressRate != nsdp.BandwidthNone || cfg.EgressRate != nsdp.BandwidthNone {
			t.Fatalf("port %d expanded to %+v, want factory defaults", port, cfg)
		}
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestPortConfigCreateFromFactoryPlanSendsNoSets(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)

	resp := createPortConfig(t, data, factoryDefaultPortModels())
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create against a factory-default switch failed: %v", resp.Diagnostics)
	}

	if len(fake.calls) != 0 {
		t.Fatalf("SET calls = %v, want none for an all-defaults plan", fake.callStrings())
	}
	if !hasWarningWithSummary(resp.Diagnostics, "Port configuration already in sync") {
		t.Fatalf("Create should warn that no SETs were needed, diags: %v", resp.Diagnostics)
	}

	model := statePortConfigModel(t, resp.State)
	if got, want := model.ID.ValueString(), "nsdp@8c:3b:ad:25:1b:88"; got != want {
		t.Fatalf("state id = %q, want %q", got, want)
	}
	if len(model.Ports) != portConfigPortCount {
		t.Fatalf("state ports = %d entries, want %d", len(model.Ports), portConfigPortCount)
	}
}

func TestPortConfigCreateSendsOnlyChangedSets(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)

	ports := factoryDefaultPortModels()
	ports[2].Enabled = types.BoolValue(false) // port 3: admin + flow both change
	ports[2].FlowControl = types.BoolValue(true)
	ports[4].QoSPriority = types.StringValue("high") // port 5
	ports[6].IngressRate = types.StringValue("1m")   // port 7
	ports[7].EgressRate = types.StringValue("512k")  // port 8

	resp := createPortConfig(t, data, ports)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create failed: %v", resp.Diagnostics)
	}

	want := []string{
		"SetPortConfig(port=3, admin=false, flow=true)",
		"SetQoSPriority(port=5, priority=1)",
		"SetIngressRate(port=7, limit=2)",
		"SetEgressRate(port=8, limit=1)",
	}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want %v", got, want)
	}

	// The final state reflects the verified device configuration.
	model := statePortConfigModel(t, resp.State)
	if model.Ports[2].Enabled.ValueBool() || !model.Ports[2].FlowControl.ValueBool() {
		t.Fatalf("port 3 state = enabled %t, flow %t; want disabled, flow on",
			model.Ports[2].Enabled.ValueBool(), model.Ports[2].FlowControl.ValueBool())
	}
	if got := model.Ports[4].QoSPriority.ValueString(); got != "high" {
		t.Fatalf("port 5 qos in state = %q, want high", got)
	}
	if got := model.Ports[6].IngressRate.ValueString(); got != "1m" {
		t.Fatalf("port 7 ingress in state = %q, want 1m", got)
	}
	if got := model.Ports[7].EgressRate.ValueString(); got != "512k" {
		t.Fatalf("port 8 egress in state = %q, want 512k", got)
	}
}

func TestPortConfigCreateToleratesLostSetReply(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.DropSetReplies[1] = true // first SET's reply is lost; the write still applies
	data := newPortConfigTestData(fake)

	ports := factoryDefaultPortModels()
	ports[1].FlowControl = types.BoolValue(true)       // port 2 → first SET
	ports[3].QoSPriority = types.StringValue("normal") // port 4 → second SET

	resp := createPortConfig(t, data, ports)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create must survive a lost SET reply: %v", resp.Diagnostics)
	}

	// Exactly the two planned SETs — the lost reply must never trigger a
	// re-send (read is truth; a re-send risks lockout strikes).
	want := []string{
		"SetPortConfig(port=2, admin=true, flow=true)",
		"SetQoSPriority(port=4, priority=3)",
	}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want %v (no re-send after lost reply)", got, want)
	}

	model := statePortConfigModel(t, resp.State)
	if !model.Ports[1].FlowControl.ValueBool() {
		t.Fatal("port 2 flow_control should be on in verified state")
	}
	if got := model.Ports[3].QoSPriority.ValueString(); got != "normal" {
		t.Fatalf("port 4 qos in state = %q, want normal", got)
	}
}

func TestPortConfigCreateFailsAfterIgnoredSets(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.IgnoreSets = true // SETs are accepted but silently never apply
	data := newPortConfigTestData(fake)

	ports := factoryDefaultPortModels()
	ports[4].QoSPriority = types.StringValue("high") // port 5

	resp := createPortConfig(t, data, ports)
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create must fail when the device silently ignores SETs")
	}

	// Initial SET + exactly ONE corrective pass, then the drift error.
	want := []string{
		"SetQoSPriority(port=5, priority=1)",
		"SetQoSPriority(port=5, priority=1)",
	}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want initial + one corrective pass %v", got, want)
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{"port 5", "qos_priority", "low (wanted high)"} {
		if !strings.Contains(text, want) {
			t.Fatalf("drift error should name %q, got: %q", want, text)
		}
	}
}

func TestPortConfigCreateAuthFailureNamesLockout(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.AuthFailOnSet = true
	data := newPortConfigTestData(fake)

	ports := factoryDefaultPortModels()
	ports[0].FlowControl = types.BoolValue(true) // port 1 → one change

	resp := createPortConfig(t, data, ports)
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create must fail on persistent NSDP auth failures")
	}

	// withNSDPClient retries exactly once with a fresh client (one
	// re-login attempt per operation, never more).
	if got := fake.callStrings(); len(got) != 2 {
		t.Fatalf("SET calls = %v, want exactly 2 (initial + one retry)", got)
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	for _, want := range []string{"password", "30-minute SET lockout", "re-apply"} {
		if !strings.Contains(text, want) {
			t.Fatalf("auth-failure diagnostic should mention %q, got: %q", want, text)
		}
	}
}

func TestPortConfigCreateRequiresAgentMAC(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)
	data.agentMAC = "" // provider configured without agent_mac
	data.deviceKey = canonicalHostKey("http://192.0.2.10")

	resp := createPortConfig(t, data, factoryDefaultPortModels())
	if !resp.Diagnostics.HasError() {
		t.Fatal("Create must fail when the provider lacks agent_mac")
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	if !strings.Contains(text, "NSDP resources require the provider attribute agent_mac") {
		t.Fatalf("error should name the missing provider attribute, got: %q", text)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("SET calls = %v, want none", fake.callStrings())
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func TestPortConfigReadReflectsDeviceDrift(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.flow[2] = true // port 2 flow control drifted on
	fake.qos[6] = 1     // port 6 QoS drifted to high
	data := newPortConfigTestData(fake)

	r := &portConfigResource{}
	r.data = data
	req := resource.ReadRequest{State: portConfigTestState(t, portConfigResourceModel{
		ID:    types.StringValue("nsdp@8c:3b:ad:25:1b:88"),
		Ports: factoryDefaultPortModels(),
	})}
	resp := resource.ReadResponse{State: tfsdk.State{Schema: portConfigSchema(t)}}
	r.Read(context.Background(), req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read failed: %v", resp.Diagnostics)
	}

	model := statePortConfigModel(t, resp.State)
	if !model.Ports[1].FlowControl.ValueBool() {
		t.Fatal("Read should surface port 2 flow_control=true drift into state")
	}
	if got := model.Ports[5].QoSPriority.ValueString(); got != "high" {
		t.Fatalf("port 6 qos in state = %q, want high", got)
	}
	if got, want := model.ID.ValueString(), "nsdp@8c:3b:ad:25:1b:88"; got != want {
		t.Fatalf("Read should preserve the state id, got %q want %q", got, want)
	}
}

func TestPortConfigReadSurfacesGetFailure(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.GetBlockErr = errors.New("no valid response after 14 attempts")
	data := newPortConfigTestData(fake)

	r := &portConfigResource{}
	r.data = data
	req := resource.ReadRequest{State: portConfigTestState(t, portConfigResourceModel{
		ID:    types.StringValue("nsdp@8c:3b:ad:25:1b:88"),
		Ports: factoryDefaultPortModels(),
	})}
	resp := resource.ReadResponse{State: tfsdk.State{Schema: portConfigSchema(t)}}
	r.Read(context.Background(), req, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("Read must fail when the block GETs fail")
	}

	text := diagnosticsDetailText(resp.Diagnostics)
	if !strings.Contains(text, "Read port configuration failed") {
		t.Fatalf("Read error should be clear about the failed read, got: %q", text)
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestPortConfigUpdateSendsOnlyChangedFields(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)

	prior := portConfigResourceModel{ID: types.StringValue("nsdp@8c:3b:ad:25:1b:88"), Ports: factoryDefaultPortModels()}

	ports := factoryDefaultPortModels()
	ports[3].QoSPriority = types.StringValue("high") // port 4: the only plan change

	resp := updatePortConfig(t, data, ports, prior)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update failed: %v", resp.Diagnostics)
	}

	want := []string{"SetQoSPriority(port=4, priority=1)"}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want only the changed port/field %v", got, want)
	}
}

func TestPortConfigUpdateIsAuthoritativeOverDeviceDrift(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	fake.flow[2] = true // port 2 drifted away from the managed config
	data := newPortConfigTestData(fake)

	prior := portConfigResourceModel{ID: types.StringValue("nsdp@8c:3b:ad:25:1b:88"), Ports: factoryDefaultPortModels()}

	ports := factoryDefaultPortModels()
	ports[3].QoSPriority = types.StringValue("normal") // port 4 plan change

	resp := updatePortConfig(t, data, ports, prior)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update failed: %v", resp.Diagnostics)
	}

	// The plan's port 4 change AND the out-of-band port 2 drift (the
	// table is authoritative) — nothing else.
	want := []string{
		"SetPortConfig(port=2, admin=true, flow=false)", // drift correction, port order first
		"SetQoSPriority(port=4, priority=3)",
	}
	if got := fake.callStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SET calls = %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestPortConfigDeleteIsStateOnly(t *testing.T) {
	t.Parallel()

	fake := newFakeSwitch()
	data := newPortConfigTestData(fake)

	r := &portConfigResource{}
	r.data = data
	req := resource.DeleteRequest{State: portConfigTestState(t, portConfigResourceModel{
		ID:    types.StringValue("nsdp@8c:3b:ad:25:1b:88"),
		Ports: factoryDefaultPortModels(),
	})}
	resp := resource.DeleteResponse{}
	r.Delete(context.Background(), req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Delete failed: %v", resp.Diagnostics)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("Delete must not write to the switch, SET calls = %v", fake.callStrings())
	}
	if !hasWarningWithSummary(resp.Diagnostics, "Delete leaves switch configuration unchanged") {
		t.Fatalf("Delete should warn that it is state-only, diags: %v", resp.Diagnostics)
	}
}

// ---------------------------------------------------------------------------
// TF_ACC-gated hardware acceptance skeleton.
//
// The repo has no terraform-plugin-testing dependency (no TF_ACC harness
// exists yet), so this drives the resource CRUD methods directly against
// real hardware, mirroring the unit-test direct-drive helpers. It is
// gated behind TF_ACC plus the NETGEAR_PLUS_AGENT_MAC / NETGEAR_PLUS_IFACE
// / NETGEAR_PLUS_PASSWORD environment variables and runs on a real switch
// only when those are set.
//
// The configuration is all factory defaults except port 3 (assumed to be a
// free port) with qos_priority changed to "normal", so a factory-fresh
// switch applies exactly one mild SET.
// ---------------------------------------------------------------------------

func TestAccPortConfigResource(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set: skipping NSDP hardware acceptance test")
	}
	agentMAC := normalizeAgentMAC(os.Getenv("NETGEAR_PLUS_AGENT_MAC"))
	password := os.Getenv("NETGEAR_PLUS_PASSWORD")
	ifaceName := os.Getenv("NETGEAR_PLUS_IFACE")
	if agentMAC == "" || password == "" {
		t.Skip("NETGEAR_PLUS_AGENT_MAC / NETGEAR_PLUS_PASSWORD not set: skipping NSDP hardware acceptance test")
	}

	ctx := context.Background()

	data := &providerData{
		config: client.Config{
			Password:       password,
			RequestSpacing: defaultRequestSpacing,
		},
		agentMAC:  agentMAC,
		ifaceName: ifaceName,
		deviceKey: agentMAC,
	}

	ports := factoryDefaultPortModels()
	ports[2].QoSPriority = types.StringValue("normal") // port 3: free port, mild change

	// Create: apply the near-factory plan.
	createResp := createPortConfig(t, data, ports)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("acceptance Create failed: %v", createResp.Diagnostics)
	}

	// Convergence: a second apply of the identical plan must send no SETs
	// (the "already in sync" warning proves the verify passed without a
	// corrective pass).
	convergeResp := createPortConfig(t, data, ports)
	if convergeResp.Diagnostics.HasError() {
		t.Fatalf("acceptance convergence apply failed: %v", convergeResp.Diagnostics)
	}
	if !hasWarningWithSummary(convergeResp.Diagnostics, "Port configuration already in sync") {
		t.Fatalf("second apply should be a no-op, diags: %v", convergeResp.Diagnostics)
	}

	// Update is the same authoritative apply; exercise it with the
	// identical plan (no further changes expected on hardware).
	prior := statePortConfigModel(t, createResp.State)
	updateResp := updatePortConfig(t, data, ports, prior)
	if updateResp.Diagnostics.HasError() {
		t.Fatalf("acceptance Update failed: %v", updateResp.Diagnostics)
	}

	// CheckDestroy equivalent: Delete is state-only — it must succeed with
	// the state-only warning and never write to the switch.
	r := &portConfigResource{}
	r.data = data
	delResp := resource.DeleteResponse{}
	r.Delete(ctx, resource.DeleteRequest{State: createResp.State}, &delResp)
	if delResp.Diagnostics.HasError() {
		t.Fatalf("acceptance Delete failed: %v", delResp.Diagnostics)
	}
	if !hasWarningWithSummary(delResp.Diagnostics, "Delete leaves switch configuration unchanged") {
		t.Fatalf("Delete should be state-only with a warning, diags: %v", delResp.Diagnostics)
	}
}
