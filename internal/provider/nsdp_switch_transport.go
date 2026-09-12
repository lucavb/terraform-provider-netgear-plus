package provider

import (
	"context"
	"fmt"
	"slices"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// ---------------------------------------------------------------------------
// nsdpSwitchTransport: the NSDP implementation of switchTransport.
//
// It runs the vlan_state resource family (netgear_plus_vlan_state, the
// switch and vlan_state data sources) over pure NSDP, building every
// switchTransport operation from the library surface: Get8021QVLANs +
// GetPVIDs (reads), Set8021QVLAN / Delete8021QVLAN / SetPVID (writes),
// GetIdentity (facts).
//
// GAP-1/GAP-2 PENDING (nsdp-gaps.sh live verdicts not yet recorded):
// the 802.1Q read/write role interpretation follows the library's
// ProSafeLinux-derived assumption (internal/nsdp/vlan.go). If a live
// verdict swaps roles, the swap happens in the library and this adapter
// follows automatically. The provider-side safety net is the
// ROLE-MISMATCH contract: whatever the wire reports, ApplyVLANState
// writes the desired state and the resource layer's verify read fails
// with a typed drift error instead of recording silent success — so a
// wrong role assumption can never produce a falsely-green apply.
// ---------------------------------------------------------------------------

// nsdpSwitchTransport implements switchTransport over the provider's
// nsdpClient seam. It holds no session state of its own: locking,
// pacing, the client cache, and the retry-once-on-auth-failure rule all
// live in withNSDPClient / withSwitchTransport, shared with the
// NSDP-native resources.
type nsdpSwitchTransport struct {
	client nsdpClient

	// agentMAC is the configured (normalized) agent_mac — the identity
	// anchor NSDP has instead of a host.
	agentMAC string

	// resourceID is the nsdp@<agent MAC> resource ID, computed once by
	// withSwitchTransport (same convention as port_config et al.).
	resourceID string
}

var _ switchTransport = nsdpSwitchTransport{}

func (t nsdpSwitchTransport) ResourceID() string {
	return t.resourceID
}

// nsdpSwitchPortCount is the physical port count of the GS108Ev3, the
// only model this provider supports. The HTTP path hardcodes the same
// count (gs108ev3 portCount); the NSDP port bitmaps are 8 bits wide.
const nsdpSwitchPortCount = 8

// require8021QEngineMode is the engine-mode guard for the NSDP VLAN
// state path — the mirror of requirePortBasedEngineMode in
// resource_port_based_vlan.go, with the roles reversed: this path ONLY
// applies in the 802.1Q modes (3 = 802.1q port-based, 4 = 802.1q
// extended). It refuses none (0), port-based (1) — where the grouping
// lives in the port-based table managed by netgear_plus_port_based_vlan
// — and id-based (2), with zero writes sent.
//
// The guard never CHANGES the engine mode: no provider resource may do
// that (SetVLANEngineMode is deliberately absent from the nsdpClient
// interface).
func require8021QEngineMode(c nsdpClient) error {
	attrs, err := c.GetBlock(nsdpBlockVLANEngineMode, nil)
	if err != nil {
		return operationError("VLAN engine mode guard failed", fmt.Errorf("read engine mode block 0x2000: %w", err))
	}

	var mode *nsdp.VLANEngineMode
	for _, a := range attrs {
		if decoded, ok := a.Decoded.(nsdp.VLANEngineMode); ok {
			mode = &decoded
			break
		}
	}
	if mode == nil {
		return operationError("VLAN engine mode guard failed", fmt.Errorf("engine mode block 0x2000 reply carried no mode value"))
	}

	switch *mode {
	case 3, 4: // 802.1q port-based, 802.1q extended
		return nil
	}

	return &providerOperationError{
		summary: "Refusing to manage 802.1Q VLAN state over NSDP",
		detail: fmt.Sprintf(
			"The switch's VLAN engine mode is %d, not an 802.1Q mode (3 = 802.1q port-based, 4 = 802.1q extended). In port-based mode (1) the port grouping lives in the port-based VLAN table managed by the `netgear_plus_port_based_vlan` resource; in mode 0 (none) or 2 (id-based) there is no 802.1Q table to manage over NSDP. `netgear_plus_vlan_state` refuses to touch the switch in this mode and sent no configuration to it. The provider never changes the VLAN engine mode itself.",
			byte(*mode),
		),
	}
}

// ReadSwitchFacts maps the NSDP identity onto the same model.SwitchFacts
// the HTTP path populates. Identity reads are harmless GETs in every
// engine mode, so they carry NO engine-mode guard.
//
// Field mapping (mirroring gs108ev3 parseSwitchFacts):
//   - Model: the product name as the switch reports it (HTTP hardcodes
//     the literal "gs108ev3"; NSDP reports the device's own string,
//     e.g. "GS108Ev3").
//   - SwitchName: the system name (tag 0x0003) — the HTTP path's
//     switch_name input equivalent.
//   - SerialNumber: tag 0x7800 (block 0x78). The HTTP path FAILS on a
//     missing serial; the NSDP path mirrors that (typed error) because
//     the resource layer's expected_serial_number pin is meaningless
//     without one.
//   - MACAddress: the CONFIGURED agent_mac — NSDP has no MAC read; the
//     configured MAC is the identity anchor the user pinned.
//   - FirmwareVersion: tag 0x0d (primary), 0x0e fallback.
//   - Host and BootloaderVersion: left empty — NSDP has no host notion
//     and NO bootloader source (documented in internal/nsdp/identity.go);
//     the resource ID comes from ResourceID(), not from facts.
func (t nsdpSwitchTransport) ReadSwitchFacts(_ context.Context) (model.SwitchFacts, error) {
	identity, err := t.client.GetIdentity()
	if err != nil {
		return model.SwitchFacts{}, fmt.Errorf("read identity: %w", err)
	}

	if identity.SerialNumber == "" {
		return model.SwitchFacts{}, fmt.Errorf("identity carried no serial number")
	}

	return model.SwitchFacts{
		Model:           identity.ProductName,
		SwitchName:      identity.SystemName,
		SerialNumber:    identity.SerialNumber,
		MACAddress:      t.agentMAC,
		FirmwareVersion: identity.FirmwareVersion,
		// Host: NSDP has no host — intentionally empty.
		// BootloaderVersion: no NSDP source — intentionally empty.
	}, nil
}

// ReadVLANState reads the live 802.1Q VLAN membership and PVID state,
// mirroring the gs108ev3 ReadVLANState shape: a normalized model.VLANState
// over all 8 ports, one entry per wire VLAN, PVID per port.
//
// Wire discipline (typed errors, never silent picks):
//   - A port appearing in BOTH the tagged and untagged bitmaps of one
//     VLAN is an invalid wire state → typed error.
//   - A VLAN ID appearing twice in the table → typed error.
//   - The PVID table must carry exactly ports 1-8, each once → typed
//     error on short, duplicate, or out-of-range tables.
func (t nsdpSwitchTransport) ReadVLANState(_ context.Context) (model.VLANState, error) {
	if err := require8021QEngineMode(t.client); err != nil {
		return model.VLANState{}, err
	}

	memberships, err := t.client.Get8021QVLANs()
	if err != nil {
		return model.VLANState{}, fmt.Errorf("read 802.1q vlan table: %w", err)
	}

	state := model.VLANState{
		PortCount: nsdpSwitchPortCount,
		VLANs:     make(map[int]model.Vlan, len(memberships)),
		PVIDs:     make(map[int]int, nsdpSwitchPortCount),
	}

	for _, membership := range memberships {
		vid := int(membership.VLANID)
		if _, dup := state.VLANs[vid]; dup {
			return model.VLANState{}, fmt.Errorf("802.1q table carries vlan %d twice", vid)
		}

		vlan := model.Vlan{ID: vid, Ports: make(map[int]model.PortMembership)}
		for _, port := range membership.TaggedPorts() {
			vlan.Ports[port] = model.PortMembershipTagged
		}
		for _, port := range membership.UntaggedPorts() {
			if _, both := vlan.Ports[port]; both {
				return model.VLANState{}, fmt.Errorf("vlan %d: port %d appears in both the tagged and untagged bitmaps — invalid wire state", vid, port)
			}
			vlan.Ports[port] = model.PortMembershipUntagged
		}
		state.VLANs[vid] = vlan
	}

	entries, err := t.client.GetPVIDs()
	if err != nil {
		return model.VLANState{}, fmt.Errorf("read pvid table: %w", err)
	}

	if len(entries) != nsdpSwitchPortCount {
		return model.VLANState{}, fmt.Errorf("pvid table carried %d entries, want exactly %d (one per port)", len(entries), nsdpSwitchPortCount)
	}
	for _, entry := range entries {
		port := int(entry.Port)
		if port < 1 || port > nsdpSwitchPortCount {
			return model.VLANState{}, fmt.Errorf("pvid table entry carries port %d, out of range [1,%d]", port, nsdpSwitchPortCount)
		}
		if _, dup := state.PVIDs[port]; dup {
			return model.VLANState{}, fmt.Errorf("pvid table carries port %d twice", port)
		}
		state.PVIDs[port] = int(entry.VLANID)
	}

	// Mirror the HTTP ReadVLANState: normalize so every VLAN carries
	// all 8 ports (omitted = ignored).
	return state.Normalize(), nil
}

// ApplyVLANState converges the switch to the desired state, mirroring
// the gs108ev3 driver's ApplyVLANState contract exactly: same
// normalize→validate→read→equal-short-circuit pipeline, same op-order
// philosophy (widen memberships first, then PVIDs, then exact
// memberships, deletes last — never delete a VLAN a port's PVID still
// references), same deletion semantics (VLANs on the wire but absent
// from desired get deleted, after the resource layer's
// allow_vlan_deletions guard has permitted it; this transport never
// re-decides that). Like the HTTP driver, it does NOT verify after the
// writes — the resource layer's read-back is the verifier.
//
// Primitive mapping: the web UI's per-VLAN membership POST becomes
// Set8021QVLAN (which adds-or-modifies in one SET, so added VLANs need
// no separate add op); the batched PVID form becomes one SetPVID per
// port (NSDP's PVID write is per-port); the checkbox delete form
// becomes Delete8021QVLAN (idempotent, live-proven).
func (t nsdpSwitchTransport) ApplyVLANState(ctx context.Context, desired model.VLANState) error {
	desired = desired.Normalize()
	if err := desired.Validate(); err != nil {
		return err
	}

	current, err := t.ReadVLANState(ctx)
	if err != nil {
		return fmt.Errorf("read current vlan state: %w", err)
	}

	current = current.Normalize()
	if current.Equal(desired) {
		return nil
	}

	removed := model.RemovedVLANs(current, desired)
	preservedPorts := model.PreservedPorts(desired)

	// step1 widens memberships (min of current and desired per port):
	// every PVID write below must land on a port that is already a
	// member of the target VLAN. step2 then sets the exact desired
	// membership, and removed VLANs are pre-cleared to all-ignored.
	step1 := make(map[int]model.Vlan)
	step2 := make(map[int]model.Vlan)

	for _, vid := range model.AddedVLANs(current, desired) {
		step1[vid] = desired.VLANs[vid]
	}

	currentIDs := current.VLANIDs()
	desiredIDs := desired.VLANIDs()
	for _, vid := range intersectVLANIDs(currentIDs, desiredIDs) {
		step1[vid] = model.Vlan{
			ID:    vid,
			Ports: mergedMembership(current.VLANs[vid].Ports, desired.VLANs[vid].Ports),
		}
		step2[vid] = desired.VLANs[vid]
	}

	for _, vid := range removed {
		step2[vid] = model.Vlan{
			ID:    vid,
			Ports: ignoredPorts(),
		}
	}

	// Ports omitted from the desired membership entirely keep their
	// current membership in the VLAN their current PVID references, so
	// their PVID stays valid (same fixup as the HTTP driver).
	for _, port := range preservedPorts {
		pvid := current.PVIDs[port]
		vlan := step2[pvid]
		if vlan.Ports == nil {
			vlan = current.VLANs[pvid]
		}
		if vlan.Ports == nil {
			vlan = model.Vlan{ID: pvid, Ports: ignoredPorts()}
		}
		vlan.Ports[port] = current.VLANs[pvid].Ports[port]
		step2[pvid] = vlan
	}

	// Removed VLANs still referenced as a PVID by a preserved port stay
	// on the wire (same filter as the HTTP driver).
	removed = model.PreserveRemovedVLANs(removed, current, preservedPorts)

	for _, vid := range sortedVLANIDs(step1) {
		if err := t.setVLANMembership(vid, step1[vid].Ports); err != nil {
			return err
		}
	}

	pvidBatches := model.BatchPVIDs(desired)
	for _, vid := range sortedVLANIDs(pvidBatches) {
		for _, port := range pvidBatches[vid] {
			if err := t.client.SetPVID(port, vid); err != nil {
				return fmt.Errorf("set pvid %d for port %d: %w", vid, port, err)
			}
		}
	}

	for _, vid := range sortedVLANIDs(step2) {
		if err := t.setVLANMembership(vid, step2[vid].Ports); err != nil {
			return err
		}
	}

	for _, vid := range removed {
		if err := t.client.Delete8021QVLAN(vid); err != nil {
			return fmt.Errorf("delete vlan %d: %w", vid, err)
		}
	}

	return nil
}

// setVLANMembership writes one VLAN's membership with Set8021QVLAN,
// splitting the per-port membership map into tagged/untagged port lists
// (ignored ports are in neither list). Error shape matches the HTTP
// driver's "set vlan %d membership: %w".
func (t nsdpSwitchTransport) setVLANMembership(vid int, ports map[int]model.PortMembership) error {
	var tagged, untagged []int
	for port := 1; port <= nsdpSwitchPortCount; port++ {
		switch ports[port] {
		case model.PortMembershipTagged:
			tagged = append(tagged, port)
		case model.PortMembershipUntagged:
			untagged = append(untagged, port)
		}
	}
	if err := t.client.Set8021QVLAN(vid, tagged, untagged); err != nil {
		return fmt.Errorf("set vlan %d membership: %w", vid, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Membership helpers mirroring the gs108ev3 driver's unexported ones
// (same semantics; the HTTP originals cannot be imported).
// ---------------------------------------------------------------------------

// ignoredPorts returns all-ignored membership over all 8 ports.
func ignoredPorts() map[int]model.PortMembership {
	ports := make(map[int]model.PortMembership, nsdpSwitchPortCount)
	for port := 1; port <= nsdpSwitchPortCount; port++ {
		ports[port] = model.PortMembershipIgnored
	}
	return ports
}

// mergedMembership takes the per-port minimum of the current and
// desired membership (untagged < tagged < ignored) — the widening step
// that keeps every PVID target valid during the transition.
func mergedMembership(current, desired map[int]model.PortMembership) map[int]model.PortMembership {
	result := ignoredPorts()
	for port := 1; port <= nsdpSwitchPortCount; port++ {
		result[port] = minMembership(current[port], desired[port])
	}
	return result
}

func minMembership(left, right model.PortMembership) model.PortMembership {
	order := map[model.PortMembership]int{
		model.PortMembershipUntagged: 1,
		model.PortMembershipTagged:   2,
		model.PortMembershipIgnored:  3,
	}

	if order[left] <= order[right] {
		return left
	}
	return right
}

func intersectVLANIDs(left, right []int) []int {
	set := make(map[int]struct{}, len(left))
	for _, value := range left {
		set[value] = struct{}{}
	}

	result := make([]int, 0, len(right))
	for _, value := range right {
		if _, ok := set[value]; ok {
			result = append(result, value)
		}
	}

	return result
}

func sortedVLANIDs[V any](vlans map[int]V) []int {
	ids := make([]int, 0, len(vlans))
	for vid := range vlans {
		ids = append(ids, vid)
	}
	slices.Sort(ids)
	return ids
}
