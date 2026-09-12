package provider

import (
	"context"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// ---------------------------------------------------------------------------
// Transport interfaces for the dual-transport switch surface.
//
// `netgear_plus_vlan_state` and the switch / vlan_state data sources are
// being migrated to run over either transport: the existing HTTP (web UI)
// driver, or NSDP once the live NSDP probes land. The resource layer
// consumes ONLY these interfaces; it never touches a concrete protocol
// client type again.
//
// The interfaces are deliberately minimal and evidence-based: exactly
// the operations the resource layer invokes today, named for the ROLE
// they play, not the protocol behind them.
//
// NSDP satisfiability (design contract for the follow-up lane): the NSDP
// implementation will build these from its primitives — Get/Set/Delete
// 8021Q VLAN and Get/Set PVID compose ApplyVLANState; identity reads
// come from the NSDP product/model/firmware/serial tags. Fields NSDP
// cannot read (notably the bootloader version) are returned as empty
// strings — ReadSwitchFacts returns what the transport has, and callers
// must not assume every field is populated.
//
// Deliberately NOT part of the interfaces (they are resource-layer
// semantics and stay there): expected_serial_number checking (the serial
// is readable over NSDP too, but the check stays in the resource),
// allow_vlan_deletions guarding, and model.VLANState.Validate().
// ---------------------------------------------------------------------------

// vlanStateTransport reads and authoritatively applies the switch's VLAN
// membership and PVID state.
type vlanStateTransport interface {
	// ReadVLANState returns the live VLAN membership and PVID map,
	// normalized over all physical ports.
	ReadVLANState(ctx context.Context) (model.VLANState, error)

	// ApplyVLANState converges the switch to the desired state. The
	// transport computes and performs the concrete writes (membership
	// changes, PVID writes, and — where the caller's resource-layer
	// guards have permitted it — VLAN deletions) from the desired
	// state; it does not re-decide whether a deletion is allowed.
	ApplyVLANState(ctx context.Context, desired model.VLANState) error
}

// switchInfoTransport reads stable switch identity and firmware facts.
type switchInfoTransport interface {
	// ReadSwitchFacts returns the identity facts the transport can
	// provide. Transports that cannot read a fact (e.g. the bootloader
	// version over NSDP) return it as an empty string.
	ReadSwitchFacts(ctx context.Context) (model.SwitchFacts, error)
}

// switchTransport is the full surface the VLAN state resource needs:
// identity facts plus VLAN/PVID state read and authoritative apply. The
// data sources consume the narrower halves.
type switchTransport interface {
	vlanStateTransport
	switchInfoTransport

	// ResourceID returns the stable Terraform resource/data source ID
	// for the transport's identity convention: `gs108ev3@<host>` over
	// HTTP (host-canonicalized), `nsdp@<agent MAC>` over NSDP — the
	// same convention the NSDP-native resources (port_config et al.)
	// use.
	//
	// TRANSPORT-SWITCH CAVEAT: the ID encodes the transport's identity
	// anchor, so switching the same physical switch between `host` and
	// `agent_mac` configuration changes the ID. Terraform then sees a
	// different resource; users must re-import (terraform import) after
	// switching transports rather than letting Terraform destroy and
	// recreate — the resource's Delete is state-only anyway.
	ResourceID() string
}

// httpSwitchTransport adapts the concrete HTTP (web UI) driver to the
// transport interfaces. It is stateless and forwards every call — the
// session lifecycle (login, caching, invalidation on
// ShouldInvalidateSession, logout) stays with the HTTP-specific
// plumbing in provider.go, exactly as before this refactor.
type httpSwitchTransport struct {
	driver client.Driver

	// resourceID is the host-shaped resource ID
	// ("<model>@<canonical host>"), computed once by withSwitchTransport
	// via providerData.resourceID().
	resourceID string
}

var _ switchTransport = httpSwitchTransport{}

func (t httpSwitchTransport) ResourceID() string {
	return t.resourceID
}

func (t httpSwitchTransport) ReadSwitchFacts(ctx context.Context) (model.SwitchFacts, error) {
	return t.driver.ReadSwitchFacts(ctx)
}

func (t httpSwitchTransport) ReadVLANState(ctx context.Context) (model.VLANState, error) {
	return t.driver.ReadVLANState(ctx)
}

func (t httpSwitchTransport) ApplyVLANState(ctx context.Context, desired model.VLANState) error {
	return t.driver.ApplyVLANState(ctx, desired)
}
