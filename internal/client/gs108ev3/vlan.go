package gs108ev3

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// ApplyVLANState applies the full authoritative VLAN state to the
// device by reading the current state, building a model.Plan (the pure
// convergence pipeline transposed out of this driver), and replaying it
// through the driver's web-UI forms via the model.VLANApplier seam. The
// hash/count plumbing (ensureHash/getVLANCount) stays driver-side,
// outside the plan: an empty plan short-circuits before ensureHash,
// exactly like the old Equal early-return.
func (d *Driver) ApplyVLANState(ctx context.Context, desired model.VLANState) error {
	desired = desired.Normalize()
	if err := desired.Validate(); err != nil {
		return err
	}

	current, err := d.ReadVLANState(ctx)
	if err != nil {
		return fmt.Errorf("read current vlan state: %w", err)
	}

	plan, err := model.Plan(current, desired)
	if err != nil {
		return err
	}
	if len(plan) == 0 {
		return nil
	}

	hash, err := d.ensureHash(ctx)
	if err != nil {
		return err
	}

	return model.Run(ctx, plan, vlanApplier{driver: d, hash: hash})
}

// vlanApplier adapts the plan's ops onto the driver's web-UI forms.
// The hash is captured once per non-empty apply (the plan ops all need
// it); vlanCount is fetched per add/delete form, as before.
type vlanApplier struct {
	driver *Driver
	hash   string
}

var _ model.VLANApplier = vlanApplier{}

// AddVLAN executes the device's add form for one newly added VLAN.
func (a vlanApplier) AddVLAN(ctx context.Context, vid int) error {
	return a.driver.addVLAN(ctx, vid, a.hash)
}

// SetMembership executes the hiddenMem membership POST for one VLAN.
func (a vlanApplier) SetMembership(ctx context.Context, vid int, ports map[int]model.PortMembership) error {
	return a.driver.setVLANMembership(ctx, vid, ports, a.hash)
}

// SetPVIDs executes the batched PVID form for one vid. BEHAVIOR CHANGE
// vs the inline pipeline: the plan emits SetPVIDs ops sorted by vid
// (with ports sorted), whereas the old code iterated BatchPVIDs' map in
// Go's random order, so identical applies could send the set-pvid
// forms in different order run to run. Wire order is now deterministic.
func (a vlanApplier) SetPVIDs(ctx context.Context, vid int, ports []int) error {
	return a.driver.setPortsPVID(ctx, ports, vid, a.hash)
}

// DeleteVLANs executes today's single batched delete form carrying all
// vids. The plan hands the vids sorted ascending (the old inline
// pipeline did too, via RemovedVLANs).
func (a vlanApplier) DeleteVLANs(ctx context.Context, vids []int) error {
	return a.driver.deleteVLANs(ctx, vids, a.hash)
}

func (d *Driver) addVLAN(ctx context.Context, vid int, hash string) error {
	vlanCount, err := d.getVLANCount(ctx)
	if err != nil {
		return err
	}

	form := url.Values{}
	form.Set("status", "Enable")
	form.Set("hiddVlan", "")
	form.Set("ADD_VLANID", strconv.Itoa(vid))
	form.Set("vlanNum", strconv.Itoa(vlanCount))
	form.Set("hash", hash)
	form.Set("ACTION", "Add")

	body, err := d.postFormAuthenticated(ctx, endpointVLANConfigCGI, form)
	if err != nil {
		return fmt.Errorf("add vlan %d: %w", vid, err)
	}
	if errMsg := parseErrorMessage(body); errMsg != "" {
		return fmt.Errorf("add vlan %d: %s", vid, errMsg)
	}

	return nil
}

func (d *Driver) deleteVLANs(ctx context.Context, vids []int, hash string) error {
	if len(vids) == 0 {
		return nil
	}

	vlanCount, err := d.getVLANCount(ctx)
	if err != nil {
		return err
	}

	currentState, err := d.ReadVLANState(ctx)
	if err != nil {
		return fmt.Errorf("read vlan state before delete: %w", err)
	}
	currentIDs := currentState.VLANIDs()

	form := url.Values{}
	form.Set("status", "Enable")
	form.Set("hiddVlan", "")
	form.Set("ADD_VLANID", "")
	form.Set("vlanNum", strconv.Itoa(vlanCount))
	form.Set("hash", hash)
	form.Set("ACTION", "Delete")

	for _, vid := range vids {
		index := slices.Index(currentIDs, vid)
		if index < 0 {
			continue
		}
		form.Set(fmt.Sprintf("vlanck%d", index), strconv.Itoa(vid))
	}

	body, err := d.postFormAuthenticated(ctx, endpointVLANConfigCGI, form)
	if err != nil {
		return fmt.Errorf("delete vlans: %w", err)
	}
	if errMsg := parseErrorMessage(body); errMsg != "" {
		return fmt.Errorf("delete vlans: %s", errMsg)
	}

	return nil
}

func (d *Driver) setVLANMembership(ctx context.Context, vid int, ports map[int]model.PortMembership, hash string) error {
	form := url.Values{}
	form.Set("VLAN_ID", strconv.Itoa(vid))
	form.Set("VLAN_ID_HD", strconv.Itoa(vid))
	form.Set("hash", hash)
	form.Set("hiddenMem", encodeMembership(ports))

	body, err := d.postFormAuthenticated(ctx, endpointVLANMemberCGI, form)
	if err != nil {
		return fmt.Errorf("set vlan %d membership: %w", vid, err)
	}
	if errMsg := parseErrorMessage(body); errMsg != "" {
		return fmt.Errorf("set vlan %d membership: %s", vid, errMsg)
	}

	return nil
}

func (d *Driver) setPortsPVID(ctx context.Context, ports []int, vid int, hash string) error {
	form := url.Values{}
	form.Set("pvid", strconv.Itoa(vid))
	form.Set("hash", hash)
	for _, port := range ports {
		form.Set(fmt.Sprintf("port%d", port), "checked")
	}

	body, err := d.postFormAuthenticated(ctx, endpointPortPVIDCGI, form)
	if err != nil {
		return fmt.Errorf("set pvid %d for ports %v: %w", vid, ports, err)
	}
	if errMsg := parseErrorMessage(body); errMsg != "" {
		return fmt.Errorf("set pvid %d for ports %v: %s", vid, ports, errMsg)
	}

	return nil
}

func (d *Driver) getVLANCount(ctx context.Context) (int, error) {
	body, err := d.tryGETAuthenticated(ctx, endpointVLANConfigHTM, endpointVLANConfigCGI)
	if err != nil {
		return 0, err
	}
	return parseVLANCount(body)
}

func encodeMembership(ports map[int]model.PortMembership) string {
	encoded := make([]byte, 0, portCount)
	for port := 1; port <= portCount; port++ {
		switch ports[port] {
		case model.PortMembershipUntagged:
			encoded = append(encoded, '1')
		case model.PortMembershipTagged:
			encoded = append(encoded, '2')
		default:
			encoded = append(encoded, '3')
		}
	}
	return string(encoded)
}
