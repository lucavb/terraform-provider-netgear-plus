package gs108ev3

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// ApplyVLANState applies the full authoritative VLAN state to the device.
func (d *Driver) ApplyVLANState(ctx context.Context, desired model.VLANState) error {
	desired = desired.Normalize()
	if err := desired.Validate(); err != nil {
		return err
	}

	current, err := d.ReadVLANState(ctx)
	if err != nil {
		return fmt.Errorf("read current vlan state: %w", err)
	}

	current = current.Normalize()
	if current.Equal(desired) {
		return nil
	}

	hash, err := d.ensureHash(ctx)
	if err != nil {
		return err
	}

	removed := model.RemovedVLANs(current, desired)
	preservedPorts := model.PreservedPorts(desired)

	step1 := make(map[int]model.Vlan)
	step2 := make(map[int]model.Vlan)

	for _, vid := range model.AddedVLANs(current, desired) {
		step1[vid] = desired.VLANs[vid]
	}

	currentIDs := current.VLANIDs()
	desiredIDs := desired.VLANIDs()
	for _, vid := range intersect(currentIDs, desiredIDs) {
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

	removed = model.PreserveRemovedVLANs(removed, current, preservedPorts)

	for _, vid := range model.AddedVLANs(current, desired) {
		if err := d.addVLAN(ctx, vid, hash); err != nil {
			return err
		}
	}

	for _, vid := range sortedVLANMapKeys(step1) {
		if err := d.setVLANMembership(ctx, vid, step1[vid].Ports, hash); err != nil {
			return err
		}
	}

	for vid, ports := range model.BatchPVIDs(desired) {
		if err := d.setPortsPVID(ctx, ports, vid, hash); err != nil {
			return err
		}
	}

	for _, vid := range sortedVLANMapKeys(step2) {
		if err := d.setVLANMembership(ctx, vid, step2[vid].Ports, hash); err != nil {
			return err
		}
	}

	if err := d.deleteVLANs(ctx, removed, hash); err != nil {
		return err
	}

	return nil
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

func ignoredPorts() map[int]model.PortMembership {
	ports := make(map[int]model.PortMembership, portCount)
	for port := 1; port <= portCount; port++ {
		ports[port] = model.PortMembershipIgnored
	}
	return ports
}

func mergedMembership(current, desired map[int]model.PortMembership) map[int]model.PortMembership {
	result := ignoredPorts()
	for port := 1; port <= portCount; port++ {
		left := current[port]
		right := desired[port]
		result[port] = minMembership(left, right)
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

func intersect(left, right []int) []int {
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

func sortedVLANMapKeys(vlans map[int]model.Vlan) []int {
	keys := make([]int, 0, len(vlans))
	for vid := range vlans {
		keys = append(keys, vid)
	}
	slices.Sort(keys)
	return keys
}
