package gs108ev3

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

func TestParseFixtures(t *testing.T) {
	t.Parallel()

	login := mustReadFixture(t, "login.htm")
	rand, err := parseLoginRand(login)
	if err != nil {
		t.Fatalf("parseLoginRand() error = %v", err)
	}
	if rand != "12345678" {
		t.Fatalf("parseLoginRand() = %q", rand)
	}

	switchInfo := mustReadFixture(t, "switch_info.htm")
	facts, err := parseSwitchFacts("192.0.2.10", "gs108ev3", switchInfo)
	if err != nil {
		t.Fatalf("parseSwitchFacts() error = %v", err)
	}
	if facts.SwitchName != "" || facts.FirmwareVersion != "V2.06.10EN" || facts.BootloaderVersion != "V0.00.00" {
		t.Fatalf("unexpected facts: %+v", facts)
	}

	vlanList := mustReadFixture(t, "8021qMembe_list.htm")
	vids, err := parseCurrentVLANIDs(vlanList)
	if err != nil {
		t.Fatalf("parseCurrentVLANIDs() error = %v", err)
	}
	if len(vids) != 2 || vids[0] != 1 || vids[1] != 10 {
		t.Fatalf("unexpected vlan ids: %v", vids)
	}

	vlan1 := mustReadFixture(t, "8021qMembe_vlan1.htm")
	parsedVLAN, err := parseVLANMembership(1, vlan1)
	if err != nil {
		t.Fatalf("parseVLANMembership() error = %v", err)
	}
	if parsedVLAN.Ports[1] != model.PortMembershipUntagged || parsedVLAN.Ports[4] != model.PortMembershipUntagged || parsedVLAN.Ports[8] != model.PortMembershipIgnored {
		t.Fatalf("unexpected vlan membership: %+v", parsedVLAN)
	}

	pvidPage := mustReadFixture(t, "portPVID.htm")
	pvids, err := parsePVIDs(pvidPage)
	if err != nil {
		t.Fatalf("parsePVIDs() error = %v", err)
	}
	if pvids[1] != 1 || pvids[4] != 1 || pvids[8] != 10 {
		t.Fatalf("unexpected pvids: %v", pvids)
	}

	vlanConfig := mustReadFixture(t, "8021qCf.htm")
	vlanCount, err := parseVLANCount(vlanConfig)
	if err != nil {
		t.Fatalf("parseVLANCount() error = %v", err)
	}
	if vlanCount != 6 {
		t.Fatalf("parseVLANCount() = %d", vlanCount)
	}
}

func TestIsRedirectToLoginRecognizesSlashLoginHTM(t *testing.T) {
	t.Parallel()

	body := `<html><script>top.location.href = "/login.htm";</script></html>`
	if !isRedirectToLogin(body) {
		t.Fatal("isRedirectToLogin() should detect /login.htm redirects")
	}
}

func mustReadFixture(t *testing.T, name string) string {
	t.Helper()

	for _, path := range candidateFixturePaths(name) {
		data, err := os.ReadFile(path)
		if err == nil {
			return string(data)
		}
	}

	t.Fatalf("read fixture %s: no candidate file found", name)
	return ""
}

func candidateFixturePaths(name string) []string {
	captureMap := map[string]string{
		"login.htm":             "login.html",
		"switch_info.htm":       "switch_info.html",
		"8021qCf.htm":           "8021qCf.html",
		"8021qMembe_list.htm":   "8021qMembe.html",
		"8021qMembe_vlan1.htm":  "8021qMembe_vlan_1.html",
		"8021qMembe_vlan10.htm": "8021qMembe_vlan_10.html",
		"portPVID.htm":          "portPVID.html",
	}

	candidates := []string{
		filepath.Join("..", "..", "testfixtures", "gs108ev3", name),
	}
	if captureName, ok := captureMap[name]; ok {
		candidates = append(candidates, filepath.Join("..", "..", "..", "captures", "gs108ev3", "sanitized", captureName))
	}
	return candidates
}
