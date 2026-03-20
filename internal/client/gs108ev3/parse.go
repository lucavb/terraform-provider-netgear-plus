package gs108ev3

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

var whitespacePattern = regexp.MustCompile(`\s+`)

func parseLoginRand(body string) (string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("parse login html: %w", err)
	}

	rand := firstValue(doc, "input#rand", "value")
	if rand == "" {
		return "", fmt.Errorf("login rand not found")
	}

	return rand, nil
}

func parseSessionHash(body string) (string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("parse hash html: %w", err)
	}

	hash := firstValue(doc, `input[name="hash"]`, "value")
	if hash == "" {
		return "", fmt.Errorf("session hash not found")
	}

	return hash, nil
}

func parseErrorMessage(body string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return ""
	}
	return firstValue(doc, "input#err_msg", "value")
}

func parseSwitchFacts(host, modelName, body string) (model.SwitchFacts, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return model.SwitchFacts{}, fmt.Errorf("parse switch facts html: %w", err)
	}

	facts := model.SwitchFacts{
		Host:              host,
		Model:             modelName,
		SwitchName:        firstValue(doc, "input#switch_name", "value"),
		SerialNumber:      tableValueByLabel(doc, "Serial Number"),
		MACAddress:        tableValueByLabel(doc, "MAC Address"),
		FirmwareVersion:   tableValueByLabel(doc, "Firmware Version"),
		BootloaderVersion: tableValueByIDText(doc, "loader"),
	}

	if facts.SerialNumber == "" {
		return model.SwitchFacts{}, fmt.Errorf("serial number not found")
	}

	return facts, nil
}

func parseCurrentVLANIDs(body string) ([]int, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("parse vlan list html: %w", err)
	}

	var vids []int
	doc.Find("select#vlanIdOption option").Each(func(_ int, selection *goquery.Selection) {
		value, ok := selection.Attr("value")
		if !ok {
			return
		}
		vid, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return
		}
		vids = append(vids, vid)
	})

	if len(vids) == 0 {
		return nil, fmt.Errorf("no vlan ids found")
	}

	slices.Sort(vids)
	return vids, nil
}

func parseVLANMembership(vid int, body string) (model.Vlan, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return model.Vlan{}, fmt.Errorf("parse vlan membership html: %w", err)
	}

	currentID := firstValue(doc, `input[name="VLAN_ID_HD"]`, "value")
	if currentID != strconv.Itoa(vid) {
		return model.Vlan{}, fmt.Errorf("expected vlan %d but page returned %q", vid, currentID)
	}

	configString := firstValue(doc, "input#hiddenMem", "value")
	if len(configString) != portCount {
		return model.Vlan{}, fmt.Errorf("expected membership string length %d, got %d", portCount, len(configString))
	}

	ports := make(map[int]model.PortMembership, portCount)
	for idx, char := range configString {
		var membership model.PortMembership
		switch char {
		case '1':
			membership = model.PortMembershipUntagged
		case '2':
			membership = model.PortMembershipTagged
		case '3':
			membership = model.PortMembershipIgnored
		default:
			return model.Vlan{}, fmt.Errorf("unknown membership %q in vlan %d", string(char), vid)
		}

		ports[idx+1] = membership
	}

	return model.Vlan{
		ID:    vid,
		Ports: ports,
	}, nil
}

func parsePVIDs(body string) (map[int]int, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("parse pvid html: %w", err)
	}

	pvids := make(map[int]int, portCount)

	doc.Find("tr.portID").Each(func(_ int, row *goquery.Selection) {
		portValue, ok := row.Find(`input[type="hidden"]`).Attr("value")
		if !ok {
			return
		}

		port, err := strconv.Atoi(strings.TrimSpace(portValue))
		if err != nil {
			return
		}

		text := strings.TrimSpace(row.Find(`td.def[sel="input"]`).First().Text())
		pvid, err := strconv.Atoi(text)
		if err != nil {
			return
		}

		pvids[port] = pvid
	})

	if len(pvids) != portCount {
		return nil, fmt.Errorf("expected %d pvid entries, got %d", portCount, len(pvids))
	}

	return pvids, nil
}

func parseVLANCount(body string) (int, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("parse vlan count html: %w", err)
	}

	value := firstValue(doc, `input[name="vlanNum"]`, "value")
	if value == "" {
		return 0, fmt.Errorf("vlan count not found")
	}

	count, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse vlan count %q: %w", value, err)
	}

	return count, nil
}

func isRedirectToLogin(body string) bool {
	normalized := strings.ToLower(whitespacePattern.ReplaceAllString(body, " "))
	return strings.Contains(normalized, "redirect to login") ||
		strings.Contains(normalized, `top.location.href = "/wmi/login"`) ||
		strings.Contains(normalized, `top.location.href = "/login.htm"`) ||
		strings.Contains(normalized, `top.location.href='/login.htm'`) ||
		strings.Contains(normalized, `top.location.href = "login.htm"`) ||
		strings.Contains(normalized, `top.location.href='login.htm'`)
}

func tableValueByLabel(doc *goquery.Document, label string) string {
	var result string
	doc.Find("td").EachWithBreak(func(_ int, td *goquery.Selection) bool {
		text := strings.TrimSpace(td.Text())
		if text != label {
			return true
		}
		result = strings.TrimSpace(td.Next().Text())
		return false
	})
	return result
}

func tableValueByIDText(doc *goquery.Document, id string) string {
	return strings.TrimSpace(doc.Find("#" + id).First().Text())
}
