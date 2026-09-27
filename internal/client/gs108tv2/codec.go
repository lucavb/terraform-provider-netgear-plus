package gs108tv2

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/fastpath"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// ---------------------------------------------------------------------------
// VLAN text-config grammar (pinned live in phase 0a, partially).
//
// Grammar maturity per template:
//
//   - `vlan <id>` declaration: LIVE-PINNED (2026-09-16, bench switch
//     GS108Tv2 @ 10.0.2.8 accepted an uploaded `vlan 42` declaration
//     and re-served it structurally intact; see
//     internal/testfixtures/gs108tv2/{vlan42-upload,vlan42-reserved}.txt).
//
//   - Membership (`vlan <id> port 0/<port> untagged|tagged`) and PVID
//     (`vlan pvid <id>`) templates: PROVISIONAL — live probing is
//     running in parallel right now; do not extend or trust the shape
//     beyond this banner until pinned.
//
// The parser is deliberately FAIL CLOSED outside pinned shapes: a
// `vlan `-prefixed line inside a managed section that does not match a
// template is a typed error (ErrGrammarLine) quoting the line — never
// silently dropped, never guessed. Non-`vlan` lines inside managed
// sections ("foreign" lines) are preserved verbatim on re-render.
//
// Defaults are IMPLICIT BY ABSENCE: when the whole `vlan database`
// body carries no vlan-prefixed content, the switch is in its factory
// state — VLAN 1 with every port untagged, PVID 1 everywhere. The
// codec renders that default state back as EMPTY bodies, so a no-op
// apply reproduces the factory file byte-identically.
//
// Structural-compare rationale (recorded live evidence): the switch
// re-serializes whitespace on ingest — the compact upload in
// vlan42-upload.txt came back double-spaced in vlan42-reserved.txt —
// so the apply pipeline verifies by structural Equality
// (model.Equal), never by byte comparison; CanonicalBytes divergence
// stays a WARNING signal.
// ---------------------------------------------------------------------------

// vlanDatabaseLabel is the managed VLAN declaration section.
const vlanDatabaseLabel = "vlan database"

// defaultPortCount: the GS108Tv2 line this driver serves has exactly
// the 8 user ports `interface 0/1`..`interface 0/8`. The `interface
// 3/x` blocks are CPU/LACP sections and are never touched.
const defaultPortCount = 8

// defaultPVID is the factory PVID (a GS108Tv2 with no staged VLANs
// bridges everything untagged in VLAN 1).
const defaultPVID = 1

// ErrGrammarLine is the fail-closed codec error: a `vlan `-prefixed
// line inside a managed section did not match any PROVISIONAL grammar
// template. It quotes the offending line; the shape is unsupported
// until the grammar is pinned live.
type ErrGrammarLine struct {
	Section string // e.g. "vlan database", "interface 0/3"
	Line    string // the offending content line, trimmed
	Reason  string
}

func (e *ErrGrammarLine) Error() string {
	return fmt.Sprintf("gs108tv2: unsupported line %q in section %q (grammar unpinned, refusing to guess): %s",
		e.Line, e.Section, e.Reason)
}

// ErrMissingSection is the codec error for a managed structural
// section that the fetched config does not contain at all.
type ErrMissingSection struct {
	Label string
}

func (e *ErrMissingSection) Error() string {
	return fmt.Sprintf("gs108tv2: config is missing managed section %q", e.Label)
}

// vlanMember is one parsed membership fact.
type vlanMember struct {
	vid, port int
	m         model.PortMembership
}

// decodedConfig is the full codec result: the semantic state (VLAN and
// port), the foreign (unmanaged) content lines per managed section in
// file order (VLAN-render preservation), and the port-namespace
// passthrough (per interface body: every line that the PORT grammar
// does not manage, in order — i.e. `vlan pvid` lines and foreign
// lines; the port render splices only the lines it owns and keeps
// these verbatim), plus the decoded per-port settings.
//
// Namespace discipline: each codec owns only its keyword namespace
// (VLAN: `vlan ...`; port: `shutdown` / `flow control`), reads the
// other's lines as passthrough, and never edits what it does not
// own. VLAN state decode errors do not strip port facts and vice
// versa: issues are aggregated and returned as error only to
// vlan-consumers — dec is always structurally complete for the port
// namespace.
type decodedConfig struct {
	State    model.VLANState
	Ports    map[int]PortSettings
	Foreign  map[string][]string
	PortPass map[string][]string
}

// decodeTextConfig parses the structural text config into VLAN and
// port state. PROVISIONAL throughout: see the grammar banner above.
// Grammar violations inside managed sections are aggregated into the
// returned error (first violation wins for errors.As), but the decode
// always completes so the port namespace stays usable even on configs
// with foreign `vlan` garbage.
func decodeTextConfig(tc fastpath.TextConfig) (decodedConfig, error) {
	dec := decodedConfig{
		Foreign:  map[string][]string{},
		PortPass: map[string][]string{},
		Ports:    map[int]PortSettings{},
		State: model.VLANState{
			PortCount: defaultPortCount,
			VLANs:     map[int]model.Vlan{},
			PVIDs:     map[int]int{},
		},
	}
	for port := 1; port <= defaultPortCount; port++ {
		dec.State.PVIDs[port] = defaultPVID
		dec.Ports[port] = DefaultPortSettings()
	}
	var issues []error

	sawVLANLine := false
	var members []vlanMember
	declared := map[int]bool{}

	dbBody, _ := tc.SectionBody(vlanDatabaseLabel)
	if _, ok := tc.Section(vlanDatabaseLabel); !ok {
		issues = append(issues, &ErrMissingSection{Label: vlanDatabaseLabel})
	}
	for _, raw := range dbBody {
		line := strings.TrimRight(raw, "\r")
		if !strings.HasPrefix(strings.TrimSpace(line), "vlan ") {
			dec.Foreign[vlanDatabaseLabel] = append(dec.Foreign[vlanDatabaseLabel], line)
			continue
		}
		if vids, ok := parseVlanDeclares(strings.Fields(line)); ok {
			for _, vid := range vids {
				declared[vid] = true
			}
			sawVLANLine = true
			continue
		}
		if m, ok := parseVlanMembership(strings.Fields(line)); ok {
			if m.port < 1 || m.port > defaultPortCount {
				issues = append(issues, &ErrGrammarLine{
					Section: vlanDatabaseLabel,
					Line:    strings.TrimSpace(line),
					Reason:  fmt.Sprintf("port 0/%d outside managed range 1..%d", m.port, defaultPortCount),
				})
				continue
			}
			members = append(members, vlanMember{vid: m.vid, port: m.port, m: m.m})
			sawVLANLine = true
			continue
		}
		issues = append(issues, &ErrGrammarLine{
			Section: vlanDatabaseLabel,
			Line:    strings.TrimSpace(line),
			Reason:  "does not match any template (vlan <id> | vlan <id> port 0/<p> untagged|tagged)",
		})
	}

	for port := 1; port <= defaultPortCount; port++ {
		label := fmt.Sprintf("interface 0/%d", port)
		ifaceBody, ok := tc.SectionBody(label)
		if !ok {
			// Absence of a port section leaves that port at factory
			// defaults; there is nothing to preserve either.
			continue
		}
		for _, raw := range ifaceBody {
			line := strings.TrimRight(raw, "\r")
			fields := strings.Fields(line)
			if strings.HasPrefix(strings.TrimSpace(line), "vlan ") {
				if vid, ok := parseVlanPVID(fields); !ok {
					issues = append(issues, &ErrGrammarLine{
						Section: label,
						Line:    strings.TrimSpace(line),
						Reason:  "does not match the pinned PVID template (vlan pvid <id>)",
					})
				} else {
					dec.State.PVIDs[port] = vid
				}
				// The VLAN namespace OWNS this line for the VLAN
				// render (its desired state regenerates it), but the
				// PORT render must preserve it: it belongs to the
				// port passthrough, not to the port grammar.
				dec.PortPass[label] = append(dec.PortPass[label], line)
				continue
			}
			// …everything else is kept for the VLAN render as foreign
			// (F2a semantics) and, unless the port grammar owns it,
			// also for the port render's passthrough.
			dec.Foreign[label] = append(dec.Foreign[label], line)
			if disabled, ok := parseShutdownLine(fields); ok {
				ps := dec.Ports[port]
				ps.Enabled = !disabled
				dec.Ports[port] = ps
				continue
			}
			if on, ok := parseFlowControlLine(fields); ok {
				ps := dec.Ports[port]
				ps.FlowControl = on
				dec.Ports[port] = ps
				continue
			}
			dec.PortPass[label] = append(dec.PortPass[label], line)
		}
	}

	// VLANS: explicit declarations plus the implicit default when the
	// database body is empty of vlan content (default-by-absence).
	if !sawVLANLine {
		declared[defaultPVID] = true
		for port := 1; port <= defaultPortCount; port++ {
			members = append(members, vlanMember{vid: defaultPVID, port: port, m: model.PortMembershipUntagged})
		}
	}
	for _, vid := range sortedDeclared(declared) {
		dec.State.VLANs[vid] = model.Vlan{ID: vid, Ports: map[int]model.PortMembership{}}
	}
	// Realize explicit membership lines (all VLANs, including a vlan 1
	// that a foreign config declared/explicitly wired).
	for _, m := range members {
		if _, ok := dec.State.VLANs[m.vid]; !ok {
			// Membership for a VLAN neither declared nor implicit-1:
			// fail closed (the firmware would not emit this, and
			// guessing the declaration is unsafe).
			issues = append(issues, &ErrGrammarLine{
				Section: vlanDatabaseLabel,
				Line:    fmt.Sprintf("vlan %d port 0/%d %s", m.vid, m.port, m.m),
				Reason:  "membership for a VLAN never declared (only VLAN 1 may stay undeclared)",
			})
			continue
		}
		dec.State.VLANs[m.vid].Ports[m.port] = m.m
	}
	// Implicit VLAN 1: realized only when it is meaningfully occupied.
	if v1, keep := inferVLAN1(declared[defaultPVID], dec.State, members); keep {
		dec.State.VLANs[defaultPVID] = v1
	}
	inferAccessVLANMembershipFromPVID(dec.State)
	if len(issues) > 0 {
		return dec, issues[0]
	}
	return dec, nil
}

// inferAccessVLANMembershipFromPVID mirrors FASTPATH access-port
// semantics observed live on GS108Tv2 @10.0.2.8: the switch persists
// `vlan pvid <id>` under interface 0/x without companion `vlan <id>
// port 0/x untagged` lines in the vlan database. For decode/verify,
// treat PVID N as untagged membership in VLAN N when that port has no
// explicit membership yet.
func inferAccessVLANMembershipFromPVID(state model.VLANState) {
	for port := 1; port <= defaultPortCount; port++ {
		vid := state.PVIDs[port]
		if vid <= 0 {
			continue
		}
		vlan, ok := state.VLANs[vid]
		if !ok {
			continue
		}
		if _, exists := vlan.Ports[port]; exists {
			continue
		}
		vlan.Ports[port] = model.PortMembershipUntagged
		state.VLANs[vid] = vlan
	}
}

// inferVLAN1 computes the implicit VLAN 1 membership map:
//   - explicit `vlan 1 port 0/p ...` lines win;
//   - otherwise a port is untagged in VLAN 1 exactly when its PVID is
//     the default and no other VLAN carries it untagged (single
//     untagged VLAN per port);
//   - otherwise ignored.
//
// keep reports whether VLAN 1 is meaningfully present (declared, or at
// least one port resolves untagged): a state whose every port moved to
// another VLAN keeps no phantom all-ignored VLAN 1 entry, keeping
// decode(render(x)) == x.
func inferVLAN1(wasDeclared bool, state model.VLANState, members []vlanMember) (model.Vlan, bool) {
	ports := map[int]model.PortMembership{}
	explicit := map[int]model.PortMembership{}
	untaggedElsewhere := map[int]bool{}
	for _, m := range members {
		if m.vid == defaultPVID {
			explicit[m.port] = m.m
			continue
		}
		if m.m == model.PortMembershipUntagged {
			untaggedElsewhere[m.port] = true
		}
	}
	keep := wasDeclared
	for port := 1; port <= state.PortCount; port++ {
		if m, ok := explicit[port]; ok {
			ports[port] = m
			if m == model.PortMembershipUntagged {
				keep = true
			}
			continue
		}
		if state.PVIDs[port] == defaultPVID && !untaggedElsewhere[port] {
			ports[port] = model.PortMembershipUntagged
			keep = true
			continue
		}
		ports[port] = model.PortMembershipIgnored
	}
	return model.Vlan{ID: defaultPVID, Ports: ports}, keep
}

// --- PROVISIONAL grammar parsers (pinned live in phase 0a) ---

// parseVlanDeclares matches "vlan <id>" and the switch normalizer's
// combined form "vlan 10,99" (comma-separated IDs in the second field).
// LIVE-PINNED (2026-09-16, bench GS108Tv2 @10.0.2.8 accepted and
// re-served a declaration; fixtures:
// internal/testfixtures/gs108tv2/vlan42-{upload,reserved}.txt).
func parseVlanDeclares(fields []string) ([]int, bool) {
	if len(fields) != 2 || fields[0] != "vlan" {
		return nil, false
	}
	parts := strings.Split(fields[1], ",")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, false
		}
		vid, err := strconv.Atoi(part)
		if err != nil || vid <= 0 {
			return nil, false
		}
		out = append(out, vid)
	}
	return out, true
}

// parseVlanMembership matches "vlan <id> port 0/<port>
// untagged|tagged" (exactly five fields). PROVISIONAL (pinned live in
// phase 0a).
func parseVlanMembership(fields []string) (vlanMember, bool) {
	if len(fields) != 5 || fields[0] != "vlan" || fields[2] != "port" {
		return vlanMember{}, false
	}
	vid, err := strconv.Atoi(fields[1])
	if err != nil || vid <= 0 {
		return vlanMember{}, false
	}
	if !strings.HasPrefix(fields[3], "0/") {
		return vlanMember{}, false
	}
	port, err := strconv.Atoi(strings.TrimPrefix(fields[3], "0/"))
	if err != nil || port <= 0 {
		return vlanMember{}, false
	}
	var m model.PortMembership
	switch fields[4] {
	case "untagged":
		m = model.PortMembershipUntagged
	case "tagged":
		m = model.PortMembershipTagged
	default:
		return vlanMember{}, false
	}
	return vlanMember{vid: vid, port: port, m: m}, true
}

// parseVlanPVID matches "vlan pvid <id>" (exactly three fields).
// PROVISIONAL (pinned live in phase 0a).
func parseVlanPVID(fields []string) (int, bool) {
	if len(fields) != 3 || fields[0] != "vlan" || fields[1] != "pvid" {
		return 0, false
	}
	vid, err := strconv.Atoi(fields[2])
	if err != nil || vid <= 0 {
		return 0, false
	}
	return vid, true
}

// --- render side ---

// captureForeign collects the unmanaged content lines per managed
// section (everything that is not a `vlan `-prefixed line — the
// managed grammar is this driver's property). Part of the same
// PROVISIONAL grammar umbrella (pinned live in phase 0a).
func captureForeign(tc fastpath.TextConfig) map[string][]string {
	foreign := map[string][]string{}
	collect := func(label string) {
		body, ok := tc.SectionBody(label)
		if !ok {
			return
		}
		for _, raw := range body {
			line := strings.TrimRight(raw, "\r")
			if strings.HasPrefix(strings.TrimSpace(line), "vlan ") {
				continue // managed grammar line: desired state replaces it
			}
			foreign[label] = append(foreign[label], line)
		}
	}
	collect(vlanDatabaseLabel)
	for port := 1; port <= defaultPortCount; port++ {
		collect(fmt.Sprintf("interface 0/%d", port))
	}
	return foreign
}

// renderVLANState splices the desired (normalized) state into the
// editor and renders upload bytes. Foreign lines inside managed
// sections are preserved FIRST (original order), generated grammar
// lines follow. Untouched sections — the `configure` preamble,
// `interface 3/x`, and any managed section the current config lacks —
// are never spliced.
// PROVISIONAL (pinned live in phase 0a).
func renderVLANState(editor *fastpath.TextConfigEditor, state model.VLANState, foreign map[string][]string) ([]byte, error) {
	dbBody := append([]string{}, foreign[vlanDatabaseLabel]...)
	dbBody = append(dbBody, generateVlanDatabaseBody(state)...)
	if err := editor.ReplaceSectionBody(vlanDatabaseLabel, dbBody); err != nil {
		return nil, err
	}

	for port := 1; port <= defaultPortCount; port++ {
		label := fmt.Sprintf("interface 0/%d", port)
		var managed []string
		if state.PVIDs[port] != defaultPVID {
			managed = append(managed, vlanPVIDLine(port, state.PVIDs[port]))
		}
		body := append(append([]string{}, foreign[label]...), managed...)
		if err := editor.ReplaceSectionBody(label, body); err != nil {
			return nil, err
		}
	}

	upload, err := editor.Render()
	if err != nil {
		return nil, err
	}
	return upload, nil
}

// generateVlanDatabaseBody emits the vlan database body for the
// desired state:
//   - `vlan <id>` declarations for every non-default VLAN (VLAN 1 is
//     implicit), ascending;
//   - per-port membership lines for every non-ignored membership,
//     ports ascending; for VLAN 1 only TAGGED lines are generated (a
//     VLAN 1 untagged membership is exactly the factory-implicit
//     "everything untagged, PVID 1" state, reproduced by absence).
//
// A fully default state therefore generates NOTHING, which reproduces
// the factory file byte-identically. PROVISIONAL (pinned live in
// phase 0a).
func generateVlanDatabaseBody(state model.VLANState) []string {
	var out []string
	for _, vid := range sortedStateVLANs(state) {
		if vid != defaultPVID {
			out = append(out, vlanDeclareLine(vid))
		}
		vlan := state.VLANs[vid]
		for port := 1; port <= state.PortCount; port++ {
			m, ok := vlan.Ports[port]
			if !ok || m == model.PortMembershipIgnored {
				continue
			}
			if vid == defaultPVID && m == model.PortMembershipUntagged {
				continue // implicit factory membership
			}
			out = append(out, vlanMembershipLine(vid, port, m))
		}
	}
	return out
}

// --- PROVISIONAL grammar renderers (pinned live in phase 0a) ---

// vlanDeclareLine renders the declaration template. LIVE-PINNED
// (2026-09-16 bench evidence, see the file banner).
func vlanDeclareLine(vid int) string {
	return fmt.Sprintf("vlan %d", vid)
}

// vlanMembershipLine renders the membership template.
// PROVISIONAL (pinned live in phase 0a).
func vlanMembershipLine(vid, port int, m model.PortMembership) string {
	return fmt.Sprintf("vlan %d port 0/%d %s", vid, port, m)
}

// vlanPVIDLine renders the PVID template.
// PROVISIONAL (pinned live in phase 0a).
func vlanPVIDLine(port, vid int) string {
	return fmt.Sprintf("vlan pvid %d", vid)
}

// sortedDeclared sorts a declared-VLAN set.
func sortedDeclared(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for vid := range set {
		out = append(out, vid)
	}
	sort.Ints(out)
	return out
}

// sortedStateVLANs returns the state's VLAN IDs ascending.
func sortedStateVLANs(state model.VLANState) []int {
	ids := make([]int, 0, len(state.VLANs))
	for vid := range state.VLANs {
		ids = append(ids, vid)
	}
	sort.Ints(ids)
	return ids
}

// validateRenderable is the driver-side semantic guard for a desired
// state, covering what the model cannot know: at most one untagged
// VLAN per port, and every PVID's VLAN must carry the port UNTAGGED
// (that is what PVID means on this firmware). PROVISIONAL — may relax
// when the live grammar is pinned in phase 0a.
func validateRenderable(state model.VLANState) error {
	if state.PortCount != defaultPortCount {
		return &ErrInvalidDesiredState{
			Reason: fmt.Sprintf("port count %d unsupported on gs108tv2 (managed range 1..%d)", state.PortCount, defaultPortCount),
		}
	}
	if err := state.Validate(); err != nil {
		return &ErrInvalidDesiredState{Reason: err.Error()}
	}
	for port := 1; port <= state.PortCount; port++ {
		untagged := 0
		for _, vlan := range state.VLANs {
			if vlan.Ports[port] == model.PortMembershipUntagged {
				untagged++
			}
		}
		if untagged > 1 {
			return &ErrInvalidDesiredState{
				Reason: fmt.Sprintf("port %d carries %d untagged memberships; firmware supports at most one", port, untagged),
			}
		}
		if vid := state.PVIDs[port]; state.VLANs[vid].Ports[port] != model.PortMembershipUntagged {
			return &ErrInvalidDesiredState{
				Reason: fmt.Sprintf("pvid %d for port %d requires an untagged membership there", vid, port),
			}
		}
	}
	return nil
}

// ErrInvalidDesiredState is the typed rejection of a semantically
// impossible desired state (the model shape passes model.Validate but
// the FASTPATH untagged/PVID contract cannot express it).
type ErrInvalidDesiredState struct {
	Reason string
}

func (e *ErrInvalidDesiredState) Error() string {
	return "gs108tv2: invalid desired VLAN state: " + e.Reason
}
