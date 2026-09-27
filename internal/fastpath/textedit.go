package fastpath

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Line-splice editor for FASTPATH text configs.
//
// There is deliberately NO serializer: mutations are line splices on a
// copy of TextConfig.Raw, so every byte outside the edited region stays
// byte-identical by construction — including the firmware-validated
// NSDP magic header, the !System comment block, blank-line runs and
// the trailing newline. This is the safety property the restore path
// leans on: the switch's own startup-config parser sees an untouched
// file except for the lines the editor replaced.
//
// The file style is DOUBLE-SPACED: every content line is followed by
// exactly one blank line. All insertions/replacements below reproduce
// that style and never introduce consecutive blank lines or lose the
// EOF newline.
//
// The editor never touches a section other than the one named:
// ReplaceSectionBody swaps only that section's editable body span
// (from ParseTextConfig spans), InsertSection appends a complete block
// after the named section's exit line, DeleteSection removes exactly
// one block. Protected sections (see protectedSections) are refused.
// ---------------------------------------------------------------------------

// TextConfigEditor performs surgical line-splice mutations on a copy
// of a parsed text config and renders the mutated bytes back. The
// working state is the full line array (strings.Split of Raw on "\n",
// with any "\r" bytes still inside the line content), so a no-op round
// trip — construct, Render — reproduces Raw byte-for-byte.
type TextConfigEditor struct {
	// lines is the working copy of the config, one element per line
	// (no trailing "\n"; Render joins with "\n").
	lines []string

	// tc mirrors the current working state: it is re-parsed after
	// every successful mutation so section spans always address the
	// live line array, never a stale one.
	tc TextConfig

	// dirty reports whether any mutation has been applied.
	dirty bool
}

// NewTextConfigEditor opens a mutation session over tc's raw bytes.
// Only ParseTextConfig-compatible input is accepted: the test of that
// is simply re-parsing the Raw bytes here, which also guarantees the
// editor's section spans are self-consistent with the bytes it will
// splice.
func NewTextConfigEditor(tc TextConfig) (*TextConfigEditor, error) {
	if len(tc.Raw) == 0 {
		return nil, fmt.Errorf("fastpath: edit: empty text config")
	}
	parsed, err := ParseTextConfig(tc.Raw)
	if err != nil {
		return nil, fmt.Errorf("fastpath: edit: %w", err)
	}
	return &TextConfigEditor{
		lines: strings.Split(string(parsed.Raw), "\n"),
		tc:    parsed,
	}, nil
}

// ReplaceSectionBody swaps the editable body region of the section
// named label for the given content lines, re-emitted in the file's
// double-spaced style (one blank after the label, one blank after
// each content line — the trailing doubles as the exit separator).
// The section's label and closing exit line survive untouched, so the
// rendered block stays firmware-parseable; an empty body reduces the
// section to the factory "vlan database" shape (label, blank, exit).
// Everything before the label line and after the exit line is
// byte-identical to the original. Errors when the section does not
// exist.
func (e *TextConfigEditor) ReplaceSectionBody(label string, body []string) error {
	s, _, ok := e.section(label)
	if !ok {
		return fmt.Errorf("fastpath: edit: text config has no section %q", label)
	}
	e.lines = spliceRegion(e.lines, s.BodyStart, s.BodyEnd, doubleSpacedBody(body))
	return e.sync()
}

// InsertSection appends a complete, well-formed section block — label
// line, blank, double-spaced body lines, exit line, blank — directly
// after the block named afterLabel (behind its closing exit line, so
// the new block lands at the same nesting level). Errors when the new
// label already exists, when afterLabel does not exist, or when the
// new label is empty.
func (e *TextConfigEditor) InsertSection(afterLabel, label string, body []string) error {
	if strings.TrimSpace(label) == "" {
		return fmt.Errorf("fastpath: edit: empty section label")
	}
	if _, _, exists := e.section(label); exists {
		return fmt.Errorf("fastpath: edit: section %q already exists", label)
	}
	s, _, ok := e.section(afterLabel)
	if !ok {
		return fmt.Errorf("fastpath: edit: text config has no section %q to insert after", afterLabel)
	}

	// Insertion point: the first content position after the anchor's
	// block — behind its own exit line for block sections, behind its
	// body span for flat sections. Blank lines already in place (the
	// anchor's trailing separator) are skipped, and the new block ends
	// with its own blank, so no consecutive blank lines appear.
	pos := s.BodyEnd + 1
	if exitIdx, ok := pairSectionExits(e.lines)[s.LabelLine]; ok {
		pos = exitIdx + 1
	}
	for pos < len(e.lines) && blankLine(e.lines[pos]) {
		pos++
	}

	block := []string{label}
	block = append(block, doubleSpacedBody(body)...)
	block = append(block, "exit", "")

	e.lines = spliceRegion(e.lines, pos, pos-1, block)
	return e.sync()
}

// DeleteSection removes exactly one whole section block — the blank
// line after the previous content belongs to that content (the file is
// double-spaced), so removal starts at the label line and extends
// through the block's trailing blank line, keeping single blank
// separation at both junctions. Sections whose deletion would brick
// the restore (see protectedSections) are refused, as are unknown
// labels.
func (e *TextConfigEditor) DeleteSection(label string) error {
	if protectedSections[label] {
		return fmt.Errorf("fastpath: edit: refusing to delete %q: it is required for the config restore to stay valid", label)
	}
	s, _, ok := e.section(label)
	if !ok {
		return fmt.Errorf("fastpath: edit: text config has no section %q", label)
	}

	end := s.BodyEnd // flat section: block ends at the body span
	if exitIdx, ok := pairSectionExits(e.lines)[s.LabelLine]; ok {
		end = exitIdx // block section: block ends at its exit line
	}
	if end+1 < len(e.lines) && blankLine(e.lines[end+1]) {
		end++ // consume the block's own trailing blank line
	}
	e.lines = spliceRegion(e.lines, s.LabelLine, end, nil)
	return e.sync()
}

// Render joins the working line array back to bytes. The bytes carry a
// firmware-validated NSDP magic header (render construction fails
// otherwise), ValidateTextConfigHeader(rendered) passes, and every
// byte outside edited regions is identical to the Raw the editor was
// constructed from.
func (e *TextConfigEditor) Render() ([]byte, error) {
	if len(e.lines) == 0 {
		return nil, fmt.Errorf("fastpath: edit: empty text config")
	}
	if h := strings.TrimRight(e.lines[0], "\r"); !strings.HasPrefix(h, "0x4e47") {
		return nil, fmt.Errorf("fastpath: edit: rendered config lost the NSDP magic header (first line %q)", h)
	}
	return []byte(strings.Join(e.lines, "\n")), nil
}

// Dirty reports whether the editor has applied at least one mutation.
func (e *TextConfigEditor) Dirty() bool {
	return e.dirty
}

// protectedSections is the denylist of DeleteSection: dropping these
// labels leaves a config the firmware can no longer ingest (an empty
// vlan database changes the command stream shape, and a missing
// configure block is not a valid FASTPATH startup-config at all).
var protectedSections = map[string]bool{
	"vlan database": true,
	"configure":     true,
}

// section returns the current parsed view's first section with the
// given label and its position.
func (e *TextConfigEditor) section(label string) (TextConfigSection, int, bool) {
	for i := range e.tc.Sections {
		if e.tc.Sections[i].Label == label {
			return e.tc.Sections[i], i, true
		}
	}
	return TextConfigSection{}, -1, false
}

// sync re-parses the working line array so subsequent mutations see
// up-to-date section spans.
func (e *TextConfigEditor) sync() error {
	parsed, err := ParseTextConfig([]byte(strings.Join(e.lines, "\n")))
	if err != nil {
		// Should not happen: mutations preserve the header line and
		// non-empty content, both of which ParseTextConfig requires.
		return fmt.Errorf("fastpath: edit: re-parse after mutation: %w", err)
	}
	e.tc = parsed
	e.dirty = true
	return nil
}

// blankLine reports whether the line carries no content (whitespace
// and "\r" aside).
func blankLine(line string) bool {
	return strings.TrimSpace(strings.TrimRight(line, "\r")) == ""
}

// doubleSpacedBody builds a section body region in the file's
// double-spaced style: one blank line behind the label, then every
// content line followed by its own blank line, whose last one doubles
// as the separator before the section's exit line. An empty body
// yields the single structural blank between label and exit, exactly
// like the factory "vlan database" block.
func doubleSpacedBody(body []string) []string {
	region := make([]string, 0, 2*len(body)+1)
	region = append(region, "")
	for _, c := range body {
		region = append(region, c, "")
	}
	return region
}

// spliceRegion replaces the inclusive line span [from, to] with the
// given lines (empty to delete the span). from == to+1 with non-empty
// region inserts the region before the line at from.
func spliceRegion(lines []string, from, to int, region []string) []string {
	out := make([]string, 0, len(lines)-(to-from+1)+len(region))
	out = append(out, lines[:from]...)
	out = append(out, region...)
	out = append(out, lines[to+1:]...)
	return out
}
