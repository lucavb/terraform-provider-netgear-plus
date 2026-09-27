package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/cfg"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/client/gs108tv2"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/fastpath"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

const restoreWaitTimeout = 5 * time.Minute

func main() {
	var (
		host      = flag.String("host", "", "Switch hostname or URL (HTTP) or NSDP unicast destination (with -agent-mac)")
		agentMAC  = flag.String("agent-mac", "", "Switch (agent) MAC for NSDP, e.g. 8c:3b:ad:2c:e9:7d")
		ifaceName = flag.String("iface", "", "Local interface for NSDP (default: first usable non-loopback)")
		password  = flag.String("password", "", "Switch password")
		modelName = flag.String("model", client.ModelGS108Ev3, "Switch model (gs108ev3 or gs108tv2)")
		op        = flag.String("op", "switch", "Operation: switch, vlans, apply, restore, config, restore-config, apply-vlan-state, apply-port-settings, or reboot")
		stateFile = flag.String("state-file", "", "Path to JSON VLAN state for apply")
		file      = flag.String("file", "", "Path to a .cfg backup for restore, or the text config to push for -op restore-config")
		roundtrip = flag.Bool("roundtrip", false, "For restore: fetch the current config and restore it verbatim")
		timeout   = flag.Int64("timeout", 15, "HTTP timeout in seconds")
		tftpFile  = flag.String("config-file", "", "-op config: /filesystem virtual file name (default startup-config)")
		outFile   = flag.String("out", "", "Where -op config writes the fetched config")
	)
	flag.Parse()

	// NSDP path: identity facts (+ the v1 guard surface) without any
	// HTTP session — exercises the same library the provider's
	// withNSDPClient/nsdpV1Guard paths use.
	if *agentMAC != "" {
		runNSDP(*ifaceName, *agentMAC, *password, *modelName, *op, *host)
		return
	}

	// FASTPATH config-file (emweb HTTP) path — mirrors the
	// netgear_plus_switch_config data source exactly: SID login,
	// arming GET, then GET /filesystem/<file>.
	if *op == "config" {
		if *host == "" {
			log.Fatal("-host is required for -op config (emweb needs the switch address)")
		}
		if *password == "" {
			log.Fatal("-password is required for -op config (emweb session login)")
		}
		sess, err := fastpath.WebLogin(*host, *password, time.Duration(*timeout)*time.Second)
		if err != nil {
			log.Fatalf("web login: %v", err)
		}
		cfgFile := *tftpFile
		if cfgFile == "" {
			cfgFile = "startup-config"
		}
		var raw []byte
		if cfgFile == "startup-config" {
			raw, err = sess.SaveConfig()
		} else {
			raw, err = sess.GetFile(cfgFile)
		}
		if err != nil {
			log.Fatalf("download %s: %v", cfgFile, err)
		}
		if *outFile != "" {
			if err := os.WriteFile(*outFile, raw, 0o644); err != nil {
				log.Printf("note: could not write %s: %v", *outFile, err)
			} else {
				fmt.Printf("config saved to %s\n", *outFile)
			}
		}
		tc, err := fastpath.ParseTextConfig(raw)
		if err != nil {
			// image1/image2 and other /filesystem files need not
			// parse as text config.
			printJSON(map[string]any{
				"host":  *host,
				"file":  cfgFile,
				"bytes": len(raw),
				"note":  "content is not a parseable text config",
			})
			return
		}
		printJSON(map[string]any{
			"host":                    *host,
			"file":                    cfgFile,
			"bytes":                   len(tc.Raw),
			"header":                  tc.Header,
			"system_description":      tc.SystemDescription,
			"system_software_version": tc.SystemSoftwareVersion,
			"sections":                tc.Sections,
		})
		return
	}

	// FASTPATH restore (emweb HTTP upload) — pushes a local text
	// config through /base/system/http_file_download.html (multipart
	// .filename_handle, submt=16 activation token).
	if *op == "restore-config" {
		if *host == "" || *password == "" {
			log.Fatal("-host and -password are required for -op restore-config")
		}
		if *file == "" {
			log.Fatal("-file is required for -op restore-config (path to the text config to push)")
		}
		content, err := os.ReadFile(*file)
		if err != nil {
			log.Fatal(err)
		}
		sess, err := fastpath.WebLogin(*host, *password, time.Duration(*timeout)*time.Second)
		if err != nil {
			log.Fatalf("web login: %v", err)
		}
		res, err := sess.ConfigRestore(content, filepath.Base(*file))
		if err != nil {
			log.Fatalf("restore: %v", err)
		}
		if res.Failed() {
			log.Fatalf("restore rejected: %s", res.Error())
		}
		printJSON(map[string]any{
			"host":            *host,
			"file":            filepath.Base(*file),
			"bytes":           len(content),
			"http_status":     res.HTTPStatus,
			"download_status": res.DownloadStatus,
			"err_flag":        res.ErrFlag,
		})
		return
	}

	if *op == "apply-vlan-state" {
		runApplyVLANState(*host, *password, *timeout, *file)
		return
	}

	if *op == "reboot" {
		runRebootOp(*host, *password, *timeout)
		return
	}

	if *op == "apply-port-settings" {
		runApplyPortSettings(*host, *password, *timeout, *file)
		return
	}

	if *host == "" || *password == "" {
		log.Fatal("-host and -password are required")
	}

	driver, err := client.NewDriver(client.Config{
		Host:           *host,
		Password:       *password,
		Model:          *modelName,
		RequestTimeout: *timeout,
		InsecureHTTP:   true,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = driver.Logout(context.Background())
	}()

	ctx := context.Background()
	switch *op {
	case "switch":
		facts, err := driver.ReadSwitchFacts(ctx)
		if err != nil {
			log.Fatal(err)
		}
		printJSON(facts)
	case "vlans":
		state, err := driver.ReadVLANState(ctx)
		if err != nil {
			log.Fatal(err)
		}
		printJSON(state)
	case "apply":
		if *stateFile == "" {
			log.Fatal("-state-file is required for -op apply")
		}
		state, err := readStateFile(*stateFile)
		if err != nil {
			log.Fatal(err)
		}
		if err := driver.ApplyVLANState(ctx, state); err != nil {
			log.Fatal(err)
		}
		fmt.Println("apply completed")
	case "restore":
		runRestore(ctx, driver, *file, *roundtrip)
	default:
		log.Fatalf("unsupported op %q", *op)
	}
}

// validateRestoreFlags enforces the exactly-one rule for restore inputs:
// -file (upload a backup from disk) or -roundtrip (re-upload the switch's
// current config verbatim).
func validateRestoreFlags(file string, roundtrip bool) error {
	if (file != "") == roundtrip {
		return errors.New("exactly one of -file or -roundtrip is required for -op restore")
	}
	return nil
}

// runRestore uploads a configuration backup to the switch and waits for the
// restore reboot to finish, printing before/after config fingerprints.
// Either file or roundtrip must be set; roundtrip restores the switch's own
// current config bytes verbatim, which is state-identical.
func runRestore(ctx context.Context, driver client.Driver, file string, roundtrip bool) {
	if err := validateRestoreFlags(file, roundtrip); err != nil {
		log.Fatal(err)
	}

	var (
		cfgBytes []byte
		before   string
	)

	switch {
	case roundtrip:
		config, err := driver.ReadConfig(ctx)
		if err != nil {
			log.Fatal(err)
		}
		cfgBytes = config.Raw
		before = config.Fingerprint()
	default:
		data, err := os.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		parsed, err := cfg.ParseConfig(data)
		if err != nil {
			log.Fatalf("invalid config backup %s: %v", file, err)
		}
		cfgBytes = data
		before = parsed.Fingerprint()
	}

	fmt.Printf("before: config checksum %s (%d bytes)\n", before, len(cfgBytes))

	if err := driver.RestoreConfigAndWait(ctx, cfgBytes, restoreWaitTimeout); err != nil {
		log.Fatal(err)
	}

	after, err := driver.ReadConfig(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("after: config checksum %s\n", after.Fingerprint())

	if after.Fingerprint() != before {
		log.Fatalf("restore verification mismatch: before %s, after %s", before, after.Fingerprint())
	}
	fmt.Println("restore completed; fingerprints match")
}

// validateApplyVLANStateFlags enforces the -op apply-vlan-state flag
// contract: host, password, and a JSON spec file (pure — no sockets, no
// flag package involvement, mirrors validateRestoreFlags).
func validateApplyVLANStateFlags(host, password, file string) error {
	if host == "" || password == "" || file == "" {
		return errors.New("-host, -password and -file are required for -op apply-vlan-state (-file is the JSON VLAN spec)")
	}
	return nil
}

// vlanStateSpec is the JSON input shape of -op apply-vlan-state:
//
//	{"vlans":[{"id":42,"ports":{"1":"tagged","2":"untagged"}}],"pvids":{"1":1}}
//
// Port keys are user port numbers 1..8; membership values are
// "tagged" or "untagged"; omitted ports are left untouched by
// normalization (they render as "ignored" only when the VLAN is absent
// from a port's PVID target and no membership was asked).
type vlanStateSpec struct {
	VLANs []struct {
		ID    int               `json:"id"`
		Ports map[string]string `json:"ports"`
	} `json:"vlans"`
	PVIDs map[string]int64 `json:"pvids"`
}

// parseApplyVLANStateSpec decodes and validates the JSON spec into a
// model.VLANState over 8 ports (pure — testable without a switch).
func parseApplyVLANStateSpec(data []byte) (model.VLANState, error) {
	var spec vlanStateSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return model.VLANState{}, fmt.Errorf("decode VLAN spec JSON: %w", err)
	}

	state := model.VLANState{
		PortCount: 8,
		VLANs:     make(map[int]model.Vlan, len(spec.VLANs)),
		PVIDs:     make(map[int]int, len(spec.PVIDs)),
	}

	for portKey, pvid := range spec.PVIDs {
		port, err := specPortKey(portKey)
		if err != nil {
			return model.VLANState{}, err
		}
		state.PVIDs[port] = int(pvid)
	}

	for _, vlan := range spec.VLANs {
		if vlan.ID <= 0 || vlan.ID > 4094 {
			return model.VLANState{}, fmt.Errorf("vlan id %d out of range 1..4094", vlan.ID)
		}
		ports := make(map[int]model.PortMembership, len(vlan.Ports))
		for portKey, membership := range vlan.Ports {
			port, err := specPortKey(portKey)
			if err != nil {
				return model.VLANState{}, err
			}
			switch membership {
			case "tagged":
				ports[port] = model.PortMembershipTagged
			case "untagged":
				ports[port] = model.PortMembershipUntagged
			default:
				return model.VLANState{}, fmt.Errorf("vlan %d port %d: membership %q must be \"tagged\" or \"untagged\"", vlan.ID, port, membership)
			}
		}
		state.VLANs[vlan.ID] = model.Vlan{ID: vlan.ID, Ports: ports}
	}

	return state.Normalize(), nil
}

// specPortKey parses a user port key: a plain decimal port number 1..8.
func specPortKey(key string) (int, error) {
	port, err := strconv.Atoi(key)
	if err != nil {
		return 0, fmt.Errorf("invalid port key %q: must be a port number 1..8", key)
	}
	if port < 1 || port > 8 {
		return 0, fmt.Errorf("port key %d out of range 1..8", port)
	}
	return port, nil
}

// runApplyVLANState stages a desired VLAN state into a GS108Tv2
// startup-config over the emweb text-config channel (NO reboot; the
// switch converges within its own ingest window while the driver
// polls). Prints staged/canonical-diverged/fingerprint plus the
// driver's typed error classification.
func runApplyVLANState(host, password string, timeout int64, file string) {
	if err := validateApplyVLANStateFlags(host, password, file); err != nil {
		log.Fatal(err)
	}
	specData, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	state, err := parseApplyVLANStateSpec(specData)
	if err != nil {
		log.Fatal(err)
	}

	drv := gs108tv2.New(gs108tv2.Config{
		Host:     host,
		Password: password,
		Timeout:  time.Duration(timeout) * time.Second,
	})
	ctx := context.Background()
	if err := drv.Login(ctx); err != nil {
		log.Fatalf("login: %v", err)
	}

	outcome, err := drv.ApplyVLANState(ctx, state)

	result := map[string]any{
		"host":               host,
		"staged":             outcome.Staged,
		"canonical_diverged": outcome.CanonicalDiverged,
	}
	if fp, ferr := drv.Fingerprint(ctx); ferr == nil {
		result["fingerprint"] = fp
	}
	if err != nil {
		result["error"] = err.Error()
		result["error_type"] = classifyApplyVLANStateError(err)
	}
	printJSON(result)

	// Typed surfaces get human follow-ups after the JSON block so ops
	// see both the machine result and the plain-language note.
	switch typed := err.(type) {
	case nil:
	case *gs108tv2.ErrRestoreRejected:
		log.Printf("note: the switch rejected the restore POST itself (upload never left the gate): %s", typed.Detail)
	case *gs108tv2.ErrRestoreDeadline:
		log.Printf("note: startup-config never verified within %s (last failure class %q)", typed.Wait, typed.LastClass)
	case *gs108tv2.ErrDriftDetected:
		log.Printf("note: the staged file decodes to a DIFFERENT state than desired (real drift): %s", typed.Detail)
	case *gs108tv2.ErrGrammarLine:
		log.Printf("note: unsupported config grammar line: %s", typed.Error())
	case *gs108tv2.ErrInvalidDesiredState:
		log.Printf("note: the desired state is not renderable on this firmware: %s", typed.Reason)
	}
}

// classifyApplyVLANStateError maps the driver's typed errors to a
// short machine-readable classification.
func classifyApplyVLANStateError(err error) string {
	switch err.(type) {
	case *gs108tv2.ErrRestoreRejected:
		return "restore_rejected"
	case *gs108tv2.ErrRestoreDeadline:
		return "restore_deadline"
	case *gs108tv2.ErrDriftDetected:
		return "drift_detected"
	case *gs108tv2.ErrGrammarLine:
		return "grammar_line"
	case *gs108tv2.ErrMissingSection:
		return "missing_section"
	case *gs108tv2.ErrInvalidDesiredState:
		return "invalid_desired_state"
	}
	return "error"
}

func readStateFile(path string) (model.VLANState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.VLANState{}, fmt.Errorf("read state file: %w", err)
	}

	var state model.VLANState
	if err := json.Unmarshal(data, &state); err != nil {
		return model.VLANState{}, fmt.Errorf("decode state file: %w", err)
	}

	return state.Normalize(), nil
}

// runNSDP drives the read rallies against a live switch over NSDP:
// identity facts always; when the model is a v1 switch the VLAN-state op
// must REFUSE with the provenance error (nsdpV1Guard mirror) — that
// refusal is itself an e2e contract of the provider path.
func runNSDP(iface, agentMAC, password, modelName, op, dest string) {
	model := strings.ToLower(strings.TrimSpace(modelName))
	cl, err := nsdp.NewClient(nsdp.Options{
		IfaceName: iface,
		AgentMAC:  agentMAC,
		Password:  []byte(password),
		Dest:      dest,
		LegacyV1:  model == client.ModelGS108Tv2,
	})
	if err != nil {
		log.Fatalf("nsdp client: %v", err)
	}
	defer cl.Close()

	switch op {
	case "switch":
		id, err := cl.GetIdentity()
		if err != nil {
			log.Fatalf("read identity: %v", err)
		}
		printJSON(id)
	case "vlans":
		if cl.IsV1() {
			log.Fatalf("802.1Q VLAN state is not supported over NSDP v1 (%s-class firmware): the v1 engine has no VLAN datatypes", model)
		}
		memberships, err := cl.Get8021QVLANs()
		if err != nil {
			log.Fatalf("read 802.1q vlan table: %v", err)
		}
		printJSON(memberships)
	default:
		log.Fatalf("unsupported op %q for NSDP (supported: switch, vlans)", op)
	}
}

// printJSON(value any) flops into the shared printer below.
// runNSDP drives the NSDP ops below.

// PrintJSON prints v as indented JSON (shared with NSDP paths).
func printJSON(value any) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(encoded))
}

// ---------------------------------------------------------------------------
// -op reboot (phase-5 bench battery workhorse): guarded reboot + wait.
// ---------------------------------------------------------------------------

// validateRebootFlags enforces the -op reboot flag contract (pure —
// no sockets, no flag package involvement, mirrors
// validateApplyVLANStateFlags).
func validateRebootFlags(host, password string) error {
	if host == "" || password == "" {
		return errors.New("-host and -password are required for -op reboot")
	}
	return nil
}

// runRebootOp reboots the switch (endpoint-sentinel-guarded) and waits
// for it to come back with the startup-config intact. The sentinel
// preflight prints the driver's typed actionable message and exits
// non-zero BEFORE any HTTP traffic — the phase-0b pinning gate.
func runRebootOp(host, password string, timeout int64) {
	if err := validateRebootFlags(host, password); err != nil {
		log.Fatal(err)
	}

	// Sentinel preflight (mirrors the driver's RebootAndWait guard;
	// a pinned endpoint still re-checks inside the driver).
	if strings.TrimSpace(gs108tv2.RebootEndpoint) == "" {
		unavailable := &gs108tv2.ErrRebootUnavailable{
			Detail: "reboot endpoint not yet pinned for FASTPATH 5.4.2.36; refusing to reboot — pin it in phase 0b before enabling reboot_to_apply",
		}
		printJSON(map[string]any{
			"host":       host,
			"rebooted":   false,
			"error":      unavailable.Error(),
			"error_type": "reboot_unavailable",
		})
		fmt.Fprintln(os.Stderr, "note: "+unavailable.Error())
		os.Exit(1)
	}

	drv := gs108tv2.New(gs108tv2.Config{Host: host, Password: password, Timeout: time.Duration(timeout) * time.Second})
	ctx := context.Background()
	if err := drv.Login(ctx); err != nil {
		log.Fatalf("login: %v", err)
	}

	outcome, err := drv.RebootAndWait(ctx)

	result := map[string]any{
		"host":         host,
		"rebooted":     outcome.Rebooted,
		"uptime_reset": outcome.UptimeReset,
	}
	if outcome.Fingerprint != "" {
		result["fingerprint"] = outcome.Fingerprint
	}
	if err != nil {
		result["error"] = err.Error()
		result["error_type"] = classifyRebootError(err)
	}
	printJSON(result)

	if err != nil {
		log.Printf("note: reboot failed: %v", err)
	}
}

// classifyRebootError maps the reboot typed errors to a short
// machine-readable classification.
func classifyRebootError(err error) string {
	switch err.(type) {
	case *gs108tv2.ErrRebootUnavailable:
		return "reboot_unavailable"
	case *gs108tv2.ErrRebootDeadline:
		return "reboot_deadline"
	case *gs108tv2.ErrRebootConfigDrift:
		return "reboot_config_drift"
	}
	return "error"
}

// ---------------------------------------------------------------------------
// -op apply-port-settings (phase-5 bench battery workhorse).
// ---------------------------------------------------------------------------

// portSettingsSpec is the JSON input shape of -op apply-port-settings:
//
//	{"ports":[{"port":3,"enabled":true,"flow_control":true,
//	          "qos_priority":"low","ingress_rate":"none","egress_rate":"none"}]}
//
// Port numbers are 1..8, once each; omitted fields keep the factory
// default for that port (defaults render by absence on the firmware).
type portSettingsSpecEntry struct {
	Port        *int    `json:"port"`
	Enabled     *bool   `json:"enabled"`
	FlowControl *bool   `json:"flow_control"`
	QoSPriority *string `json:"qos_priority"`
	IngressRate *string `json:"ingress_rate"`
	EgressRate  *string `json:"egress_rate"`
}

type portSettingsSpec struct {
	Ports []portSettingsSpecEntry `json:"ports"`
}

// parsePortSettingsSpec decodes and validates the JSON spec into a full
// 1..8 gs108tv2.PortSettings map (pure — testable without a switch).
// Validation mirrors the driver's validatePortSettings vocabulary
// locally so a malformed spec fails before any network traffic.
func parsePortSettingsSpec(data []byte) (map[int]gs108tv2.PortSettings, error) {
	var spec portSettingsSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("decode port settings spec JSON: %w", err)
	}

	settings := gs108tv2.DefaultPortSettingsMap()
	seen := make(map[int]bool, len(spec.Ports))
	for _, entry := range spec.Ports {
		if entry.Port == nil {
			return nil, fmt.Errorf("ports entry has no port number")
		}
		port := *entry.Port
		if port < 1 || port > 8 {
			return nil, fmt.Errorf("port %d out of range 1..8", port)
		}
		if seen[port] {
			return nil, fmt.Errorf("port %d appears twice in the spec (entries must name each port once)", port)
		}
		seen[port] = true
		ps := settings[port]

		if entry.Enabled != nil {
			ps.Enabled = *entry.Enabled
		}
		if entry.FlowControl != nil {
			ps.FlowControl = *entry.FlowControl
		}
		if entry.QoSPriority != nil {
			if err := specQoSPriority(*entry.QoSPriority); err != nil {
				return nil, err
			}
			ps.QoSPriority = strings.ToLower(strings.TrimSpace(*entry.QoSPriority))
		}
		if entry.IngressRate != nil {
			if err := specRateLimit(*entry.IngressRate); err != nil {
				return nil, err
			}
			ps.IngressRate = strings.ToLower(strings.TrimSpace(*entry.IngressRate))
		}
		if entry.EgressRate != nil {
			if err := specRateLimit(*entry.EgressRate); err != nil {
				return nil, err
			}
			ps.EgressRate = strings.ToLower(strings.TrimSpace(*entry.EgressRate))
		}
		settings[port] = ps
	}
	return settings, nil
}

func specQoSPriority(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high", "middle", "normal", "low":
		return nil
	}
	return fmt.Errorf("invalid qos_priority %q: want one of high, middle, normal, low", value)
}

func specRateLimit(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "none", "512k", "1m", "2m", "4m", "8m", "16m", "32m", "64m", "128m", "256m", "512m":
		return nil
	}
	return fmt.Errorf("invalid rate limit %q: want one of none, 512k, 1m, 2m, 4m, 8m, 16m, 32m, 64m, 128m, 256m, 512m", value)
}

// runApplyPortSettings stages a desired port-settings map into a
// GS108Tv2 startup-config (NO reboot) and prints the staged outcome +
// typed error classification, mirroring -op apply-vlan-state.
func runApplyPortSettings(host, password string, timeout int64, file string) {
	if err := validateApplyVLANStateFlags(host, password, file); err != nil {
		log.Fatal(err)
	}
	specData, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	settings, err := parsePortSettingsSpec(specData)
	if err != nil {
		log.Fatal(err)
	}

	drv := gs108tv2.New(gs108tv2.Config{
		Host:     host,
		Password: password,
		Timeout:  time.Duration(timeout) * time.Second,
	})
	ctx := context.Background()
	if err := drv.Login(ctx); err != nil {
		log.Fatalf("login: %v", err)
	}

	outcome, err := drv.ApplyPortSettings(ctx, settings)

	result := map[string]any{
		"host":               host,
		"staged":             outcome.Staged,
		"canonical_diverged": outcome.CanonicalDiverged,
	}
	if fp, ferr := drv.Fingerprint(ctx); ferr == nil {
		result["fingerprint"] = fp
	}
	if err != nil {
		result["error"] = err.Error()
		result["error_type"] = classifyApplyPortSettingsError(err)
	}
	printJSON(result)

	switch typed := err.(type) {
	case nil:
	case *gs108tv2.ErrUnsupportedAttribute:
		log.Printf("note: %s (%s)", typed.Error(), typed.Reason)
	case *gs108tv2.ErrRestoreRejected:
		log.Printf("note: the switch rejected the restore POST itself (upload never left the gate): %s", typed.Detail)
	case *gs108tv2.ErrRestoreDeadline:
		log.Printf("note: startup-config never verified within %s (last failure class %q)", typed.Wait, typed.LastClass)
	case *gs108tv2.ErrDriftDetected:
		log.Printf("note: the staged file decodes to a DIFFERENT state than desired (real drift): %s", typed.Detail)
	}
}

// classifyApplyPortSettingsError maps the driver's typed errors to a
// short machine-readable classification for the port op.
func classifyApplyPortSettingsError(err error) string {
	switch err.(type) {
	case *gs108tv2.ErrUnsupportedAttribute:
		return "unsupported_attribute"
	case *gs108tv2.ErrRestoreRejected:
		return "restore_rejected"
	case *gs108tv2.ErrRestoreDeadline:
		return "restore_deadline"
	case *gs108tv2.ErrDriftDetected:
		return "drift_detected"
	case *gs108tv2.ErrGrammarLine:
		return "grammar_line"
	case *gs108tv2.ErrMissingSection:
		return "missing_section"
	case *gs108tv2.ErrInvalidDesiredState:
		return "invalid_desired_state"
	}
	return "error"
}
