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
	"strings"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/cfg"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
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
		op        = flag.String("op", "switch", "Operation: switch, vlans, apply, restore, config, or restore-config")
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
