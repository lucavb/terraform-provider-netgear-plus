package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/cfg"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

const restoreWaitTimeout = 5 * time.Minute

func main() {
	var (
		host      = flag.String("host", "", "Switch hostname or URL")
		password  = flag.String("password", "", "Switch password")
		modelName = flag.String("model", client.ModelGS108Ev3, "Switch model")
		op        = flag.String("op", "switch", "Operation: switch, vlans, apply, or restore")
		stateFile = flag.String("state-file", "", "Path to JSON VLAN state for apply")
		file      = flag.String("file", "", "Path to a .cfg backup for restore")
		roundtrip = flag.Bool("roundtrip", false, "For restore: fetch the current config and restore it verbatim")
		timeout   = flag.Int64("timeout", 15, "HTTP timeout in seconds")
	)
	flag.Parse()

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

func printJSON(value any) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(encoded))
}
