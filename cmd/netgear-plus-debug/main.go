package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

func main() {
	var (
		host      = flag.String("host", "", "Switch hostname or URL")
		password  = flag.String("password", "", "Switch password")
		modelName = flag.String("model", client.ModelGS108Ev3, "Switch model")
		op        = flag.String("op", "switch", "Operation: switch, vlans, or apply")
		stateFile = flag.String("state-file", "", "Path to JSON VLAN state for apply")
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
	default:
		log.Fatalf("unsupported op %q", *op)
	}
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
