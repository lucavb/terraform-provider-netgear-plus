// Command cfg2tf converts an FMv2 binary switch configuration backup
// (such as a GS108Ev3 .cfg file) into a Terraform configuration for the
// netgear_plus_vlan_state resource, including a config-driven import block
// so terraform plan can adopt the switch state in one step.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/cfg"
)

const usage = "usage: cfg2tf [flags] <path-to-config.cfg>"

func main() {
	opts := options{}

	fs := flag.NewFlagSet("cfg2tf", flag.ContinueOnError)
	fs.StringVar(&opts.Host, "host", "", "switch host; defaults to the IP stored in the backup's ethconfig section when present (required if the backup has none)")
	fs.StringVar(&opts.Model, "model", "gs108ev3", "switch model, used in the provider block and the import ID")
	fs.StringVar(&opts.Name, "name", "switch", "Terraform resource label")
	fs.StringVar(&opts.Serial, "serial", "", "expected serial number; if empty, reference data.netgear_plus_switch.target.serial_number")
	fs.BoolVar(&opts.AllowDeletions, "allow-deletions", false, "emit allow_vlan_deletions = true")
	fs.BoolVar(&opts.SkipImport, "skip-import", false, "omit the import block and the CLI import comment")
	fs.BoolVar(&opts.Force, "force", false, "emit output even if the decoded state fails validation")
	outPath := fs.String("out", "", "write the .tf file to this path instead of stdout")

	path, err := parseArgs(fs, os.Args[1:])
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(os.Stderr, "cfg2tf: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if path == "" {
		fmt.Fprintln(os.Stderr, usage)
		fs.PrintDefaults()
		os.Exit(1)
	}
	opts.SourcePath = path

	if err := run(opts, *outPath); err != nil {
		fmt.Fprintf(os.Stderr, "cfg2tf: %v\n", err)
		os.Exit(1)
	}
}

// resolveHost fills opts.Host from the backup's ethconfig section when no
// -host was given.
func resolveHost(config *cfg.Config, opts options) (options, error) {
	if opts.Host != "" {
		return opts, nil
	}

	eth, err := config.EthernetConfig()
	if err != nil {
		return opts, fmt.Errorf("no -host given and the backup's ethconfig section is unusable: %w", err)
	}
	if eth == nil {
		return opts, fmt.Errorf("no -host given and the backup has no usable ethconfig section")
	}

	opts.Host = fmt.Sprintf("%d.%d.%d.%d", eth.IP[0], eth.IP[1], eth.IP[2], eth.IP[3])
	opts.HostInferred = true

	return opts, nil
}

// parseArgs parses flags plus the single positional config path. The flag
// package stops at the first positional argument, so parsing resumes after
// it; flags may appear before and after the path.
func parseArgs(fs *flag.FlagSet, args []string) (string, error) {
	var positionals []string

	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return "", err
		}

		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}

	switch len(positionals) {
	case 0:
		return "", nil
	case 1:
		return positionals[0], nil
	default:
		return "", fmt.Errorf("expected exactly one config path, got %d arguments", len(positionals))
	}
}

func run(opts options, outPath string) error {
	data, err := os.ReadFile(opts.SourcePath)
	if err != nil {
		return err
	}

	config, err := cfg.ParseConfig(data)
	if err != nil {
		return err
	}

	opts, err = resolveHost(config, opts)
	if err != nil {
		return err
	}
	if opts.HostInferred {
		fmt.Fprintf(os.Stderr, "cfg2tf: host inferred from ethconfig section: %s\n", opts.Host)
	}

	content, problems := render(config, opts)
	if content == "" {
		// Validation problems are fatal unless -force was given; render
		// guarantees problems is non-empty whenever content is empty.
		for _, problem := range problems {
			fmt.Fprintf(os.Stderr, "cfg2tf: %v\n", problem)
		}
		os.Exit(1)
	}

	for _, problem := range problems {
		fmt.Fprintf(os.Stderr, "cfg2tf: warning: %v\n", problem)
	}

	if outPath != "" {
		return os.WriteFile(outPath, []byte(content), 0o644)
	}

	_, err = fmt.Print(content)
	return err
}
