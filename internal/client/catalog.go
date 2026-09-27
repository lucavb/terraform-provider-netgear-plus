package client

import (
	"fmt"
	"strings"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client/gs108ev3"
)

const (
	// ModelGS108Ev3 is the only explicitly supported v0.1.0 model.
	ModelGS108Ev3 = "gs108ev3"

	// ModelGS108Tv2 is the GS108Tv2/GS110TPv2-class "ProSAFE Smart
	// Managed" family running FASTPATH firmware (e.g. v5.4.2.36,
	// live-verified 2026-09-15). The legacy NSDP v1 dialect (UDP
	// 63323/63324) carries identity/firmware facts, system name and IP
	// configuration; its engine has no VLAN/port datatypes (see
	// nsdpV1Guard). VLAN state for this model runs over its FASTPATH
	// text-config channel, OUTSIDE this package:
	// internal/client/gs108tv2 carries the emweb driver (startup-config
	// save/mutate/restore + structural verify), and
	// internal/provider/textcfg_switch_transport.go composes it into
	// the provider transport. client.NewDriver intentionally stays
	// ev3-only — withSwitchTransport wires the gs108tv2 branches — and
	// the firmware's emweb/FASTPATH UI is unrelated to the gs108ev3
	// Plus pages, so no gs108ev3-style HTTP driver can ever serve it.
	ModelGS108Tv2 = "gs108tv2"
)

// Config contains provider-level client configuration.
type Config struct {
	Host           string
	Password       string
	Model          string
	RequestTimeout int64
	InsecureHTTP   bool
	RequestSpacing time.Duration
}

// NewDriver returns the model-specific driver implementation.
func NewDriver(cfg Config) (Driver, error) {
	modelName := strings.ToLower(strings.TrimSpace(cfg.Model))
	if modelName == "" {
		modelName = ModelGS108Ev3
	}

	switch modelName {
	case ModelGS108Ev3:
		return gs108ev3.New(cfg.Host, cfg.Password, cfg.RequestTimeout, cfg.RequestSpacing)
	default:
		return nil, fmt.Errorf("unsupported model %q", cfg.Model)
	}
}
