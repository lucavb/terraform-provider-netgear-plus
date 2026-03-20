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
