package client

import (
	"context"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/cfg"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// Driver is the model-specific protocol implementation.
type Driver interface {
	Login(ctx context.Context) error
	Logout(ctx context.Context) error
	ReadSwitchFacts(ctx context.Context) (model.SwitchFacts, error)
	ReadVLANState(ctx context.Context) (model.VLANState, error)
	ApplyVLANState(ctx context.Context, desired model.VLANState) error
	ReadConfig(ctx context.Context) (*cfg.Config, error)
	RestoreConfigAndWait(ctx context.Context, cfgBytes []byte, timeout time.Duration) error
	ShouldInvalidateSession(err error) bool
}
