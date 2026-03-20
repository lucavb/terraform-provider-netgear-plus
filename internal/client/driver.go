package client

import (
	"context"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

// Driver is the model-specific protocol implementation.
type Driver interface {
	Login(ctx context.Context) error
	Logout(ctx context.Context) error
	ReadSwitchFacts(ctx context.Context) (model.SwitchFacts, error)
	ReadVLANState(ctx context.Context) (model.VLANState, error)
	ApplyVLANState(ctx context.Context, desired model.VLANState) error
	ShouldInvalidateSession(err error) bool
}
