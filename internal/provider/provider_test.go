package provider

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/model"
)

type stubDriver struct {
	readSwitchFacts         func(context.Context) (model.SwitchFacts, error)
	readVLANState           func(context.Context) (model.VLANState, error)
	applyVLANState          func(context.Context, model.VLANState) error
	logout                  func(context.Context) error
	shouldInvalidateSession func(error) bool
}

func (d *stubDriver) Login(context.Context) error {
	return nil
}

func (d *stubDriver) Logout(ctx context.Context) error {
	if d.logout != nil {
		return d.logout(ctx)
	}
	return nil
}

func (d *stubDriver) ReadSwitchFacts(ctx context.Context) (model.SwitchFacts, error) {
	if d.readSwitchFacts != nil {
		return d.readSwitchFacts(ctx)
	}
	return model.SwitchFacts{}, nil
}

func (d *stubDriver) ReadVLANState(ctx context.Context) (model.VLANState, error) {
	if d.readVLANState != nil {
		return d.readVLANState(ctx)
	}
	return model.VLANState{}, nil
}

func (d *stubDriver) ApplyVLANState(ctx context.Context, state model.VLANState) error {
	if d.applyVLANState != nil {
		return d.applyVLANState(ctx, state)
	}
	return nil
}

func (d *stubDriver) ShouldInvalidateSession(err error) bool {
	if d.shouldInvalidateSession != nil {
		return d.shouldInvalidateSession(err)
	}
	return false
}

func TestProviderSchemaIncludesRequestSpacing(t *testing.T) {
	t.Parallel()

	var resp frameworkprovider.SchemaResponse
	(&netgearPlusProvider{}).Schema(context.Background(), frameworkprovider.SchemaRequest{}, &resp)

	if _, ok := resp.Schema.Attributes["request_spacing"]; !ok {
		t.Fatal("provider schema should expose request_spacing")
	}
}

func TestProviderDataResourceIDCanonicalizesHost(t *testing.T) {
	t.Parallel()

	data := &providerData{
		config: client.Config{
			Host:  "http://192.0.2.10:80",
			Model: client.ModelGS108Ev3,
		},
	}

	if got, want := data.resourceID(), "gs108ev3@192.0.2.10"; got != want {
		t.Fatalf("resourceID() = %q, want %q", got, want)
	}
}

func TestReadVLANStateDataSourceStateUsesProvidedResourceID(t *testing.T) {
	t.Parallel()

	driver := &stubDriver{
		readSwitchFacts: func(context.Context) (model.SwitchFacts, error) {
			t.Fatal("ReadSwitchFacts() should not be called by VLAN data source state helper")
			return model.SwitchFacts{}, nil
		},
		readVLANState: func(context.Context) (model.VLANState, error) {
			return model.VLANState{
				PortCount: 8,
				VLANs: map[int]model.Vlan{
					1: {
						ID: 1,
						Ports: map[int]model.PortMembership{
							1: model.PortMembershipUntagged,
							2: model.PortMembershipUntagged,
							3: model.PortMembershipIgnored,
							4: model.PortMembershipIgnored,
							5: model.PortMembershipIgnored,
							6: model.PortMembershipIgnored,
							7: model.PortMembershipIgnored,
							8: model.PortMembershipIgnored,
						},
					},
				},
				PVIDs: map[int]int{
					1: 1,
					2: 1,
					3: 1,
					4: 1,
					5: 1,
					6: 1,
					7: 1,
					8: 1,
				},
			}, nil
		},
	}

	state, err := readVLANStateDataSourceState(context.Background(), driver, "gs108ev3@192.0.2.10")
	if err != nil {
		t.Fatalf("readVLANStateDataSourceState() error = %v", err)
	}

	if got, want := state.ID.ValueString(), "gs108ev3@192.0.2.10"; got != want {
		t.Fatalf("state ID = %q, want %q", got, want)
	}
	if len(state.VLANs) != 1 {
		t.Fatalf("VLAN count = %d, want 1", len(state.VLANs))
	}

	pvids := make(map[string]int64)
	if diags := state.PVIDs.ElementsAs(context.Background(), &pvids, false); diags.HasError() {
		t.Fatalf("PVID map decode failed: %v", diags.Errors())
	}
	if got, want := pvids["1"], int64(1); got != want {
		t.Fatalf("PVID for port 1 = %d, want %d", got, want)
	}
}

func TestWithDriverForHostReusesCachedDriverAndSerializesCalls(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondEntered := make(chan struct{}, 1)
	errCh := make(chan error, 2)

	var mu sync.Mutex
	factoryCalls := 0
	logoutCalls := 0
	data := &providerData{
		config: client.Config{Host: "http://192.0.2.10:80", RequestSpacing: time.Millisecond},
		driverFactory: func(client.Config) (client.Driver, error) {
			mu.Lock()
			factoryCalls++
			mu.Unlock()

			return &stubDriver{
				logout: func(context.Context) error {
					mu.Lock()
					logoutCalls++
					mu.Unlock()
					return nil
				},
			}, nil
		},
	}

	go func() {
		errCh <- withDriverForHost(ctx, data, func(client.Driver) error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
	}()

	<-firstEntered

	go func() {
		errCh <- withDriverForHost(ctx, data, func(client.Driver) error {
			secondEntered <- struct{}{}
			return nil
		})
	}()

	select {
	case <-secondEntered:
		t.Fatal("second operation should block until the first call releases the host lock")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseFirst)

	select {
	case <-secondEntered:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for second callback: %v", ctx.Err())
	}

	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("withDriverForHost() error = %v", err)
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for helper result: %v", ctx.Err())
		}
	}

	mu.Lock()
	if factoryCalls != 1 {
		t.Fatalf("driverFactory call count = %d, want 1", factoryCalls)
	}
	if logoutCalls != 0 {
		t.Fatalf("logout call count = %d before invalidation, want 0", logoutCalls)
	}
	mu.Unlock()

	data.invalidateCachedDriver(ctx)

	mu.Lock()
	defer mu.Unlock()
	if logoutCalls != 1 {
		t.Fatalf("logout call count = %d after invalidation, want 1", logoutCalls)
	}
}

func TestWithDriverForHostInvalidatesCachedDriverOnConfigChange(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var mu sync.Mutex
	factoryCalls := 0
	logoutCalls := 0
	data := &providerData{
		config: client.Config{
			Host:           "http://192.0.2.10",
			Password:       "first-password",
			Model:          client.ModelGS108Ev3,
			RequestTimeout: 15,
			InsecureHTTP:   true,
			RequestSpacing: time.Millisecond,
		},
		driverFactory: func(client.Config) (client.Driver, error) {
			mu.Lock()
			factoryCalls++
			mu.Unlock()

			return &stubDriver{
				logout: func(context.Context) error {
					mu.Lock()
					logoutCalls++
					mu.Unlock()
					return nil
				},
			}, nil
		},
	}

	if err := withDriverForHost(ctx, data, func(client.Driver) error { return nil }); err != nil {
		t.Fatalf("first withDriverForHost() error = %v", err)
	}

	data.config.Password = "second-password"

	if err := withDriverForHost(ctx, data, func(client.Driver) error { return nil }); err != nil {
		t.Fatalf("second withDriverForHost() error = %v", err)
	}

	mu.Lock()
	if factoryCalls != 2 {
		t.Fatalf("driverFactory call count = %d, want 2", factoryCalls)
	}
	if logoutCalls != 1 {
		t.Fatalf("logout call count = %d after config change, want 1", logoutCalls)
	}
	mu.Unlock()

	data.invalidateCachedDriver(ctx)

	mu.Lock()
	defer mu.Unlock()
	if logoutCalls != 2 {
		t.Fatalf("logout call count = %d after final invalidation, want 2", logoutCalls)
	}
}

func TestWithDriverForHostInvalidatesCachedDriverOnRequestSpacingChange(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var mu sync.Mutex
	factoryCalls := 0
	logoutCalls := 0
	data := &providerData{
		config: client.Config{
			Host:           "http://192.0.2.10",
			Model:          client.ModelGS108Ev3,
			RequestSpacing: time.Millisecond,
		},
		driverFactory: func(client.Config) (client.Driver, error) {
			mu.Lock()
			factoryCalls++
			mu.Unlock()

			return &stubDriver{
				logout: func(context.Context) error {
					mu.Lock()
					logoutCalls++
					mu.Unlock()
					return nil
				},
			}, nil
		},
	}

	if err := withDriverForHost(ctx, data, func(client.Driver) error { return nil }); err != nil {
		t.Fatalf("first withDriverForHost() error = %v", err)
	}

	data.config.RequestSpacing = 2 * time.Millisecond

	if err := withDriverForHost(ctx, data, func(client.Driver) error { return nil }); err != nil {
		t.Fatalf("second withDriverForHost() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if factoryCalls != 2 {
		t.Fatalf("driverFactory call count = %d, want 2", factoryCalls)
	}
	if logoutCalls != 1 {
		t.Fatalf("logout call count = %d after request spacing change, want 1", logoutCalls)
	}
}

func TestWithDriverForHostInvalidatesCachedDriverOnCallbackError(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var mu sync.Mutex
	factoryCalls := 0
	logoutCalls := 0
	data := &providerData{
		config: client.Config{Host: "http://192.0.2.10", RequestSpacing: time.Millisecond},
		driverFactory: func(client.Config) (client.Driver, error) {
			mu.Lock()
			factoryCalls++
			mu.Unlock()

			return &stubDriver{
				shouldInvalidateSession: func(error) bool { return true },
				logout: func(context.Context) error {
					mu.Lock()
					logoutCalls++
					mu.Unlock()
					return nil
				},
			}, nil
		},
	}

	wantErr := errors.New("boom")
	if err := withDriverForHost(ctx, data, func(client.Driver) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("withDriverForHost() error = %v, want %v", err, wantErr)
	}

	mu.Lock()
	if factoryCalls != 1 {
		t.Fatalf("driverFactory call count = %d, want 1 after error", factoryCalls)
	}
	if logoutCalls != 1 {
		t.Fatalf("logout call count = %d, want 1 after error invalidation", logoutCalls)
	}
	mu.Unlock()

	if err := withDriverForHost(ctx, data, func(client.Driver) error { return nil }); err != nil {
		t.Fatalf("withDriverForHost() after invalidation error = %v", err)
	}

	mu.Lock()
	if factoryCalls != 2 {
		t.Fatalf("driverFactory call count = %d, want 2 after retry", factoryCalls)
	}
	mu.Unlock()
}

func TestWithDriverForHostPreservesCachedDriverOnNonSessionError(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var mu sync.Mutex
	factoryCalls := 0
	logoutCalls := 0
	data := &providerData{
		config: client.Config{Host: "http://192.0.2.11", RequestSpacing: time.Millisecond},
		driverFactory: func(client.Config) (client.Driver, error) {
			mu.Lock()
			factoryCalls++
			mu.Unlock()

			return &stubDriver{
				shouldInvalidateSession: func(error) bool { return false },
				logout: func(context.Context) error {
					mu.Lock()
					logoutCalls++
					mu.Unlock()
					return nil
				},
			}, nil
		},
	}

	wantErr := errors.New("boom")
	if err := withDriverForHost(ctx, data, func(client.Driver) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("withDriverForHost() error = %v, want %v", err, wantErr)
	}

	if err := withDriverForHost(ctx, data, func(client.Driver) error { return nil }); err != nil {
		t.Fatalf("withDriverForHost() after non-session error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if factoryCalls != 1 {
		t.Fatalf("driverFactory call count = %d, want 1 when session is preserved", factoryCalls)
	}
	if logoutCalls != 0 {
		t.Fatalf("logout call count = %d, want 0 when session is preserved", logoutCalls)
	}
}

func TestWithDriverForHostWaitsBetweenOperations(t *testing.T) {
	t.Cleanup(func() {
		hostMutexes = sync.Map{}
		hostOperationPacers = sync.Map{}
	})

	const spacing = 20 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	starts := make([]time.Time, 0, 2)
	data := &providerData{
		config: client.Config{Host: "http://192.0.2.12", RequestSpacing: spacing},
		driverFactory: func(client.Config) (client.Driver, error) {
			return &stubDriver{}, nil
		},
	}

	for i := 0; i < 2; i++ {
		if err := withDriverForHost(ctx, data, func(client.Driver) error {
			starts = append(starts, time.Now())
			return nil
		}); err != nil {
			t.Fatalf("withDriverForHost() error = %v", err)
		}
	}

	if len(starts) != 2 {
		t.Fatalf("callback count = %d, want 2", len(starts))
	}
	if gap := starts[1].Sub(starts[0]); gap < spacing {
		t.Fatalf("operation gap = %s, want at least %s", gap, spacing)
	}
}
