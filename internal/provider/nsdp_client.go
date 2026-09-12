package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

// nsdpClient is the provider-facing contract over *nsdp.Client. It exists
// so the cache lifecycle below can be unit-tested without opening UDP
// sockets; *nsdp.Client satisfies it without adaptation.
type nsdpClient interface {
	Close() error
	Login() error
	GetAttr(tag byte) ([]byte, error)
	GetAttrs(tags ...byte) (map[byte][]byte, error)
	GetSystemName() (string, error)
	SetSystemName(name string) error
	SetRaw(tag uint16, value []byte) error

	// Block GETs (dump.go) and typed per-port SETs (methods.go) used by
	// the NSDP resources.
	GetBlock(blockID byte, selector []byte) ([]nsdp.Attr, error)
	SetPortConfig(port int, adminEnabled, flowControl bool) error
	SetQoSPriority(port int, priority nsdp.QoSPriority) error
	SetIngressRate(port int, limit nsdp.BandwidthLimit) error
	SetEgressRate(port int, limit nsdp.BandwidthLimit) error

	// Global-settings and port-based VLAN SETs used by the switch
	// settings / port-based VLAN resources. SetVLANEngineMode is
	// deliberately absent: no provider resource may change the VLAN
	// engine mode.
	SetQoSMode(mode nsdp.QoSMode) error
	SetBlockUnknownMulticast(blocked bool) error
	SetPortMirroring(destPort int, srcPorts []int) error
	SetPortBasedVLAN(vlanID int, ports []int) error
}

// cachedNSDPClient is the NSDP counterpart of cachedDriverSession. Its
// lifecycle is INDEPENDENT of the HTTP driver session: invalidating one
// never touches the other.
type cachedNSDPClient struct {
	fingerprint string
	client      nsdpClient
}

// normalizeAgentMAC trims and lowercases an agent_mac value so the same
// device written in any case form yields one key and one fingerprint.
func normalizeAgentMAC(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// nsdpClient returns the cached NSDP client for the current fingerprint,
// building it on first use (lazily, mirroring driverForConfig). The same
// fingerprint always yields the same instance: the nsdp client is NOT
// safe for concurrent use, so callers must already hold the per-device
// mutex (see withNSDPClient / withDriverForHost).
func (d *providerData) nsdpClient(ctx context.Context) (nsdpClient, error) {
	_ = ctx // reserved for future factory plumbing; nsdp.NewClient takes none

	if d == nil {
		return nil, errors.New("provider is not configured")
	}

	if d.agentMAC == "" {
		return nil, errors.New("NSDP resources require the provider attribute agent_mac")
	}

	fingerprint := d.nsdpConfigFingerprint()
	if d.cachedNSDP != nil && d.cachedNSDP.fingerprint == fingerprint && d.cachedNSDP.client != nil {
		return d.cachedNSDP.client, nil
	}

	d.invalidateCachedNSDPClient()

	factory := d.nsdpFactory
	if factory == nil {
		factory = func(opts nsdp.Options) (nsdpClient, error) {
			return nsdp.NewClient(opts)
		}
	}

	// An empty IfaceName keeps the nsdp package default: the first
	// non-loopback interface with a hardware address.
	client, err := factory(nsdp.Options{
		IfaceName: d.ifaceName,
		AgentMAC:  d.agentMAC,
		Password:  []byte(d.config.Password),
	})
	if err != nil {
		return nil, err
	}

	d.cachedNSDP = &cachedNSDPClient{
		fingerprint: fingerprint,
		client:      client,
	}

	return client, nil
}

// invalidateCachedNSDPClient closes and drops the cached NSDP client. It
// does NOT rebuild or re-login — callers decide when (and whether) a new
// login attempt is worth a lockout strike.
func (d *providerData) invalidateCachedNSDPClient() {
	if d == nil || d.cachedNSDP == nil {
		return
	}
	if d.cachedNSDP.client != nil {
		_ = d.cachedNSDP.client.Close()
	}
	d.cachedNSDP = nil
}

// nsdpConfigFingerprint tracks only the fields that shape the NSDP socket
// and login: interface, normalized agent MAC, and password.
func (d *providerData) nsdpConfigFingerprint() string {
	if d == nil {
		return ""
	}

	return strings.Join([]string{
		strings.TrimSpace(d.ifaceName),
		normalizeAgentMAC(d.agentMAC),
		strings.TrimSpace(d.config.Password),
	}, "\x00")
}

// NSDP reply status/tags that point at a stale or missing auth token
// (see internal/nsdp client.go loginTagFor / errors.go): the switch
// reports them with status 0x0d and/or the failing auth tag.
const (
	nsdpStatusAuthFailure = 0x0d
	nsdpAuthTagV2         = 0x001a
	nsdpAuthTagV1         = 0x0018
	nsdpAuthTagPlaintext  = 0x000a
)

// isNSDPAuthFailure reports whether err is an NSDP error status that a
// fresh client (one new login) could possibly fix: an auth-token
// mismatch. Every other failure — including unexpected login errors,
// which may signal the 3-strikes ~30-minute SET lockout — is left to the
// caller to surface; it never triggers a re-login.
func isNSDPAuthFailure(err error) bool {
	var statusErr *nsdp.ErrStatus
	if !errors.As(err, &statusErr) {
		return false
	}
	if statusErr.Status == nsdpStatusAuthFailure {
		return true
	}
	switch statusErr.FailingTag {
	case nsdpAuthTagV2, nsdpAuthTagV1, nsdpAuthTagPlaintext:
		return true
	}
	return false
}

// withNSDPClient runs fn with the provider's NSDP client, serialized
// against the same device key as HTTP operations (withDriverForHost), so
// an HTTP VLAN apply and an NSDP SET on the same physical switch can
// never interleave.
//
// On an NSDP auth-status failure the cached client is invalidated and fn
// is retried exactly once with a fresh client — at most ONE re-login per
// operation. Re-login attempts burn the switch's 3-strikes ~30-minute
// lockout, so a naive retry loop is never used.
func withNSDPClient(ctx context.Context, data *providerData, fn func(nsdpClient) error) error {
	if data == nil {
		return fmt.Errorf("provider is not configured")
	}

	key := data.deviceLockKey()
	mutex := mutexForDevice(key)
	mutex.Lock()
	defer mutex.Unlock()

	if err := waitForDeviceOperation(ctx, key, data.config.RequestSpacing); err != nil {
		return err
	}

	client, err := data.nsdpClient(ctx)
	if err != nil {
		return err
	}

	err = fn(client)
	if err == nil || !isNSDPAuthFailure(err) {
		return err
	}

	data.invalidateCachedNSDPClient()

	client, err = data.nsdpClient(ctx)
	if err != nil {
		return err
	}

	return fn(client)
}
