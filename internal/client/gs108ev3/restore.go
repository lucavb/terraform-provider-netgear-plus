package gs108ev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime/multipart"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/cfg"
)

const (
	endpointRestoreConfCGI = "/restore_conf.cgi"
	restoreHashField       = "hash"
	restoreFileField       = "fileField"
	restoreFileName        = "GS108Ev3.cfg"
	restorePollInterval    = 2 * time.Second
)

// RestoreConfig uploads a raw FMv2 configuration backup to the switch.
//
// The upload mirrors the switch's own restore dialog: a cookie-authenticated
// multipart POST with a hash field followed by the raw .cfg bytes. The
// switch accepts the upload and reboots, so the response body is only a
// splash page — use RestoreConfigAndWait to verify the restored
// configuration once the switch is back.
func (d *Driver) RestoreConfig(ctx context.Context, cfgBytes []byte) error {
	if _, err := d.postRestoreAuthenticated(ctx, endpointRestoreConfCGI, cfgBytes); err != nil {
		return fmt.Errorf("restore config: %w", err)
	}
	return nil
}

// RestoreConfigAndWait uploads a raw FMv2 configuration backup and waits for
// the switch to come back from the restore reboot. It polls with fresh
// logins (connection failures during the reboot window are expected and do
// not trip the auth-failure circuit breaker), then verifies that the
// fingerprint of the freshly served configuration matches the uploaded
// bytes.
func (d *Driver) RestoreConfigAndWait(ctx context.Context, cfgBytes []byte, timeout time.Duration) error {
	parsed, err := cfg.ParseConfig(cfgBytes)
	if err != nil {
		return fmt.Errorf("restore config: cannot fingerprint upload: %w", err)
	}
	expected := parsed.Fingerprint()

	if err := d.RestoreConfig(ctx, cfgBytes); err != nil {
		return err
	}

	return d.waitForRestoredConfig(ctx, expected, timeout)
}

func (d *Driver) postRestoreAuthenticated(ctx context.Context, endpoint string, cfgBytes []byte) (string, error) {
	if _, err := d.ensureHash(ctx); err != nil {
		return "", err
	}
	return d.postRestoreRaw(ctx, endpoint, d.hash, cfgBytes, true)
}

func (d *Driver) postRestoreRaw(ctx context.Context, endpoint, hash string, cfgBytes []byte, retryAuth bool) (string, error) {
	body, contentType, err := buildRestoreBody(hash, cfgBytes)
	if err != nil {
		return "", err
	}

	response, err := d.postBodyRaw(ctx, endpoint, contentType, body)
	if err != nil {
		return "", err
	}

	if retryAuth && isRedirectToLogin(response) {
		if err := d.Login(ctx); err != nil {
			return "", err
		}
		// The fresh session has a fresh hash; rebuild the body.
		return d.postRestoreRaw(ctx, endpoint, d.hash, cfgBytes, false)
	}

	return response, nil
}

// buildRestoreBody builds the multipart/form-data body the switch's restore
// dialog posts: a hash part followed by the raw .cfg bytes.
func buildRestoreBody(hash string, cfgBytes []byte) (body []byte, contentType string, err error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	if err := writer.WriteField(restoreHashField, hash); err != nil {
		return nil, "", fmt.Errorf("restore config: write hash field: %w", err)
	}

	file, err := writer.CreateFormFile(restoreFileField, restoreFileName)
	if err != nil {
		return nil, "", fmt.Errorf("restore config: create file field: %w", err)
	}
	if _, err := file.Write(cfgBytes); err != nil {
		return nil, "", fmt.Errorf("restore config: write config bytes: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("restore config: finalize body: %w", err)
	}

	return buf.Bytes(), writer.FormDataContentType(), nil
}

func (d *Driver) waitForRestoredConfig(ctx context.Context, expected string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for {
		loginErr := d.Login(ctx)
		if loginErr == nil {
			return d.verifyRestoredConfig(ctx, expected)
		}

		switch {
		case errors.Is(loginErr, errAuthenticationFailed),
			errors.Is(loginErr, errSwitchLocked),
			errors.Is(loginErr, errAuthFailureLimit):
			// Auth rejections are not reboot symptoms; surface them
			// instead of burning the poll budget.
			return fmt.Errorf("restore config: login rejected while waiting for the switch to come back: %w", loginErr)
		case ctx.Err() != nil:
			return ctx.Err()
		}

		// The switch is still rebooting: connection-level failures are
		// expected here and do not count against the auth-failure breaker.
		if !time.Now().Before(deadline) {
			return fmt.Errorf("restore config: switch did not come back within %s: %w", timeout, loginErr)
		}

		interval := restorePollInterval
		if remaining := time.Until(deadline); remaining < interval {
			interval = remaining
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (d *Driver) verifyRestoredConfig(ctx context.Context, expected string) error {
	config, err := d.ReadConfig(ctx)
	if err != nil {
		return fmt.Errorf("restore config: verify: %w", err)
	}

	if got := config.Fingerprint(); got != expected {
		return fmt.Errorf("restore config: verification failed: expected config checksum %s, got %s", expected, got)
	}

	return nil
}
