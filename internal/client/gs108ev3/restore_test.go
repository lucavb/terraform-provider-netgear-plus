package gs108ev3

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/cfg"
)

// testAlternateConfigBackup differs from testConfigBackup in checksum and
// content, so a restore can be proven to have taken effect.
func testAlternateConfigBackup() []byte {
	return buildTestConfigBackup("restored-switch2", []int{1, 1, 1, 1, 20, 20, 20, 20})
}

func fingerprintOf(t *testing.T, data []byte) string {
	t.Helper()

	parsed, err := cfg.ParseConfig(data)
	if err != nil {
		t.Fatalf("cfg.ParseConfig() error = %v", err)
	}
	return parsed.Fingerprint()
}

func TestDriverRestoreConfigAndWaitAcrossReboot(t *testing.T) {
	t.Parallel()

	server := newTestSwitchServer()
	defer server.Close()
	server.rebootAfterRestore(3)

	driver, err := New(server.URL(), "password", 15, 0)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	if err := driver.Login(ctx); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	loginsBefore := server.loginAttemptCount()

	upload := testAlternateConfigBackup()
	expected := fingerprintOf(t, upload)
	if expected == fingerprintOf(t, testConfigBackup()) {
		t.Fatal("alternate fixture must have a different checksum from the default fixture")
	}

	if err := driver.RestoreConfigAndWait(ctx, upload, 30*time.Second); err != nil {
		t.Fatalf("RestoreConfigAndWait() error = %v", err)
	}

	// The restore request hit the switch exactly once, with the exact
	// multipart structure the restore dialog uses.
	record := server.lastRestoreRecord()
	if got := server.restoreRequestCount(); got != 1 {
		t.Fatalf("restore request count = %d, want 1", got)
	}
	if !record.valid {
		t.Fatalf("restore request was rejected as invalid: %+v", record)
	}
	if !record.cookieValid {
		t.Fatal("restore request was not sent with a valid GS108SID cookie")
	}
	if record.hash != "deadbeefcafebabe" {
		t.Fatalf("restore hash field = %q, want the session hash", record.hash)
	}
	if !record.fileFieldValid {
		t.Fatalf("restore file field invalid: %+v", record)
	}
	if !bytes.Equal(record.uploaded, upload) {
		t.Fatal("uploaded bytes differ from the requested backup")
	}
	if got := server.refusedRestoreCount(); got != 0 {
		t.Fatalf("refused restores = %d, want 0 with a live session", got)
	}

	// The reboot window was simulated and a fresh login happened after it.
	if got := server.refusedConnectionCount(); got < 1 {
		t.Fatal("expected the simulated reboot to refuse connections")
	}
	if got := server.loginAttemptCount(); got <= loginsBefore {
		t.Fatal("expected a fresh login after the reboot")
	}

	// The switch now serves the restored bytes, verified by fingerprint.
	config, err := driver.ReadConfig(ctx)
	if err != nil {
		t.Fatalf("ReadConfig() error = %v", err)
	}
	if got := config.Fingerprint(); got != expected {
		t.Fatalf("post-restore fingerprint = %s, want %s", got, expected)
	}

	pvids, err := config.PVIDs()
	if err != nil {
		t.Fatalf("PVIDs() error = %v", err)
	}
	if !slices.Equal(pvids, []int{1, 1, 1, 1, 20, 20, 20, 20}) {
		t.Fatalf("restored PVIDs = %v, want the uploaded backup's values", pvids)
	}
}

func TestDriverRestoreConfigAndWaitFingerprintMismatch(t *testing.T) {
	t.Parallel()

	server := newTestSwitchServer()
	defer server.Close()
	server.rebootAfterRestore(0)
	server.setRestoredConfigOverride(testConfigBackup())

	driver, err := New(server.URL(), "password", 15, 0)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	if err := driver.Login(ctx); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	upload := testAlternateConfigBackup()
	expected := fingerprintOf(t, upload)
	got := fingerprintOf(t, testConfigBackup())

	err = driver.RestoreConfigAndWait(ctx, upload, 30*time.Second)
	if err == nil {
		t.Fatal("RestoreConfigAndWait() should fail when the fingerprint does not match")
	}

	msg := err.Error()
	if !strings.Contains(msg, expected) || !strings.Contains(msg, got) {
		t.Fatalf("RestoreConfigAndWait() error = %q, want it to name expected checksum %s and got %s", msg, expected, got)
	}

	if server.restoreRequestCount() != 1 || !server.lastRestoreRecord().valid {
		t.Fatalf("restore should have executed exactly once: count=%d record=%+v",
			server.restoreRequestCount(), server.lastRestoreRecord())
	}
}

func TestDriverRestoreConfigRefusedWithoutAuthCookie(t *testing.T) {
	t.Parallel()

	server := newTestSwitchServer()
	defer server.Close()
	server.setLoginFailures(1000) // no session can ever be established

	driver, err := New(server.URL(), "password", 15, 0)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = driver.RestoreConfig(context.Background(), testConfigBackup())
	if !errors.Is(err, errAuthenticationFailed) {
		t.Fatalf("RestoreConfig() error = %v, want errAuthenticationFailed", err)
	}
	if got := server.restoreRequestCount(); got != 0 {
		t.Fatalf("restore request count = %d, want 0 without an auth cookie", got)
	}
}

func TestDriverRestoreConfigRetriesAfterSessionExpiry(t *testing.T) {
	t.Parallel()

	server := newTestSwitchServer()
	defer server.Close()

	driver, err := New(server.URL(), "password", 15, 0)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	if err := driver.Login(ctx); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// The old GS108SID is dead, like after a session expiry or reboot.
	server.rotateSession()

	if err := driver.RestoreConfig(ctx, testConfigBackup()); err != nil {
		t.Fatalf("RestoreConfig() error = %v", err)
	}

	if got := server.refusedRestoreCount(); got != 1 {
		t.Fatalf("refused restores = %d, want 1", got)
	}
	if got := server.restoreRequestCount(); got != 1 {
		t.Fatalf("restore request count = %d, want 1 after the re-login retry", got)
	}
	record := server.lastRestoreRecord()
	if !record.valid || !record.cookieValid {
		t.Fatalf("restore retry invalid: %+v", record)
	}
}
