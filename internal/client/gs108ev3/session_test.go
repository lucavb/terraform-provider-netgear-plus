package gs108ev3

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIsLoginAttemptLockout(t *testing.T) {
	t.Parallel()

	if !isLoginAttemptLockout("The maximum number of attempts has been reached. Wait a few minutes and then try again.") {
		t.Fatal("isLoginAttemptLockout() should detect switch lockout message")
	}
	if isLoginAttemptLockout("Password is invalid.") {
		t.Fatal("isLoginAttemptLockout() should not flag generic login failures")
	}
}

func TestLoginFailureErrorAddsActionableLockoutGuidance(t *testing.T) {
	t.Parallel()

	err := loginFailureError("10.0.2.2", "The maximum number of attempts has been reached. Wait a few minutes and then try again.")
	if err == nil {
		t.Fatal("loginFailureError() returned nil")
	}

	msg := err.Error()
	for _, needle := range []string{
		"login failed for 10.0.2.2",
		"temporarily locked after too many attempts",
		"verify the password",
		"Firmware message:",
	} {
		if !strings.Contains(msg, needle) {
			t.Fatalf("loginFailureError() = %q, missing %q", msg, needle)
		}
	}
}

func TestDriverShouldInvalidateSession(t *testing.T) {
	t.Parallel()

	driver := &Driver{}
	if !driver.ShouldInvalidateSession(loginFailureError("10.0.2.2", "Password is invalid.")) {
		t.Fatal("ShouldInvalidateSession() should treat login failures as session-invalidating")
	}
	if !driver.ShouldInvalidateSession(loginFailureError("10.0.2.2", "The maximum number of attempts has been reached. Wait a few minutes and then try again.")) {
		t.Fatal("ShouldInvalidateSession() should treat lockouts as session-invalidating")
	}
	if driver.ShouldInvalidateSession(context.DeadlineExceeded) {
		t.Fatal("ShouldInvalidateSession() should ignore non-auth errors")
	}
}

func TestRequestSpacingDelaysSequentialRequests(t *testing.T) {
	t.Cleanup(func() {
		requestPacers = sync.Map{}
	})

	const spacing = 20 * time.Millisecond

	requestTimes := make([]time.Time, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestTimes = append(requestTimes, time.Now())
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	driver, err := New(server.URL, "secret", 1, spacing)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	for i := 0; i < 2; i++ {
		if _, err := driver.getRaw(ctx, endpointSwitchInfoHTM, false); err != nil {
			t.Fatalf("getRaw() call %d error = %v", i+1, err)
		}
	}

	if len(requestTimes) != 2 {
		t.Fatalf("request count = %d, want 2", len(requestTimes))
	}
	minGap := spacing - 2*time.Millisecond
	if gap := requestTimes[1].Sub(requestTimes[0]); gap < minGap {
		t.Fatalf("request gap = %s, want at least %s", gap, minGap)
	}
}
