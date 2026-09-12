package gs108ev3

import (
	"context"
	"errors"
	"fmt"
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
	if driver.ShouldInvalidateSession(fmt.Errorf("%w: aborted", errAuthFailureLimit)) {
		t.Fatal("ShouldInvalidateSession() must not treat the circuit breaker error as session-invalidating")
	}
}

func TestLoginCircuitBreakerAbortsAfterConsecutiveFailures(t *testing.T) {
	t.Parallel()

	server := newTestSwitchServer()
	defer server.Close()
	server.setLoginFailures(1000) // reject every login attempt

	driver, err := New(server.URL(), "password", 15, 0)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()

	for attempt := 1; attempt <= maxConsecutiveAuthFailures; attempt++ {
		loginErr := driver.Login(ctx)
		if !errors.Is(loginErr, errAuthenticationFailed) {
			t.Fatalf("Login() attempt %d error = %v, want errAuthenticationFailed", attempt, loginErr)
		}
		if got := server.loginAttemptCount(); got != attempt {
			t.Fatalf("server saw %d login attempts after attempt %d, want %d", got, attempt, attempt)
		}
	}

	loginErr := driver.Login(ctx)
	if !errors.Is(loginErr, errAuthFailureLimit) {
		t.Fatalf("Login() error = %v, want errAuthFailureLimit", loginErr)
	}
	if errors.Is(loginErr, errAuthenticationFailed) || errors.Is(loginErr, errSwitchLocked) {
		t.Fatalf("circuit breaker error %v must be distinct from the other auth sentinels", loginErr)
	}
	if driver.ShouldInvalidateSession(loginErr) {
		t.Fatal("ShouldInvalidateSession() must not treat the circuit breaker error as session-invalidating")
	}

	msg := loginErr.Error()
	for _, needle := range []string{
		"consecutive login failure limit reached",
		"aborting further login attempts",
		"avoid the switch's global login lockout",
		"check the configured credentials",
		"the failure counter resets in a fresh provider run",
	} {
		if !strings.Contains(msg, needle) {
			t.Fatalf("Login() error = %q, missing %q", msg, needle)
		}
	}

	if got := server.loginAttemptCount(); got != maxConsecutiveAuthFailures {
		t.Fatalf("server saw %d login attempts, want exactly %d", got, maxConsecutiveAuthFailures)
	}

	// Further login attempts must short-circuit without reaching the switch.
	for i := 0; i < 2; i++ {
		repeatErr := driver.Login(ctx)
		if !errors.Is(repeatErr, errAuthFailureLimit) {
			t.Fatalf("short-circuit Login() call %d error = %v, want errAuthFailureLimit", i+1, repeatErr)
		}
	}
	if got := server.loginAttemptCount(); got != maxConsecutiveAuthFailures {
		t.Fatalf("server saw %d login attempts after short-circuits, want %d", got, maxConsecutiveAuthFailures)
	}
}

func TestLoginCircuitBreakerResetsAfterSuccessfulLogin(t *testing.T) {
	t.Parallel()

	server := newTestSwitchServer()
	defer server.Close()
	server.setLoginFailures(2) // fail twice, then accept logins again

	driver, err := New(server.URL(), "password", 15, 0)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()

	for attempt := 1; attempt <= 2; attempt++ {
		loginErr := driver.Login(ctx)
		if !errors.Is(loginErr, errAuthenticationFailed) {
			t.Fatalf("Login() attempt %d error = %v, want errAuthenticationFailed", attempt, loginErr)
		}
	}

	// The successful login resets the consecutive-failure counter.
	if err := driver.Login(ctx); err != nil {
		t.Fatalf("Login() after failures error = %v, want nil", err)
	}
	if got := server.loginAttemptCount(); got != 3 {
		t.Fatalf("server saw %d login attempts, want 3", got)
	}

	// Failure counting starts again from zero after the reset.
	server.setLoginFailures(maxConsecutiveAuthFailures)
	for attempt := 1; attempt <= maxConsecutiveAuthFailures; attempt++ {
		loginErr := driver.Login(ctx)
		if !errors.Is(loginErr, errAuthenticationFailed) {
			t.Fatalf("Login() attempt %d after reset error = %v, want errAuthenticationFailed", attempt, loginErr)
		}
	}

	loginErr := driver.Login(ctx)
	if !errors.Is(loginErr, errAuthFailureLimit) {
		t.Fatalf("Login() error = %v, want errAuthFailureLimit", loginErr)
	}
	if got := server.loginAttemptCount(); got != 3+maxConsecutiveAuthFailures {
		t.Fatalf("server saw %d login attempts, want %d", got, 3+maxConsecutiveAuthFailures)
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
