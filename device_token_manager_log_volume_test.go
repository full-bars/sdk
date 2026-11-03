package sdk

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

	"github.com/urnetwork/connect"
)

type testLogCapture struct {
	mu    sync.Mutex
	lines []string
	v1    bool
}

func (self *testLogCapture) add(line string) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.lines = append(self.lines, line)
}

func (self *testLogCapture) Info(args ...any) { self.add(fmt.Sprint(args...)) }
func (self *testLogCapture) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testLogCapture) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testLogCapture) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testLogCapture) V(level int32) connect.Verbose {
	return testLogCaptureVerbose{capture: self, enabled: self.v1 && level <= 1}
}

type testLogCaptureVerbose struct {
	capture *testLogCapture
	enabled bool
}

func (self testLogCaptureVerbose) Enabled() bool { return self.enabled }
func (self testLogCaptureVerbose) Info(args ...any) {
	if self.enabled {
		self.capture.Info(args...)
	}
}
func (self testLogCaptureVerbose) Infof(format string, args ...any) {
	if self.enabled {
		self.capture.Infof(format, args...)
	}
}

func (self *testLogCapture) allLines() []string {
	self.mu.Lock()
	defer self.mu.Unlock()
	copied := make([]string, len(self.lines))
	copy(copied, self.lines)
	return copied
}

func (self *testLogCapture) matchingLines(substr string) []string {
	self.mu.Lock()
	defer self.mu.Unlock()
	var matched []string
	for _, line := range self.lines {
		if strings.Contains(line, substr) {
			matched = append(matched, line)
		}
	}
	return matched
}

// TestTokenManagerOneFailureProducesExactlyOneLine verifies that a refresh failure
// emits exactly ONE failure line at info, readable with human units, and guards
// against the duplicate line that previously appeared at line 651 and line 679.
func TestTokenManagerOneFailureProducesExactlyOneLine(t *testing.T) {
	resetTokenManagerSummaryTrackerForTesting()
	t.Cleanup(resetTokenManagerSummaryTrackerForTesting)

	log := &testLogCapture{v1: false}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, api, closeFunc := testingNewTokenManager(t, ctx, "https://refresh.example", func(string) {}, func() error { return nil })
	defer closeFunc()
	api.setLog(log)
	api.SetByJwt(testingRefreshableJwt(t))

	expectedReason := "service overloaded"
	api.setHttpGetRaw(func(ctx context.Context, requestUrl string, byJwt string) ([]byte, error) {
		return nil, errors.New(expectedReason)
	})

	manager := testingRunnableTokenManager(ctx, api)
	manager.retryTimeout = func() time.Duration {
		return 10 * time.Minute
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.run()
	}()

	// Wait for the failure line to be emitted
	var failureLines []string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		failureLines = log.matchingLines("sign-in renewal failed")
		if len(failureLines) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	manager.cancel()
	<-done

	if len(failureLines) != 1 {
		t.Fatalf("expected exactly 1 failure line, got %d: %v", len(failureLines), failureLines)
	}

	line := failureLines[0]
	if !strings.Contains(line, "sign-in renewal failed for client") {
		t.Errorf("line does not name client: %q", line)
	}
	if !strings.Contains(line, "service overloaded") && !strings.Contains(line, "503") {
		t.Errorf("line does not contain reason: %q", line)
	}
	if !strings.Contains(line, "retrying in 10m") {
		t.Errorf("line does not contain human retry: %q", line)
	}

	// Guard against duplicate: neither the old line 651 error nor old line 679 format must appear
	oldErrors := log.matchingLines("failed to refresh JWT:")
	if len(oldErrors) != 0 {
		t.Errorf("duplicate old error line :651 appeared: %v", oldErrors)
	}
	oldJitterLines := log.matchingLines("jwt refresh failed. Will retry in")
	if len(oldJitterLines) != 0 {
		t.Errorf("duplicate old jitter line :679 appeared: %v", oldJitterLines)
	}
}

// TestTokenManagerDemotedLinesSilentAtInfoAndPresentAtDebug verifies that
// "refreshing the jwt now", "successfully refreshed JWT", and "waiting %.2fs to refresh the jwt"
// are completely silent at info level and present when debug logging (V(1)) is enabled.
func TestTokenManagerDemotedLinesSilentAtInfoAndPresentAtDebug(t *testing.T) {
	resetTokenManagerSummaryTrackerForTesting()
	t.Cleanup(resetTokenManagerSummaryTrackerForTesting)

	for _, tc := range []struct {
		name       string
		debugLevel bool
		wantLines  bool
	}{
		{"info_level_silent", false, false},
		{"debug_level_present", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &testLogCapture{v1: tc.debugLevel}
			refreshedJwt := testingRefreshableJwtWithMarker(t, "demoted-test-"+tc.name)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"by_jwt":%q}`, refreshedJwt)
			}))
			defer server.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			_, api, closeFunc := testingNewTokenManager(t, ctx, server.URL, func(string) {}, func() error { return nil })
			defer closeFunc()
			api.setLog(log)
			api.SetByJwt(testingRefreshableJwt(t))

			manager := testingRunnableTokenManager(ctx, api)
			done := make(chan struct{})
			go func() {
				defer close(done)
				manager.run()
			}()

			// Give manager time to run the immediate refresh and schedule the next
			time.Sleep(300 * time.Millisecond)
			manager.cancel()
			<-done

			refreshingLines := log.matchingLines("refreshing the jwt now")
			successLines := log.matchingLines("successfully refreshed JWT")
			waitingLines := log.matchingLines("to refresh the jwt")

			if tc.wantLines {
				if len(refreshingLines) == 0 {
					t.Errorf("expected 'refreshing the jwt now' at debug level, got none. All lines: %v", log.allLines())
				}
				if len(successLines) == 0 {
					t.Errorf("expected 'successfully refreshed JWT' at debug level, got none. All lines: %v", log.allLines())
				}
				if len(waitingLines) == 0 {
					t.Errorf("expected 'waiting ... to refresh the jwt' at debug level, got none. All lines: %v", log.allLines())
				}
			} else {
				if len(refreshingLines) > 0 {
					t.Errorf("expected 'refreshing the jwt now' to be silent at info level, got: %v", refreshingLines)
				}
				if len(successLines) > 0 {
					t.Errorf("expected 'successfully refreshed JWT' to be silent at info level, got: %v", successLines)
				}
				if len(waitingLines) > 0 {
					t.Errorf("expected 'waiting ... to refresh the jwt' to be silent at info level, got: %v", waitingLines)
				}
			}
		})
	}
}

// TestTokenManagerSummarySilentWhenAllHealthy verifies that when all clients
// are healthy (0 failing renewal), the summary line is completely silent.
func TestTokenManagerSummarySilentWhenAllHealthy(t *testing.T) {
	resetTokenManagerSummaryTrackerForTesting()
	t.Cleanup(resetTokenManagerSummaryTrackerForTesting)

	log := &testLogCapture{v1: false}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"by_jwt":%q}`, testingRefreshableJwtWithMarker(t, "healthy"))
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, api, closeFunc := testingNewTokenManager(t, ctx, server.URL, func(string) {}, func() error { return nil })
	defer closeFunc()
	api.setLog(log)
	api.SetByJwt(testingRefreshableJwt(t))

	manager := testingRunnableTokenManager(ctx, api)
	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.run()
	}()

	time.Sleep(300 * time.Millisecond)

	// Trigger summary emission
	emitted := emitTokenManagerSummary()
	if emitted {
		t.Fatalf("emitTokenManagerSummary returned true when all clients are healthy")
	}

	summaryLines := log.matchingLines("clients failing renewal")
	if len(summaryLines) > 0 {
		t.Fatalf("summary line appeared when all clients are healthy: %v", summaryLines)
	}

	manager.cancel()
	<-done
}

// TestTokenManagerSummaryAppearsWhenFailingAndCountIsRight verifies that
// the summary appears when clients are failing with the correct count and soonest retry,
// and becomes silent once failing clients recover.
func TestTokenManagerSummaryAppearsWhenFailingAndCountIsRight(t *testing.T) {
	resetTokenManagerSummaryTrackerForTesting()
	t.Cleanup(resetTokenManagerSummaryTrackerForTesting)

	log := &testLogCapture{v1: false}

	// Construct 3 distinct mock managers with refreshable tokens
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	managers := make([]*apiTokenManager, 3)
	for i := range managers {
		clientStrategy := newTestClientStrategy(ctx)
		defer clientStrategy.Close()
		api := newApi(ctx, clientStrategy, "https://example.invalid")
		defer api.Close()
		api.setLog(log)
		jwt := testingRefreshableJwtWithMarker(t, fmt.Sprintf("summary-client-%d", i))
		api.SetByJwt(jwt)

		m := testingRunnableTokenManager(ctx, api)
		defer m.cancel()
		globalTokenRenewalTracker.registerClient(m)
		managers[i] = m
	}

	now := time.Now()

	// 1. Initially, no clients are failing -> silent
	if emitTokenManagerSummaryAt(now) {
		t.Fatal("summary emitted when 0 clients are failing")
	}
	if len(log.matchingLines("clients failing renewal")) > 0 {
		t.Fatal("summary line logged when 0 clients are failing")
	}

	// 2. Mark 1 client failing, next retry in 5m
	globalTokenRenewalTracker.recordFailure(managers[0], now.Add(5*time.Minute))

	if !emitTokenManagerSummaryAt(now) {
		t.Fatal("summary not emitted when 1 client is failing")
	}
	lines := log.matchingLines("clients failing renewal")
	if len(lines) != 1 {
		t.Fatalf("expected 1 summary line, got: %v", lines)
	}
	want1 := "sign-in: 1 of 3 clients failing renewal, next retry in 5m"
	if !strings.Contains(lines[0], want1) {
		t.Fatalf("summary line = %q, want %q", lines[0], want1)
	}

	// 3. Mark another client failing, with a SOONER retry in 2m
	globalTokenRenewalTracker.recordFailure(managers[1], now.Add(2*time.Minute))

	if !emitTokenManagerSummaryAt(now) {
		t.Fatal("summary not emitted when 2 clients are failing")
	}
	lines = log.matchingLines("clients failing renewal")
	if len(lines) != 2 {
		t.Fatalf("expected 2 summary lines total, got: %v", lines)
	}
	want2 := "sign-in: 2 of 3 clients failing renewal, next retry in 2m"
	if !strings.Contains(lines[1], want2) {
		t.Fatalf("summary line = %q, want %q", lines[1], want2)
	}

	// 4. Clients recover (succeed renewal) -> summary becomes silent again
	globalTokenRenewalTracker.clearFailure(managers[0])
	globalTokenRenewalTracker.clearFailure(managers[1])

	if emitTokenManagerSummaryAt(now) {
		t.Fatal("summary emitted after all failing clients recovered")
	}
	lines = log.matchingLines("clients failing renewal")
	if len(lines) != 2 {
		t.Fatalf("new summary line appeared after recovery: %v", lines)
	}
}

// TestTokenManagerPeriodicSummaryTicker verifies that the background ticker
// emits the summary periodically while clients are failing and shuts off when healthy.
func TestTokenManagerPeriodicSummaryTicker(t *testing.T) {
	resetTokenManagerSummaryTrackerForTesting()
	t.Cleanup(resetTokenManagerSummaryTrackerForTesting)

	log := &testLogCapture{v1: false}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientStrategy := newTestClientStrategy(ctx)
	defer clientStrategy.Close()
	api := newApi(ctx, clientStrategy, "https://example.invalid")
	defer api.Close()
	api.setLog(log)
	api.SetByJwt(testingRefreshableJwt(t))

	manager := testingRunnableTokenManager(ctx, api)
	defer manager.cancel()
	globalTokenRenewalTracker.registerClient(manager)

	// Set a fast ticker for test
	origInterval := tokenRenewalSummaryInterval
	tokenRenewalSummaryInterval = 25 * time.Millisecond
	defer func() { tokenRenewalSummaryInterval = origInterval }()

	// Record a failure -> starts ticker
	globalTokenRenewalTracker.recordFailure(manager, time.Now().Add(10*time.Minute))

	// Wait for ticker to fire at least once
	var lines []string
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		lines = log.matchingLines("clients failing renewal")
		if len(lines) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(lines) == 0 {
		t.Fatal("periodic summary ticker did not emit within 1s")
	}

	// Clear failure -> ticker stops
	globalTokenRenewalTracker.clearFailure(manager)
	countAfterClear := len(log.matchingLines("clients failing renewal"))

	time.Sleep(80 * time.Millisecond)
	countLater := len(log.matchingLines("clients failing renewal"))
	if countLater != countAfterClear {
		t.Fatalf("summary ticker kept emitting after recovery: %d -> %d", countAfterClear, countLater)
	}
}

// TestFormatHumanDuration tests human unit formatting across various ranges.
func TestFormatHumanDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{-5 * time.Second, "0s"},
		{500 * time.Millisecond, "1s"},
		{45 * time.Second, "45s"},
		{59 * time.Second, "59s"},
		{60 * time.Second, "1m"},
		{120 * time.Second, "2m"},
		{595*time.Second + 830*time.Millisecond, "10m"}, // from problem description
		{10 * time.Minute, "10m"},
		{59 * time.Minute, "59m"},
		{60 * time.Minute, "1h"},
		{2 * time.Hour, "2h"},
		{24 * time.Hour, "1d"},
		{48 * time.Hour, "2d"},
	}

	for _, tc := range cases {
		if got := formatHumanDuration(tc.d); got != tc.want {
			t.Errorf("formatHumanDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
