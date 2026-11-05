package sdk

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// The extender's direct strategy caps every request it carries, so the cap has
// to allow at least the activation's budget. A cap below it tears the
// activation down mid-probe while the operator still spends the caller's
// budget on the request.
func TestExtenderStrategyRequestTimeout(t *testing.T) {
	defaultTimeout := connect.DefaultExtenderActivatorSettings().RequestTimeout
	if defaultTimeout <= 0 {
		t.Fatalf("the activator default must be positive, got %s", defaultTimeout)
	}
	if defaultTimeout <= 15*time.Second {
		t.Fatalf("the activator default must exceed the strategy's 15s default, got %s", defaultTimeout)
	}

	cases := []struct {
		name       string
		activation time.Duration
		strategy   time.Duration
		expect     time.Duration
	}{
		// a zero budget means the activator's own default, which is what an
		// unset provider setting resolves to
		{"zero activation takes the default", 0, 15 * time.Second, defaultTimeout},
		// a negative budget is not a shorter budget, it is unset
		{"negative activation takes the default", -time.Second, 15 * time.Second, defaultTimeout},
		// the ordinary repair: the strategy's 15s is raised to the activation's
		{"strategy raised to activation", 90 * time.Second, 15 * time.Second, 90 * time.Second},
		// a strategy already longer than the activation is never lowered
		{"longer strategy kept", 5 * time.Second, 30 * time.Second, 30 * time.Second},
		// equal budgets stay put
		{"equal budgets stay", 60 * time.Second, 60 * time.Second, 60 * time.Second},
		// a zero strategy timeout is no cap (connect reads it as unbounded),
		// so raising it to the budget would add a cap that was never there
		{"zero strategy stays unbounded", 45 * time.Second, 0, 0},
		{"negative strategy stays unbounded", 45 * time.Second, -time.Second, -time.Second},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extenderStrategyRequestTimeout(c.activation, c.strategy); got != c.expect {
				t.Fatalf("extenderStrategyRequestTimeout(%s, %s) = %s, want %s", c.activation, c.strategy, got, c.expect)
			}
		})
	}
}

// captureExtenderDirectStrategy installs a capture in place of
// connect.NewDirectClientStrategy and returns the settings the role's client
// strategy is built from. The capture returns no strategy.
func captureExtenderDirectStrategy(t *testing.T) **connect.ClientStrategySettings {
	t.Helper()
	captured := new(*connect.ClientStrategySettings)
	original := newExtenderDirectClientStrategy
	newExtenderDirectClientStrategy = func(ctx context.Context, settings *connect.ClientStrategySettings, ipFamily int) *connect.ClientStrategy {
		*captured = settings
		return nil
	}
	t.Cleanup(func() {
		newExtenderDirectClientStrategy = original
	})
	return captured
}

// The raised timeout has to reach the strategy the role builds, not only the
// helper that computes it: the activator sets its budget after the strategy is
// configured, so a hook that changes it later never gets there.
func TestExtenderStrategyTimeoutReachesDirectStrategy(t *testing.T) {
	cases := []struct {
		name       string
		activation time.Duration
		strategy   time.Duration
		expect     time.Duration
	}{
		{"activation budget reaches the strategy", 90 * time.Second, 15 * time.Second, 90 * time.Second},
		{"unset activation reaches the strategy as the default", 0, 15 * time.Second, connect.DefaultExtenderActivatorSettings().RequestTimeout},
		{"longer strategy reaches the strategy", 5 * time.Second, 30 * time.Second, 30 * time.Second},
		{"unbounded strategy stays unbounded", 90 * time.Second, 0, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			captured := captureExtenderDirectStrategy(t)
			strategySettings := connect.DefaultClientStrategySettings()
			strategySettings.ConnectSettings.RequestTimeout = c.strategy
			self := &deviceLocalExtender{
				ctx: context.Background(),
				settings: &deviceLocalExtenderSettings{
					RequestTimeout:         c.activation,
					ClientStrategySettings: strategySettings,
				},
			}
			self.newClientStrategy()
			if *captured == nil {
				t.Fatalf("the role built no direct client strategy")
			}
			if got := (*captured).ConnectSettings.RequestTimeout; got != c.expect {
				t.Fatalf("direct strategy RequestTimeout = %s, want %s", got, c.expect)
			}
		})
	}
}

// Raising the strategy timeout copies the caller's settings. The caller's
// strategy settings keep their own timeout, so the same settings can build
// another role later without picking up this one's budget.
func TestExtenderStrategyCallerSettingsUntouched(t *testing.T) {
	captured := captureExtenderDirectStrategy(t)
	strategySettings := connect.DefaultClientStrategySettings()
	before := strategySettings.ConnectSettings.RequestTimeout
	roleSettings := &deviceLocalExtenderSettings{
		RequestTimeout:         90 * time.Second,
		ClientStrategySettings: strategySettings,
	}
	self := &deviceLocalExtender{ctx: context.Background(), settings: roleSettings}
	self.newClientStrategy()

	if got := strategySettings.ConnectSettings.RequestTimeout; got != before {
		t.Fatalf("the caller's strategy RequestTimeout changed from %s to %s", before, got)
	}
	if roleSettings.ClientStrategySettings != strategySettings {
		t.Fatalf("the caller's strategy settings pointer was replaced")
	}
	if *captured == strategySettings {
		t.Fatalf("the strategy was built from the caller's settings, not a copy")
	}
	if got := (*captured).ConnectSettings.RequestTimeout; got != 90*time.Second {
		t.Fatalf("the copy's RequestTimeout = %s, want 90s", got)
	}
}
