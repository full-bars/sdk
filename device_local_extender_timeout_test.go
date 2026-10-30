package sdk

import (
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
		// a zero strategy is raised like any other shorter cap
		{"zero strategy raised", 45 * time.Second, 0, 45 * time.Second},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extenderStrategyRequestTimeout(c.activation, c.strategy); got != c.expect {
				t.Fatalf("extenderStrategyRequestTimeout(%s, %s) = %s, want %s", c.activation, c.strategy, got, c.expect)
			}
		})
	}
}
