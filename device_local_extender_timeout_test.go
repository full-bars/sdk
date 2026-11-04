//go:build !ios && !android && !js

package sdk

import (
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

func TestExtenderActivationStrategyRequestBudget(t *testing.T) {
	cases := []struct {
		name       string
		activation time.Duration
		strategy   time.Duration
		want       time.Duration
	}{
		{"default activation", 0, 15 * time.Second, connect.DefaultExtenderActivatorSettings().RequestTimeout},
		{"configured activation", 90 * time.Second, 15 * time.Second, 90 * time.Second},
		{"longer strategy retained", 30 * time.Second, 90 * time.Second, 90 * time.Second},
		{"negative activation uses default", -time.Second, 15 * time.Second, connect.DefaultExtenderActivatorSettings().RequestTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var supplied *connect.ClientStrategySettings
			fixture := newTestProvideExtenderFixture(t, func(settings *deviceLocalExtenderSettings) {
				settings.RequestTimeout = tc.activation
				supplied = settings.ClientStrategySettings
				supplied.ConnectSettings.RequestTimeout = tc.strategy
			})
			strategy := fixture.extender().clientStrategy
			if got := strategy.ConnectSettings().RequestTimeout; got != tc.want {
				t.Fatalf("strategy request timeout = %s, want %s", got, tc.want)
			}
			if got := supplied.ConnectSettings.RequestTimeout; got != tc.strategy {
				t.Fatalf("caller strategy settings changed to %s, want %s", got, tc.strategy)
			}
		})
	}
}
