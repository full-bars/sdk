//go:build !ios && !android && !js

package sdk

import (
	"testing"

	"github.com/urnetwork/connect"
)

// A hold is a session decision: it withholds the role and it never clears the
// embedder's setting, which is what separates it from the user's own
// preference. That is what lets an embedder revisit a launch-time decision.
func TestHoldProvideExtenderSession(t *testing.T) {
	device := &DeviceLocal{log: connect.NewNoopLogger(), extenderProvideMonitor: connect.NewMonitor()}
	device.settings = &DeviceLocalSettings{ProvideExtenderEnabled: true}

	device.HoldProvideExtenderSession(true)
	if !device.provideExtenderSessionHeld {
		t.Fatal("the hold was not recorded")
	}
	if !device.settings.ProvideExtenderEnabled {
		t.Fatal("the hold must not clear the embedder's setting")
	}

	device.HoldProvideExtenderSession(false)
	if device.provideExtenderSessionHeld {
		t.Fatal("the hold was not released")
	}
}

// A hold that is already in force is not re-applied, so a repeated decision
// does not churn the status listeners.
func TestHoldProvideExtenderSessionIsIdempotent(t *testing.T) {
	device := &DeviceLocal{log: connect.NewNoopLogger(), extenderProvideMonitor: connect.NewMonitor()}
	device.settings = &DeviceLocalSettings{ProvideExtenderEnabled: true}

	device.HoldProvideExtenderSession(true)
	device.HoldProvideExtenderSession(true)
	if !device.provideExtenderSessionHeld {
		t.Fatal("the hold must still be in force")
	}

	device.HoldProvideExtenderSession(false)
	device.HoldProvideExtenderSession(false)
	if device.provideExtenderSessionHeld {
		t.Fatal("the hold must be released")
	}
}
