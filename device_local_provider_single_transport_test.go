package sdk

// A provider built with DisablePlatformFamilyTransports runs ONE family-agnostic
// transport, which is 3.23's shape for a proxied identity
// (provider/family_transport.go, useFamilyTransports: only the direct identity
// gets the v4/v6/standby group). The miner sets it for proxied slots, where a
// pinned v6 transport can only fail: the SOCKS proxy carries the connection,
// not the host's own route.

import (
	"testing"

	"github.com/urnetwork/connect"
)

// TestProviderFamilyUrlsAppliesTheSetting pins the one function that decides:
// the urls are blanked rather than flagged, because empty urls are what every
// transport construction already reads as "legacy single transport".
func TestProviderFamilyUrlsAppliesTheSetting(t *testing.T) {
	for _, c := range []struct {
		name    string
		disable bool
		wantV4  string
		wantV6  string
	}{
		{"default keeps both pins", false, "wss://connect-v4.invalid", "wss://connect-v6.invalid"},
		{"setting blanks both", true, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			v4, v6 := providerFamilyUrls("wss://connect-v4.invalid", "wss://connect-v6.invalid", c.disable)
			if v4 != c.wantV4 || v6 != c.wantV6 {
				t.Fatalf("urls = %q/%q, want %q/%q", v4, v6, c.wantV4, c.wantV6)
			}
		})
	}
}

// TestProviderWithNoFamilyUrlsBuildsOnePlainTransport is the Step 1 shape: no
// pinned transports, no group. A group wrapping only the standby would still
// pay the group's watcher goroutines and standby delay for a decision with
// nothing to decide.
func TestProviderWithNoFamilyUrlsBuildsOnePlainTransport(t *testing.T) {
	provider := newTestFamilyProvider(t, "", "")
	transport := provider.newProviderPlatformTransport(
		provider.auth,
		provider.targetMode,
		connect.DefaultPlatformTransportSettings(),
	)
	defer waitTransportDone(t, transport)

	if _, ok := transport.(*connect.FamilyPlatformTransportGroup); ok {
		t.Fatal("built a family group with no family urls; the group exists to arbitrate pins that do not exist")
	}
	// the generation is the agnostic transport alone: the optional v6 pin
	// (device_local_provider_ipv6_pin.go) is off by default
	plain, ok := transport.(*providerPlainTransport)
	if !ok {
		t.Fatalf("transport is %T, want a plain generation", transport)
	}
	if n := len(plain.Transports()); n != 1 {
		t.Fatalf("plain generation runs %d transports, want 1", n)
	}
	if plain.agnostic.IpFamily() != 0 {
		t.Fatalf("plain transport pinned to family %d, want 0 (family-agnostic)", plain.agnostic.IpFamily())
	}
}

// TestProviderWithFamilyUrlsStillBuildsTheGroup guards the direct identity: the
// setting must not turn the dual-stack group off for everyone.
func TestProviderWithFamilyUrlsStillBuildsTheGroup(t *testing.T) {
	provider := newTestFamilyProvider(t, "wss://connect-v4.test.invalid", "wss://connect-v6.test.invalid")
	transport := provider.newProviderPlatformTransport(
		provider.auth,
		provider.targetMode,
		connect.DefaultPlatformTransportSettings(),
	)
	defer waitTransportDone(t, transport)

	group, ok := transport.(*connect.FamilyPlatformTransportGroup)
	if !ok {
		t.Fatalf("transport is %T, want a *connect.FamilyPlatformTransportGroup", transport)
	}
	if group.Ipv4Transport() == nil || group.Ipv6Transport() == nil {
		t.Fatal("group is missing a pinned transport")
	}
	status := group.Status()
	if !status.HasIpv4 || !status.HasIpv6 {
		t.Fatalf("group status = ipv4 %v ipv6 %v, want both", status.HasIpv4, status.HasIpv6)
	}
}

// TestSingleTransportSurvivesEveryGeneration pins the rebuild requirement: a
// provide-mode flip or a drain migration calls newProviderPlatformTransport
// again, and each generation must be a plain transport too. Counting across
// three generations is the cheap stand-in for the three rebuild paths.
func TestSingleTransportSurvivesEveryGeneration(t *testing.T) {
	provider := newTestFamilyProvider(t, "", "")
	for generation := 0; generation < 3; generation++ {
		transport := provider.newProviderPlatformTransport(
			provider.auth,
			provider.targetMode,
			connect.DefaultPlatformTransportSettings(),
		)
		if _, ok := transport.(*connect.FamilyPlatformTransportGroup); ok {
			t.Fatalf("generation %d rebuilt a family group", generation)
		}
		waitTransportDone(t, transport)
	}
}

// TestSingleTransportStatusReadersDoNotPanic covers the readers that assume a
// group: the family status readout must fall back to the connected bit, and the
// move path must see exactly one transport. A nil dereference here would crash
// the status endpoint on the first proxied identity.
func TestSingleTransportStatusReadersDoNotPanic(t *testing.T) {
	provider := newTestFamilyProvider(t, "", "")
	transport := provider.newProviderPlatformTransport(
		provider.auth,
		provider.targetMode,
		connect.DefaultPlatformTransportSettings(),
	)
	defer waitTransportDone(t, transport)

	provider.stateLock.Lock()
	provider.platformTransport = transport
	provider.stateLock.Unlock()

	if status := provider.familyTransportStatus(); status == nil {
		t.Fatal("family status is nil for a plain transport")
	}
	if moves := providerResidentMoveTransports(transport); len(moves) != 1 {
		t.Fatalf("move transports = %d, want 1 for a single transport", len(moves))
	}
	if !canMakeBeforeBreak(transport, transport) {
		t.Fatal("a plain transport refused make-before-break against itself")
	}
}

// TestSingleTransportRunsItsOwnH1Dial is a structural check, not an H1+ test.
//
// H1+ is switched inside the strategy's H1 dial, which PlatformTransport makes
// for itself; the group never carried the flag. No seam exposes a transport's
// settings, so what can be asserted here is only that the provider builds a
// transport that dials rather than a group that delegates. The H1+ proof is the
// expression at connect transport.go:2443-2449 (at pin 49d75e264480), which
// reads the transport's own settings, quoted in the pull request.
func TestSingleTransportRunsItsOwnH1Dial(t *testing.T) {
	provider := newTestFamilyProvider(t, "", "")
	transport := provider.newProviderPlatformTransport(
		provider.auth,
		provider.targetMode,
		connect.DefaultPlatformTransportSettings(),
	)
	defer waitTransportDone(t, transport)
	plain, ok := transport.(*providerPlainTransport)
	if !ok {
		t.Fatalf("transport %T does not run its own H1 dial", transport)
	}
	// IpFamily comes from the settings the transport was built with: 0 is the
	// family-agnostic copy the provider hands over, not a pinned child's.
	if plain.agnostic.IpFamily() != 0 {
		t.Fatalf("transport pinned to family %d, want the agnostic 0", plain.agnostic.IpFamily())
	}
}
