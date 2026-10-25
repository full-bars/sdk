package sdk

// A provider built with DisablePlatformFamilyTransports runs ONE family-agnostic
// transport, which is 3.23's shape for a proxied identity
// (provider/family_transport.go, useFamilyTransports: only the direct identity
// gets the v4/v6/standby group). The miner sets it for proxied slots only.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

const (
	testSingleTransportPlatformUrl   = "wss://connect.test.invalid"
	testSingleTransportPlatformUrlV4 = "wss://connect-v4.test.invalid"
	testSingleTransportPlatformUrlV6 = "wss://connect-v6.test.invalid"
)

// providerPinnedTransportCount is the number of family-pinned transports one
// generation runs: zero for a plain transport.
func providerPinnedTransportCount(t *testing.T, transport migratablePlatformTransport) int {
	t.Helper()
	switch v := transport.(type) {
	case *connect.FamilyPlatformTransportGroup:
		n := 0
		if v.Ipv4Transport() != nil {
			n++
		}
		if v.Ipv6Transport() != nil {
			n++
		}
		return n
	case *connect.PlatformTransport:
		return 0
	default:
		t.Fatalf("unexpected transport %T", transport)
		return -1
	}
}

// newTestSingleTransportProvider is the fixture provider with the family
// fields set exactly as newDeviceLocalProviderWithOverrides sets them for the
// setting (TestDeviceLocalConstructionAppliesDisablePlatformFamilyTransports
// pins that construction does this).
func newTestSingleTransportProvider(t *testing.T, disable bool) *deviceLocalProvider {
	t.Helper()
	v4, v6 := providerFamilyUrls(testSingleTransportPlatformUrlV4, testSingleTransportPlatformUrlV6, disable)
	provider := newTestFamilyProvider(t, v4, v6)
	provider.disablePlatformFamilyTransports = disable
	return provider
}

// The one function that blanks the urls.
func TestProviderFamilyUrlsAppliesTheSetting(t *testing.T) {
	for _, c := range []struct {
		name    string
		disable bool
		wantV4  string
		wantV6  string
	}{
		{"default keeps both pins", false, testSingleTransportPlatformUrlV4, testSingleTransportPlatformUrlV6},
		{"setting blanks both", true, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			v4, v6 := providerFamilyUrls(testSingleTransportPlatformUrlV4, testSingleTransportPlatformUrlV6, c.disable)
			if v4 != c.wantV4 || v6 != c.wantV6 {
				t.Fatalf("urls = %q/%q, want %q/%q", v4, v6, c.wantV4, c.wantV6)
			}
		})
	}
}

// The setting reaches the provider through the real device construction: with
// it the provider keeps no family urls, remembers the setting, and its first
// generation is a plain transport; without it the same space builds the group
// with both pins.
func TestDeviceLocalConstructionAppliesDisablePlatformFamilyTransports(t *testing.T) {
	for _, disable := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "disabled"}[disable], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			strategySettings := testOfflineClientStrategySettings()
			strategySettings.Log = connect.NewNoopLogger()
			networkSpace := NewNetworkSpaceWithUrls(ctx, "https://api.test.invalid", testSingleTransportPlatformUrl, strategySettings)
			t.Cleanup(networkSpace.Close)
			if !networkSpace.HasPlatformFamilyUrls() {
				t.Fatal("the space derived no family urls, so the setting proves nothing")
			}

			settings := testExtenderStatusDeviceSettings()
			settings.AllowProvider = true
			settings.ProvideExtenderEnabled = false
			settings.DnsPumpHost = "pump.test.invalid"
			settings.DisablePlatformFamilyTransports = disable
			device, err := newDeviceLocalWithOverrides(networkSpace, "", "", "", "", NewId(), settings, connect.NewId())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(device.Close)

			device.stateLock.Lock()
			provider := device.provider
			device.stateLock.Unlock()
			if provider == nil {
				t.Fatal("the device built no provider")
			}
			provider.stateLock.Lock()
			transport := provider.platformTransport
			provider.stateLock.Unlock()

			if provider.disablePlatformFamilyTransports != disable {
				t.Fatalf("provider setting = %v, want %v", provider.disablePlatformFamilyTransports, disable)
			}
			pins := providerPinnedTransportCount(t, transport)
			if disable {
				if provider.platformUrlV4 != "" || provider.platformUrlV6 != "" {
					t.Fatalf("family urls = %q/%q, want both blank", provider.platformUrlV4, provider.platformUrlV6)
				}
				if _, ok := transport.(*connect.PlatformTransport); !ok {
					t.Fatalf("first generation is %T, want a plain *connect.PlatformTransport", transport)
				}
				if pins != 0 {
					t.Fatalf("pinned transports = %d, want 0", pins)
				}
			} else {
				if _, ok := transport.(*connect.FamilyPlatformTransportGroup); !ok {
					t.Fatalf("first generation is %T, want the family group", transport)
				}
				if pins != 2 {
					t.Fatalf("pinned transports = %d, want 2", pins)
				}
			}
		})
	}
}

// Every rebuild keeps the shape: the construction generation, the rebuild a
// provide-mode flip to public starts, and a platform-directed (drain)
// migration. The migrations run through the production builder; the hook only
// records what it built. Three generations, pinned transports counted in each.
func TestSingleTransportSurvivesProvideModeFlipAndMigration(t *testing.T) {
	for _, disable := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "disabled"}[disable], func(t *testing.T) {
			provider := newTestSingleTransportProvider(t, disable)
			// the replacements dial nothing reachable; give up on each at once
			// so the migration worker ends without waiting for a connect
			provider.migrateConnectTimeout = time.Millisecond

			var builtLock sync.Mutex
			built := []migratablePlatformTransport{}
			record := func(transport migratablePlatformTransport) migratablePlatformTransport {
				builtLock.Lock()
				defer builtLock.Unlock()
				built = append(built, transport)
				return transport
			}
			t.Cleanup(func() {
				builtLock.Lock()
				defer builtLock.Unlock()
				for _, transport := range built {
					waitTransportDone(t, transport)
				}
			})

			// generation 1, as newDeviceLocalProviderWithOverrides installs it
			first := record(provider.newProviderPlatformTransport(provider.auth, provider.targetMode, provider.platformTransportSettings))
			provider.stateLock.Lock()
			provider.platformTransport = first
			provider.stateLock.Unlock()
			provider.newPlatformTransport = func(
				auth *connect.ClientAuth,
				targetMode connect.TransportMode,
				settings *connect.PlatformTransportSettings,
			) migratablePlatformTransport {
				return record(provider.newProviderPlatformTransport(auth, targetMode, settings))
			}

			// generation 2: the provide-mode flip to public
			provider.setProvideMode(ProvideModePublic)
			provider.migrationWorkers.Wait()
			// generation 3: a platform drain migration
			if !provider.requestPlatformTransportMigrationWith(deviceLocalProviderMigration{
				migrateTime:      time.Now(),
				platformDirected: true,
			}) {
				t.Fatal("the drain migration did not start")
			}
			provider.migrationWorkers.Wait()

			builtLock.Lock()
			generations := append([]migratablePlatformTransport{}, built...)
			builtLock.Unlock()
			if len(generations) != 3 {
				t.Fatalf("generations built = %d, want 3", len(generations))
			}
			for i, transport := range generations {
				pins := providerPinnedTransportCount(t, transport)
				if disable {
					if _, ok := transport.(*connect.PlatformTransport); !ok {
						t.Fatalf("generation %d is %T, want a plain *connect.PlatformTransport", i+1, transport)
					}
					if pins != 0 {
						t.Fatalf("generation %d pinned transports = %d, want 0", i+1, pins)
					}
				} else {
					if _, ok := transport.(*connect.FamilyPlatformTransportGroup); !ok {
						t.Fatalf("generation %d is %T, want the family group", i+1, transport)
					}
					if pins != 2 {
						t.Fatalf("generation %d pinned transports = %d, want 2", i+1, pins)
					}
				}
			}
		})
	}
}

// A space that derives no family urls on its own (an ip literal) keeps the
// legacy group of one standby: only the setting selects the plain transport.
func TestNoFamilyUrlsWithoutTheSettingKeepsTheLegacyGroup(t *testing.T) {
	provider := newTestFamilyProvider(t, "", "")
	transport := provider.newProviderPlatformTransport(provider.auth, provider.targetMode, provider.platformTransportSettings)
	defer waitTransportDone(t, transport)
	group, ok := transport.(*connect.FamilyPlatformTransportGroup)
	if !ok {
		t.Fatalf("transport is %T, want the legacy group", transport)
	}
	if n := len(group.Transports()); n != 1 {
		t.Fatalf("legacy group transports = %d, want 1", n)
	}
}

// The readers that type-switch on the group handle a plain transport: the
// family status falls back to the connected bit, the move path sees exactly
// one family-agnostic transport, and make-before-break is decided in every
// pairing of plain and group.
func TestSingleTransportStatusReadersDoNotPanic(t *testing.T) {
	provider := newTestSingleTransportProvider(t, true)
	transport := provider.newProviderPlatformTransport(provider.auth, provider.targetMode, provider.platformTransportSettings)
	defer waitTransportDone(t, transport)
	plain, ok := transport.(*connect.PlatformTransport)
	if !ok {
		t.Fatalf("transport is %T, want a plain *connect.PlatformTransport", transport)
	}
	if plain.IpFamily() != 0 {
		t.Fatalf("plain transport pinned to family %d, want 0", plain.IpFamily())
	}
	if !plain.Enabled() {
		t.Fatal("plain transport starts disabled; nothing would ever enable it")
	}

	provider.stateLock.Lock()
	provider.platformTransport = transport
	provider.stateLock.Unlock()

	status := provider.familyTransportStatus()
	if status == nil {
		t.Fatal("family status is nil for a plain transport")
	}
	if status.HasIpv4 || status.HasIpv6 {
		t.Fatalf("status = %+v, want no pins reported", *status)
	}
	if status.Ipv4State != ProviderFamilyTransportStateUnknown || status.Ipv6State != ProviderFamilyTransportStateUnknown {
		t.Fatalf("status = %+v, want unknown family states", *status)
	}
	if !status.StandbyActive || status.StandbyState == "" {
		t.Fatalf("status = %+v, want the single transport reported as the active standby", *status)
	}
	_ = provider.IsConnected()

	moves := providerResidentMoveTransports(transport)
	if len(moves) != 1 {
		t.Fatalf("move transports = %d, want 1", len(moves))
	}
	if moves[0].IpFamily() != 0 {
		t.Fatalf("move transport family = %d, want 0", moves[0].IpFamily())
	}

	groupProvider := newTestFamilyProvider(t, testSingleTransportPlatformUrlV4, testSingleTransportPlatformUrlV6)
	group := groupProvider.newProviderPlatformTransport(groupProvider.auth, groupProvider.targetMode, groupProvider.platformTransportSettings)
	defer waitTransportDone(t, group)
	// each pairing is decided without a nil dereference; the values are
	// connect's budget decisions and are not asserted here
	_ = canMakeBeforeBreak(transport, transport)
	_ = canMakeBeforeBreak(transport, group)
	_ = canMakeBeforeBreak(group, transport)
}

// h1UpgradeRecorder is a platform endpoint that records the Upgrade header of
// every request and refuses each one, so a transport keeps dialing it.
type h1UpgradeRecorder struct {
	server   *httptest.Server
	upgrades chan string
}

func newH1UpgradeRecorder(t *testing.T) *h1UpgradeRecorder {
	t.Helper()
	recorder := &h1UpgradeRecorder{upgrades: make(chan string, 64)}
	recorder.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case recorder.upgrades <- r.Header.Get("Upgrade"):
		default:
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(recorder.server.Close)
	return recorder
}

// a fresh listener per case: connect remembers a refused H1+ upgrade per
// host and port (FramedUpgradePermitted), which would hide the next case
func (self *h1UpgradeRecorder) url() string {
	return "ws://" + self.server.Listener.Addr().String()
}

func (self *h1UpgradeRecorder) first(t *testing.T) string {
	t.Helper()
	select {
	case upgrade := <-self.upgrades:
		return upgrade
	case <-time.After(30 * time.Second):
		t.Fatal("the transport never dialed the platform")
		return ""
	}
}

// firstH1Upgrade builds one generation through the production builder,
// public as the miner's providers are (so the strategy is the provider's
// direct standby strategy), and returns the Upgrade header of its first H1
// dial: connect.H1FramerProtocol when H1+ was tried, "websocket" otherwise.
func firstH1Upgrade(t *testing.T, disable bool) string {
	t.Helper()
	recorder := newH1UpgradeRecorder(t)
	var provider *deviceLocalProvider
	if disable {
		provider = newTestSingleTransportProvider(t, true)
		provider.platformUrl = recorder.url()
	} else {
		// the group's standby dials the recorder. Its pins name hosts that
		// never resolve (and in a sandbox without a global address their
		// family is not even supported, so they sleep), which is exactly
		// the state in which the group enables its standby at once
		// (transport_family.go pinnedCannotConnectWithLock).
		provider = newTestFamilyProvider(t, testSingleTransportPlatformUrlV4, testSingleTransportPlatformUrlV6)
		provider.platformUrl = recorder.url()
	}
	provider.provideMode = ProvideModePublic
	transport := provider.newProviderPlatformTransport(provider.auth, connect.TransportModeH1, connect.DefaultPlatformTransportSettings())
	defer waitTransportDone(t, transport)
	if disable {
		if _, ok := transport.(*connect.PlatformTransport); !ok {
			t.Fatalf("transport is %T, want a plain *connect.PlatformTransport", transport)
		}
	} else if _, ok := transport.(*connect.FamilyPlatformTransportGroup); !ok {
		t.Fatalf("transport is %T, want the family group", transport)
	}
	return recorder.first(t)
}

// H1+ acceptance. connect computes the H1+ flag of every H1 dial from the
// transport's own settings (transport.go: EnableH1Plus && V2H1Auth && the
// message limit fits) and gates the attempt on the process switch
// connect.SetH1PlusDisabled, which is what the miner's `h1_plus` control key
// (urnet-tools set h1-plus) calls. The single transport must try H1+ exactly
// where the group's standby did, and the switch must reach it. The group's
// pins copy the same settings and change only family, start, budget priority
// and alt url (NewFamilyPlatformTransportGroup, pinnedSettings), so their
// flag is the standby's; they are not dialed here because a pinned dial
// needs a host path of its family, which a test sandbox may not have.
func TestSingleTransportCarriesH1PlusLikeTheGroup(t *testing.T) {
	previouslyDisabled := !connect.H1PlusAvailable()
	t.Cleanup(func() { connect.SetH1PlusDisabled(previouslyDisabled) })

	connect.SetH1PlusDisabled(false)
	groupUpgrade := firstH1Upgrade(t, false)
	singleUpgrade := firstH1Upgrade(t, true)
	if groupUpgrade != connect.H1FramerProtocol {
		t.Fatalf("group standby first upgrade = %q, want H1+ (%q)", groupUpgrade, connect.H1FramerProtocol)
	}
	if singleUpgrade != groupUpgrade {
		t.Fatalf("single transport first upgrade = %q, want %q like the group", singleUpgrade, groupUpgrade)
	}

	connect.SetH1PlusDisabled(true)
	groupUpgrade = firstH1Upgrade(t, false)
	singleUpgrade = firstH1Upgrade(t, true)
	if groupUpgrade != "websocket" {
		t.Fatalf("group standby first upgrade with H1+ off = %q, want websocket", groupUpgrade)
	}
	if singleUpgrade != "websocket" {
		t.Fatalf("single transport first upgrade with H1+ off = %q, want websocket", singleUpgrade)
	}
}
