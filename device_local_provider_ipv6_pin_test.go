package sdk

// Tests of the optional v6 pin of a provider that runs one family-agnostic
// transport (device_local_provider_ipv6_pin.go). No test reaches a platform:
// every dial is refused by the provide-mode fixture's recorder, so the pins
// here are built, attached, detached and joined, never connected.

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

const testPinnedIpv6Url = "wss://connect-v6.test.invalid"

// newTestPinProvider is the provide-mode fixture with the v6 url a provider
// built with DisablePlatformFamilyTransports keeps for its pin, and its first
// generation installed.
func newTestPinProvider(t *testing.T) *deviceLocalProvider {
	t.Helper()
	provider, _ := newTestProvideModeProvider(t, ProvideModeNetwork)
	provider.pinnedIpv6PlatformUrl = providerPinnedIpv6PlatformUrl(testPinnedIpv6Url, true)
	provider.platformTransport = provider.newProviderPlatformTransport(
		provider.auth,
		provider.targetMode,
		provider.platformTransportSettings,
	)
	t.Cleanup(func() {
		_ = provider.CloseAndWait(context.Background())
	})
	return provider
}

func currentPlain(t *testing.T, provider *deviceLocalProvider) *providerPlainTransport {
	t.Helper()
	provider.stateLock.Lock()
	defer provider.stateLock.Unlock()
	plain, ok := provider.platformTransport.(*providerPlainTransport)
	if !ok {
		t.Fatalf("current generation is %T, want *providerPlainTransport", provider.platformTransport)
	}
	return plain
}

// assertPinShape checks a plain generation: the agnostic transport, plus
// exactly one v6-pinned transport when wantPin.
func assertPinShape(t *testing.T, label string, plain *providerPlainTransport, wantPin bool) {
	t.Helper()
	transports := plain.Transports()
	if transports[0] != plain.agnostic || plain.agnostic.IpFamily() != 0 {
		t.Fatalf("%s: first transport is not the family-agnostic one", label)
	}
	if !wantPin {
		if len(transports) != 1 || plain.Ipv6Transport() != nil {
			t.Fatalf("%s: %d transports, want the agnostic transport alone", label, len(transports))
		}
		return
	}
	if len(transports) != 2 {
		t.Fatalf("%s: %d transports, want the agnostic transport and one v6 pin", label, len(transports))
	}
	if pin := plain.Ipv6Transport(); pin == nil || pin.IpFamily() != 6 || transports[1] != pin {
		t.Fatalf("%s: second transport is not pinned to v6", label)
	}
}

// waitGoroutinesAtMost polls until the count drops to want, so the settle
// takes as long as the joins do and no longer.
func waitGoroutinesAtMost(t *testing.T, want int) {
	t.Helper()
	if !waitProviderCondition(5*time.Second, func() bool {
		runtime.GC()
		return runtime.NumGoroutine() <= want
	}) {
		t.Fatalf("goroutines = %d after the pin closed, want at most %d", runtime.NumGoroutine(), want)
	}
}

func TestProviderPinnedIpv6UrlOnlyForTheSingleTransport(t *testing.T) {
	if url := providerPinnedIpv6PlatformUrl(testPinnedIpv6Url, false); url != "" {
		t.Fatalf("a provider with the family group got an optional pin url %q", url)
	}
	if url := providerPinnedIpv6PlatformUrl(testPinnedIpv6Url, true); url != testPinnedIpv6Url {
		t.Fatalf("pin url = %q, want %q", url, testPinnedIpv6Url)
	}
}

// Enabled: the agnostic transport plus exactly one v6 pin. Disabled (the
// default): exactly one transport.
func TestProviderPinBuildShape(t *testing.T) {
	provider := newTestPinProvider(t)
	assertPinShape(t, "default", currentPlain(t, provider), false)

	provider.stateLock.Lock()
	provider.pinnedIpv6Enabled = true
	provider.stateLock.Unlock()
	built := provider.newProviderPlatformTransport(provider.auth, provider.targetMode, provider.platformTransportSettings)
	defer waitTransportDone(t, built)
	plain, ok := built.(*providerPlainTransport)
	if !ok {
		t.Fatalf("built %T, want *providerPlainTransport", built)
	}
	assertPinShape(t, "built while enabled", plain, true)
	if status := func() *ProviderFamilyTransportStatus {
		provider.stateLock.Lock()
		previous := provider.platformTransport
		provider.platformTransport = built
		provider.stateLock.Unlock()
		defer func() {
			provider.stateLock.Lock()
			provider.platformTransport = previous
			provider.stateLock.Unlock()
		}()
		return provider.familyTransportStatus()
	}(); !status.HasIpv6 || status.HasIpv4 || !status.StandbyActive {
		t.Fatalf("status with the pin = %+v, want v6 present, no v4, the agnostic transport active", *status)
	}
}

// The runtime switch attaches and detaches on the current generation, and a
// closed pin leaves no goroutine behind.
func TestProviderPinToggleLeavesNoGoroutine(t *testing.T) {
	provider := newTestPinProvider(t)
	plain := currentPlain(t, provider)
	runtime.GC()
	baseline := runtime.NumGoroutine()

	provider.setPinnedIpv6Enabled(true)
	assertPinShape(t, "enabled", plain, true)
	pin := plain.Ipv6Transport()
	if runtime.NumGoroutine() <= baseline {
		t.Fatalf("goroutines = %d with the pin, baseline %d: the pin started nothing", runtime.NumGoroutine(), baseline)
	}

	provider.setPinnedIpv6Enabled(false)
	assertPinShape(t, "disabled", plain, false)
	select {
	case <-pin.Done():
	default:
		t.Fatal("the closed pin's transport is not done when the switch returned")
	}
	waitGoroutinesAtMost(t, baseline)

	// a repeated switch is a no-op, not a second pin
	provider.setPinnedIpv6Enabled(true)
	provider.setPinnedIpv6Enabled(true)
	assertPinShape(t, "enabled twice", plain, true)
}

// The pin is present or absent as asked across three generations: a flip to
// public, a flip back, and a platform drain, each built by the production
// builder and installed by the production migration.
func TestProviderPinFollowsEveryGeneration(t *testing.T) {
	provider := newTestPinProvider(t)
	generations := make(chan *providerPlainTransport, 8)
	var hook struct {
		sync.Mutex
		duringBuild func()
	}
	provider.newPlatformTransport = func(
		auth *connect.ClientAuth,
		targetMode connect.TransportMode,
		settings *connect.PlatformTransportSettings,
	) migratablePlatformTransport {
		next := provider.newProviderPlatformTransport(auth, targetMode, settings).(*providerPlainTransport)
		next.connectedForTest = true
		hook.Lock()
		duringBuild := hook.duringBuild
		hook.duringBuild = nil
		hook.Unlock()
		if duringBuild != nil {
			// a change that lands after the build and before the install
			duringBuild()
		}
		generations <- next
		return next
	}
	installed := func(label string) *providerPlainTransport {
		t.Helper()
		var next *providerPlainTransport
		select {
		case next = <-generations:
		case <-time.After(15 * time.Second):
			t.Fatalf("%s: no generation was built", label)
		}
		if !waitProviderCondition(15*time.Second, func() bool {
			provider.stateLock.Lock()
			defer provider.stateLock.Unlock()
			return provider.platformTransport == next && !provider.migrating.Load()
		}) {
			t.Fatalf("%s: the generation was not installed", label)
		}
		return next
	}

	provider.setPinnedIpv6Enabled(true)
	first := currentPlain(t, provider)
	assertPinShape(t, "first generation", first, true)
	firstPin := first.Ipv6Transport()

	// generation 2: the flip to public, built while the pin is wanted
	provider.setProvideMode(ProvideModePublic)
	second := installed("flip to public")
	assertPinShape(t, "flip to public", second, true)
	select {
	case <-firstPin.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the replaced generation's pin was not closed")
	}

	// generation 3: the flip back, built with the pin and switched off before
	// its install. The install must not resurrect it.
	hook.Lock()
	hook.duringBuild = func() { provider.setPinnedIpv6Enabled(false) }
	hook.Unlock()
	provider.setProvideMode(ProvideModeNetwork)
	third := installed("flip back, switched off in flight")
	assertPinShape(t, "flip back, switched off in flight", third, false)

	// generation 4: a drain, built without the pin and switched on before its
	// install. The install must not lose it.
	hook.Lock()
	hook.duringBuild = func() { provider.setPinnedIpv6Enabled(true) }
	hook.Unlock()
	provider.requestPlatformTransportMigrationWith(deviceLocalProviderMigration{
		migrateTime:      time.Now(),
		platformDirected: true,
	})
	fourth := installed("drain, switched on in flight")
	assertPinShape(t, "drain, switched on in flight", fourth, true)

	// every replaced generation is closed, pins included
	for label, plain := range map[string]*providerPlainTransport{"second": second, "third": third} {
		if _, closed := plain.pinState(); !closed {
			t.Fatalf("the %s generation was not closed when replaced", label)
		}
	}
}

// The direct slot keeps the family group: the switch is a no-op there.
func TestProviderPinDoesNotTouchTheGroup(t *testing.T) {
	provider := newTestFamilyProvider(t, "wss://connect-v4.test.invalid", "wss://connect-v6.test.invalid")
	group := provider.newProviderPlatformTransport(provider.auth, provider.targetMode, provider.platformTransportSettings)
	provider.platformTransport = group
	t.Cleanup(func() { _ = provider.CloseAndWait(context.Background()) })

	provider.setPinnedIpv6Enabled(true)
	provider.stateLock.Lock()
	current := provider.platformTransport
	provider.stateLock.Unlock()
	if current != group {
		t.Fatal("the switch replaced the family group")
	}
	if n := len(group.(*connect.FamilyPlatformTransportGroup).Transports()); n != 3 {
		t.Fatalf("group transports = %d after the switch, want 3", n)
	}
	rebuilt := provider.newProviderPlatformTransport(provider.auth, provider.targetMode, provider.platformTransportSettings)
	defer waitTransportDone(t, rebuilt)
	if _, ok := rebuilt.(*connect.FamilyPlatformTransportGroup); !ok {
		t.Fatalf("a rebuild with the switch on built %T, want the family group", rebuilt)
	}
}

// The pin takes the generation's settings: H1+, the v2 H1 auth, the stats
// collectors, the budget and the client limit hold are the same objects.
func TestProviderPinSettingsKeepH1Plus(t *testing.T) {
	settings := connect.DefaultPlatformTransportSettings()
	settings.EnableH1Plus = true
	settings.V2H1Auth = true
	settings.H1PlusStats = &connect.H1PlusStats{}
	settings.H1ConnectionStats = &connect.H1ConnectionStats{}
	settings.ClientLimitBackoff = connect.NewClientLimitBackoff()
	settings.PlatformTransportBudget = connect.NewPlatformTransportBudget(1<<20, 0)
	settings.AltUrl = "wss://alt.test.invalid"
	settings.IpFamily = 0

	pinned := providerIpv6PinSettings(settings)
	if pinned.EnableH1Plus != settings.EnableH1Plus ||
		pinned.V2H1Auth != settings.V2H1Auth ||
		pinned.H1PlusStats != settings.H1PlusStats ||
		pinned.H1ConnectionStats != settings.H1ConnectionStats ||
		pinned.ClientLimitBackoff != settings.ClientLimitBackoff ||
		pinned.PlatformTransportBudget != settings.PlatformTransportBudget {
		t.Fatal("the pin's settings differ from the agnostic transport's outside the family")
	}
	if pinned.IpFamily != 6 || pinned.PlatformTransportBudgetPriority != connect.PlatformTransportBudgetPriorityBackground {
		t.Fatalf("pin family %d priority %d, want 6 and background", pinned.IpFamily, pinned.PlatformTransportBudgetPriority)
	}
	if settings.IpFamily != 0 || settings.AltUrl == "" {
		t.Fatal("building the pin's settings mutated the caller's")
	}
}

// The pin is H1 only and dials the v6 url with the settings above. No seam
// exposes a transport's mode or settings, so this reads the builder.
func TestProviderPinBuilderIsH1Only(t *testing.T) {
	source, err := os.ReadFile("device_local_provider_ipv6_pin.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"connect.NewDirectClientStrategy(self.client.Ctx(), strategySettings, 6)",
		"connect.TransportModeH1,\n\t\tproviderIpv6PinSettings(settings),",
		"self.client.RouteManager(),\n\t\tself.pinnedIpv6PlatformUrl,",
	} {
		if !strings.Contains(string(source), want) {
			t.Fatalf("the pin builder no longer contains %q", want)
		}
	}
}

type recordingPinObserver struct {
	mu      sync.Mutex
	results []bool
}

func (self *recordingPinObserver) PinnedIpv6Dial(success bool) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.results = append(self.results, success)
}

func (self *recordingPinObserver) take() []bool {
	self.mu.Lock()
	defer self.mu.Unlock()
	results := self.results
	self.results = nil
	return results
}

func TestProviderPinDialObserverRule(t *testing.T) {
	observer := &recordingPinObserver{}
	up := func() bool { return true }
	down := func() bool { return false }
	failed := errors.New("socks connect tcp6: unexpected EOF")
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, c := range []struct {
		name      string
		connected func() bool
		ctx       context.Context
		err       error
		want      []bool
	}{
		{"success", down, context.Background(), nil, []bool{true}},
		{"isolated failure counts", up, context.Background(), failed, []bool{false}},
		{"failure with the agnostic transport down", down, context.Background(), failed, nil},
		{"canceled error", up, context.Background(), context.Canceled, nil},
		{"canceled dial", up, canceledCtx, failed, nil},
		{"deadline counts", up, context.Background(), context.DeadlineExceeded, []bool{false}},
	} {
		t.Run(c.name, func(t *testing.T) {
			observeIpv6PinDial(observer, c.connected, c.ctx, c.err)
			got := observer.take()
			if len(got) != len(c.want) || (len(got) == 1 && got[0] != c.want[0]) {
				t.Fatalf("reported %v, want %v", got, c.want)
			}
		})
	}
	// no observer installed is no report and no panic
	observeIpv6PinDial(nil, up, context.Background(), failed)
}

// The observed dial is the injected one, so a proxied identity's pin still
// dials through its proxy, and the factory survives.
func TestProviderPinStrategyKeepsTheInjectedDial(t *testing.T) {
	injectedCalls := 0
	factory := func(context.Context) (net.PacketConn, error) { return nil, errors.New("unused") }
	settings := connect.DefaultClientStrategySettings()
	settings.ConnectSettings.DialContextSettings = &connect.DialContextSettings{
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			injectedCalls++
			if network != "tcp6" || addr != "connect-v6.test.invalid:443" {
				t.Fatalf("injected dial got %s %s", network, addr)
			}
			return nil, errors.New("refused by the test")
		},
		PacketConnFactory: factory,
	}
	var observed []error
	wrapped := providerIpv6PinStrategySettings(settings, func(ctx context.Context, err error) {
		observed = append(observed, err)
	})
	if settings.ConnectSettings.DialContextSettings.PacketConnFactory == nil || wrapped.ConnectSettings.DialContextSettings.PacketConnFactory == nil {
		t.Fatal("the packet conn factory was dropped")
	}
	_, err := wrapped.ConnectSettings.DialContextSettings.DialContext(context.Background(), "tcp6", "connect-v6.test.invalid:443")
	if err == nil || injectedCalls != 1 || len(observed) != 1 || observed[0] != err {
		t.Fatalf("injected calls %d, observed %v, err %v", injectedCalls, observed, err)
	}
}
