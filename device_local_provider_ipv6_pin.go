package sdk

// device_local_provider_ipv6_pin.go - the optional IPv6-pinned transport of a
// provider that runs ONE family-agnostic transport
// (DisablePlatformFamilyTransports).
//
// The platform records a provider as dual-stack only when it has proven both
// families: a connection with no declared family proves v4, and a pinned
// connection proves its family when the family the server observed matches
// the declared one. A proxied identity runs one agnostic transport, so it can
// only ever prove v4. When its proxy has real IPv6 egress, one extra transport
// pinned to v6 and dialed through the same proxy proves v6 as well.
//
// Every proxy without IPv6 must pay nothing for this, so the pin is never held
// parked: a parked transport still takes its H1 budget reservation and starts
// its run loop, its mode runner and a strategy. It is BUILT when the embedder
// asks for it and CLOSED when the embedder stops asking.
//
// The wanted state is provider state, not transport state. A provide-mode flip
// and a platform drain or move each build a new transport generation through
// newProviderPlatformTransport, so:
//   - a generation built while the pin is wanted is built with it;
//   - a generation built before a change is corrected when it is installed,
//     under stateLock, in the same scope as the swap, so a migration in flight
//     can neither lose a pin that was asked for nor resurrect one that was not.
//
// The pin is H1 only. H3 would leave through the proxy's SOCKS UDP relay, and
// whether that relay exits over IPv6 is not known.
//
// Lock order: pinnedIpv6Lock, then the provider's stateLock, then a
// generation's own stateLock. Nothing under a generation's lock calls out.

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/urnetwork/connect"
)

// PinnedIpv6DialObserver hears the outcome of the v6 pin's dial attempts, so
// an embedder can retire a pin whose proxy stopped carrying IPv6.
//
// It sees the attempt below the pin's family enforcement and above nothing:
// for a proxied identity that is the proxy dial plus the SOCKS CONNECT to the
// v6 host. A success is reported as true. A failure is reported as false only
// when it counts as evidence about the v6 path: it was not a local
// cancellation, and the generation's family-agnostic transport was connected
// at that moment, so the proxy itself was working. Every other failure is not
// reported.
//
// It is called on the dial goroutine and must not block.
type PinnedIpv6DialObserver interface {
	PinnedIpv6Dial(success bool)
}

// providerPlainTransport is one generation of a provider that runs one
// family-agnostic transport, with room for the optional v6 pin. With no pin it
// costs one small struct and nothing else: no goroutine, no strategy, no
// budget reservation.
type providerPlainTransport struct {
	agnostic *connect.PlatformTransport

	stateLock sync.Mutex
	// set by Close. A closed generation keeps the pin it had so CloseAndWait
	// can join it, and refuses any attach or detach after that
	closed bool
	pin    *providerIpv6Pin

	// connectedForTest makes the generation read connected, so a package test
	// can drive a migration's install with real generations and no platform.
	// Set before the generation is handed to a migration; never in production.
	connectedForTest bool
}

func newProviderPlainTransport(agnostic *connect.PlatformTransport) *providerPlainTransport {
	return &providerPlainTransport{agnostic: agnostic}
}

// providerIpv6Pin is the pinned transport and the direct strategy it owns.
type providerIpv6Pin struct {
	transport *connect.PlatformTransport
	strategy  *connect.ClientStrategy
}

// close stops the pin without waiting, as the family group closes its pins.
func (self *providerIpv6Pin) close() {
	self.transport.Close()
	self.strategy.Close()
}

// closeAndWait stops the pin and joins its transport, so no goroutine of it
// outlives the call. The strategy is closed after the transport that dials
// with it is done.
func (self *providerIpv6Pin) closeAndWait() {
	self.transport.Close()
	_ = self.transport.CloseAndWait(context.Background())
	self.strategy.Close()
}

// The family-agnostic transport carries the generation: it alone decides
// connected, because the pin is optional and a migration must not wait on it.
func (self *providerPlainTransport) ConnectedNotify() <-chan struct{} {
	return self.agnostic.ConnectedNotify()
}

func (self *providerPlainTransport) IsConnected() bool {
	return self.connectedForTest || self.agnostic.IsConnected()
}

func (self *providerPlainTransport) SetAuth(auth *connect.ClientAuth) {
	self.agnostic.SetAuth(auth)
	if pin := self.currentPin(); pin != nil {
		pin.transport.SetAuth(auth)
	}
}

// Close is nonblocking, like the transport it wraps.
func (self *providerPlainTransport) Close() {
	pin := func() *providerIpv6Pin {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		return self.pin
	}()
	self.agnostic.Close()
	if pin != nil {
		pin.close()
	}
}

// CloseAndWait joins both transports. A pin detached before the close is
// joined by whoever detached it.
func (self *providerPlainTransport) CloseAndWait(ctx context.Context) error {
	self.Close()
	err := self.agnostic.CloseAndWait(ctx)
	if pin := self.currentPin(); pin != nil {
		err = errors.Join(err, pin.transport.CloseAndWait(ctx))
	}
	return err
}

// Transports lists the agnostic transport and, when present, the pin.
func (self *providerPlainTransport) Transports() []*connect.PlatformTransport {
	transports := []*connect.PlatformTransport{self.agnostic}
	if pin := self.currentPin(); pin != nil {
		transports = append(transports, pin.transport)
	}
	return transports
}

// Ipv6Transport is the pin, nil while there is none.
func (self *providerPlainTransport) Ipv6Transport() *connect.PlatformTransport {
	if pin := self.currentPin(); pin != nil {
		return pin.transport
	}
	return nil
}

func (self *providerPlainTransport) currentPin() *providerIpv6Pin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pin
}

// pinState reads whether a pin is attached and whether the generation closed.
func (self *providerPlainTransport) pinState() (hasPin bool, closed bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pin != nil, self.closed
}

// attachPin installs pin, false when the generation is closed or already has
// one. The caller closes a pin that was not attached.
func (self *providerPlainTransport) attachPin(pin *providerIpv6Pin) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed || self.pin != nil {
		return false
	}
	self.pin = pin
	return true
}

// detachPin removes the pin and hands it to the caller to close, nil when
// there is none or the generation closed (its Close owns the pin then).
func (self *providerPlainTransport) detachPin() *providerIpv6Pin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil
	}
	pin := self.pin
	self.pin = nil
	return pin
}

// providerIpv6PinSettings is the pin's copy of the generation's settings: the
// same settings in every respect that is not about the family (H1+, the v2 H1
// auth, the stats collectors, the budget, the client limit hold, the move
// memory), pinned to v6 and ranked as background for the budget, as the
// family group's pinnedSettings does.
//
// Two fields differ from the group's pins, both because the pin is H1 only:
// the alt url is cleared, since only the H3 carriers read it, and the pin
// takes no part in a move's dial (the move is planned over the agnostic
// transport alone, which is the Step 1 behaviour, and a pin redials by name).
// The caller's settings are not mutated.
func providerIpv6PinSettings(settings *connect.PlatformTransportSettings) *connect.PlatformTransportSettings {
	copied := *settings
	copied.IpFamily = 6
	copied.StartDisabled = false
	copied.PlatformTransportBudgetPriority = connect.PlatformTransportBudgetPriorityBackground
	copied.AltUrl = ""
	copied.ResidentMoveDial = nil
	return &copied
}

// providerIpv6PinStrategySettings is the strategy settings the pin's direct
// strategy is built from: the provider's own, with the dial the pin will use
// wrapped so each attempt's outcome reaches observe. The wrapped dial is
// exactly the one connect.NewDirectClientStrategy would have kept as its inner
// dial: the injected DialContextSettings when there is one (a proxied
// identity's proxy dial), else the settings' own net dialer. The caller's
// settings are not mutated.
func providerIpv6PinStrategySettings(
	settings *connect.ClientStrategySettings,
	observe func(ctx context.Context, err error),
) *connect.ClientStrategySettings {
	copied := *settings
	var dial connect.DialContextFunction
	var packetConnFactory func(context.Context) (net.PacketConn, error)
	if injected := copied.ConnectSettings.DialContextSettings; injected != nil {
		dial = injected.DialContext
		packetConnFactory = injected.PacketConnFactory
	}
	if dial == nil {
		base := copied.ConnectSettings
		base.DialContextSettings = nil
		dial = base.NetDialer().DialContext
	}
	copied.ConnectSettings.DialContextSettings = &connect.DialContextSettings{
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			conn, err := dial(ctx, network, addr)
			observe(ctx, err)
			return conn, err
		},
		PacketConnFactory: packetConnFactory,
	}
	return &copied
}

// observeIpv6PinDial applies the rule PinnedIpv6DialObserver documents.
func observeIpv6PinDial(
	observer PinnedIpv6DialObserver,
	agnosticConnected func() bool,
	ctx context.Context,
	err error,
) {
	if observer == nil {
		return
	}
	if err == nil {
		observer.PinnedIpv6Dial(true)
		return
	}
	if errors.Is(err, context.Canceled) || (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) {
		// a lost race or a close, not evidence about the path
		return
	}
	if !agnosticConnected() {
		// the proxy may be down for every family; nothing isolates v6
		return
	}
	observer.PinnedIpv6Dial(false)
}

// newProviderIpv6Pin builds the pin for one generation: a direct strategy
// pinned to v6 (connect.NewDirectClientStrategy keeps the injected proxy dial
// and drops extenders and VLESS) and an H1-only transport on the v6 url,
// sharing the generation's route manager and, through settings, its client
// limit hold. Nil when the space has no v6 url.
func (self *deviceLocalProvider) newProviderIpv6Pin(
	plain *providerPlainTransport,
	auth *connect.ClientAuth,
	settings *connect.PlatformTransportSettings,
	clientStrategySettings *connect.ClientStrategySettings,
) *providerIpv6Pin {
	if self.pinnedIpv6PlatformUrl == "" {
		return nil
	}
	if clientStrategySettings == nil {
		clientStrategySettings = connect.DefaultClientStrategySettings()
	}
	strategySettings := providerIpv6PinStrategySettings(
		clientStrategySettings,
		func(ctx context.Context, err error) {
			observeIpv6PinDial(self.pinnedIpv6Observer(), plain.agnostic.IsConnected, ctx, err)
		},
	)
	strategy := connect.NewDirectClientStrategy(self.client.Ctx(), strategySettings, 6)
	transport := connect.NewPlatformTransportWithTargetMode(
		self.client.Ctx(),
		strategy,
		self.client.RouteManager(),
		self.pinnedIpv6PlatformUrl,
		auth,
		connect.TransportModeH1,
		providerIpv6PinSettings(settings),
	)
	return &providerIpv6Pin{transport: transport, strategy: strategy}
}

func (self *deviceLocalProvider) pinnedIpv6Observer() PinnedIpv6DialObserver {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pinnedIpv6DialObserver
}

// pinnedIpv6WantedWithLock is whether a generation installed now should carry
// the pin. Must be called with stateLock.
func (self *deviceLocalProvider) pinnedIpv6WantedWithLock() bool {
	return self.pinnedIpv6Enabled && self.pinnedIpv6PlatformUrl != ""
}

func (self *deviceLocalProvider) pinnedIpv6Wanted() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pinnedIpv6WantedWithLock()
}

// setPinnedIpv6DialObserver installs the observer every pin's dial reports to,
// including the pins already running. Nil removes it.
func (self *deviceLocalProvider) setPinnedIpv6DialObserver(observer PinnedIpv6DialObserver) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pinnedIpv6DialObserver = observer
}

// setPinnedIpv6Enabled records the wanted state and brings the current
// generation in line before returning. It is a no-op for a provider that runs
// the family group, which has its own v6 pin. It is joined by the provider's
// close like a migration.
func (self *deviceLocalProvider) setPinnedIpv6Enabled(enabled bool) {
	self.stateLock.Lock()
	if self.closed {
		self.stateLock.Unlock()
		return
	}
	self.pinnedIpv6Enabled = enabled
	self.migrationWorkers.Add(1)
	self.stateLock.Unlock()
	defer self.migrationWorkers.Done()
	self.reconcilePinnedIpv6()
}

// pinnedIpv6Correction is what an install found wrong with the generation it
// installed, applied once stateLock is released: a pin to close, or a pin to
// build.
type pinnedIpv6Correction struct {
	detached  *providerIpv6Pin
	reconcile bool
}

// pinnedIpv6CorrectionWithLock compares the generation being installed with
// the wanted state. A pin that is no longer wanted is detached here, in the
// scope of the swap, so it cannot carry traffic as the current generation's
// pin; a missing pin that is wanted is built after the scope, because a
// strategy is never built under stateLock (see standbyClientStrategy). Must be
// called with stateLock.
func (self *deviceLocalProvider) pinnedIpv6CorrectionWithLock(next migratablePlatformTransport) pinnedIpv6Correction {
	plain, ok := next.(*providerPlainTransport)
	if !ok {
		return pinnedIpv6Correction{}
	}
	hasPin, closed := plain.pinState()
	if closed {
		return pinnedIpv6Correction{}
	}
	wanted := self.pinnedIpv6WantedWithLock()
	switch {
	case hasPin && !wanted:
		return pinnedIpv6Correction{detached: plain.detachPin()}
	case !hasPin && wanted:
		return pinnedIpv6Correction{reconcile: true}
	}
	return pinnedIpv6Correction{}
}

// apply runs outside stateLock.
func (self pinnedIpv6Correction) apply(provider *deviceLocalProvider) {
	if self.detached != nil {
		self.detached.closeAndWait()
	}
	if self.reconcile {
		provider.reconcilePinnedIpv6()
	}
}

// reconcilePinnedIpv6 brings the current generation's pin in line with the
// wanted state. Calls are serialized by pinnedIpv6Lock; each pass reads the
// state afresh, so whichever runs last leaves the generation as wanted then.
// A pin is built with no lock held and attached only if, under stateLock, the
// generation it was built for is still current and the pin still wanted; a
// generation installed meanwhile is corrected by its own install or by the
// next pass of this loop. Every pin it detaches is closed and joined before
// it returns.
func (self *deviceLocalProvider) reconcilePinnedIpv6() {
	self.pinnedIpv6Lock.Lock()
	defer self.pinnedIpv6Lock.Unlock()
	for {
		var plain *providerPlainTransport
		var wanted bool
		var auth *connect.ClientAuth
		var authVersion uint64
		var settings connect.PlatformTransportSettings
		stop := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.closed {
				return true
			}
			var ok bool
			plain, ok = self.platformTransport.(*providerPlainTransport)
			if !ok {
				// the family group carries its own pins; a test seam has none
				return true
			}
			wanted = self.pinnedIpv6WantedWithLock()
			auth = self.auth
			authVersion = self.authVersion
			settings = *connect.DefaultPlatformTransportSettings()
			if self.platformTransportSettings != nil {
				settings = *self.platformTransportSettings
			}
			if self.clientLimitBackoff != nil {
				settings.ClientLimitBackoff = self.clientLimitBackoff
			}
			return false
		}()
		if stop {
			return
		}
		hasPin, closed := plain.pinState()
		if closed || hasPin == wanted {
			// a closed generation is being replaced, and its replacement's
			// install corrects it
			return
		}
		if wanted {
			pin := self.newProviderIpv6Pin(plain, auth, &settings, self.clientStrategySettings)
			if pin == nil {
				return
			}
			attached := func() bool {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				if self.closed || self.platformTransport != plain || !self.pinnedIpv6WantedWithLock() {
					return false
				}
				if self.authVersion != authVersion {
					// a refresh landed while the pin was built
					pin.transport.SetAuth(self.auth)
				}
				return plain.attachPin(pin)
			}()
			if !attached {
				pin.closeAndWait()
			}
			continue
		}
		pin := func() *providerIpv6Pin {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.platformTransport != plain || self.pinnedIpv6WantedWithLock() {
				return nil
			}
			return plain.detachPin()
		}()
		if pin != nil {
			pin.closeAndWait()
		}
	}
}

// SetPinnedIpv6Enabled asks this device's provider to run, or stop running, an
// additional IPv6-pinned platform transport beside its one family-agnostic
// transport, so the platform can record the provider as dual-stack. It only
// acts on a device built with DisablePlatformFamilyTransports: the family
// group of every other device already carries a v6 transport. Default off.
//
// The wanted state survives every rebuild of the provider's transports. When
// it returns, the current generation carries the pin or not as asked; a pin
// it closed has been joined. An embedder calls it only for an identity whose
// egress is known to reach the platform over IPv6, since a pin that cannot
// connect costs its dials and a budget reservation for nothing.
func (self *DeviceLocal) SetPinnedIpv6Enabled(enabled bool) {
	if provider := self.pinnedIpv6Provider(); provider != nil {
		provider.setPinnedIpv6Enabled(enabled)
	}
}

// SetPinnedIpv6DialObserver installs the observer of the v6 pin's dial
// attempts (PinnedIpv6DialObserver). Nil removes it. Install it before
// SetPinnedIpv6Enabled(true) so the first dial is heard.
func (self *DeviceLocal) SetPinnedIpv6DialObserver(observer PinnedIpv6DialObserver) {
	if provider := self.pinnedIpv6Provider(); provider != nil {
		provider.setPinnedIpv6DialObserver(observer)
	}
}

func (self *DeviceLocal) pinnedIpv6Provider() *deviceLocalProvider {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.provider
}
