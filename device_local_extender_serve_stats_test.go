//go:build !ios && !android && !js

package sdk

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// Tests for Deliverables 1, 2, 3: ExtenderServeStats observability,
// session lifecycle counters, peak monotonicity, and lifetime persistence.

func waitServeCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("timed out waiting for condition")
	}
}

// The tracker counts in memory, then saves after its lock is released, so the
// persisted count can trail the in-memory one. Waits for the stored count to
// reach want before it is read.
func waitPersistedLifetime(t *testing.T, networkSpace *NetworkSpace, want uint64) {
	t.Helper()
	waitServeCondition(t, 5*time.Second, func() bool {
		lifetime, err := networkSpace.getExtenderServedLifetime()
		return err == nil && lifetime == want
	})
}

// Requirement: The accessor is zero-valued and non-panicking before the role starts,
// and safe to call on nil or after Close.
func TestExtenderServeStatsAccessorBeforeStartAndAfterClose(t *testing.T) {
	// 1. Nil receiver is non-panicking and returns zero values
	var nilDev *DeviceLocal
	stats := nilDev.ExtenderServeStats()
	if stats != (ExtenderServeStats{}) {
		t.Fatalf("expected zero ExtenderServeStats on nil device, got %+v", stats)
	}

	// 2. Created device before the role starts is non-panicking and zero-valued
	testEnableExtenderProvideRole(t)
	storagePath, err := os.MkdirTemp("", "test_serve_stats_accessor")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(storagePath) })

	spaceManager := NewNetworkSpaceManager(storagePath)
	t.Cleanup(spaceManager.Close)
	space := spaceManager.updateNetworkSpace(
		NewNetworkSpaceKey("space.example", "main"),
		func(values *NetworkSpaceValues) {},
	)

	settings := DefaultDeviceLocalSettings()
	settings.AllowProvider = true
	settings.ProvideExtenderEnabled = true
	settings.DisableLogging = true
	device, err := newDeviceLocalWithOverrides(
		space, "", "", "", "", NewId(), settings, connect.NewId(),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Before role starts (ProvideMode is None by default)
	stats = device.ExtenderServeStats()
	if stats != (ExtenderServeStats{}) {
		t.Fatalf("expected zero ExtenderServeStats before role starts, got %+v", stats)
	}
	if stats.Connected != 0 || stats.ServedProcess != 0 || stats.ServedLifetime != 0 || stats.PeakConnected != 0 {
		t.Fatalf("counters non-zero before role starts: %+v", stats)
	}
	if stats.LastServed != 0 {
		t.Fatalf("LastServed non-zero before role starts: %d", stats.LastServed)
	}
	if stats.Ipv4 != "" || stats.Ipv6 != "" || stats.ActivatedV4 || stats.ActivatedV6 || stats.Listening || stats.Enabled {
		t.Fatalf("posture flags non-zero before role starts: %+v", stats)
	}

	// 3. After Close, safe to call and non-panicking
	_ = device.CloseAndWait(context.Background())
	statsAfterClose := device.ExtenderServeStats()
	if statsAfterClose != (ExtenderServeStats{}) {
		t.Fatalf("expected zero ExtenderServeStats after close, got %+v", statsAfterClose)
	}
}

// Requirement: A served session increments Connected while open and ServedProcess
// and PeakConnected on the way up; Connected returns to zero when it closes.
// Requirement: Peak only grows.
func TestExtenderServeStatsSessionLifecycleAndPeakGrowth(t *testing.T) {
	// Destination endpoint for forward dials
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	endpointAddr := listener.Addr().String()

	fixture := newTestProvideExtenderFixtureWithDevice(
		t,
		func(settings *DeviceLocalSettings) {
			settings.ProviderDialContextSettings = &connect.DialContextSettings{
				DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", endpointAddr)
				},
			}
		},
		nil,
	)

	fixture.waitStatus("listening", func(status *ExtenderProvideStatus) bool {
		return status.Enabled && status.Listening
	})

	// Initial posture: listening and enabled, but no sessions served yet
	initStats := fixture.device.ExtenderServeStats()
	if !initStats.Listening || !initStats.Enabled {
		t.Fatalf("expected listening and enabled, got %+v", initStats)
	}
	if initStats.Connected != 0 || initStats.ServedProcess != 0 || initStats.PeakConnected != 0 {
		t.Fatalf("expected zero initial counters, got %+v", initStats)
	}
	if initStats.LastServed != 0 {
		t.Fatalf("expected zero LastServed, got %d", initStats.LastServed)
	}

	dialClient := func() net.Conn {
		connectSettings := connect.DefaultConnectSettings()
		connectSettings.ConnectTimeout = 10 * time.Second
		connectSettings.TlsTimeout = 10 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		conn, _, err := connect.DialExtender(
			ctx,
			connectSettings,
			&connect.ExtenderConfig{
				Profile: connect.ExtenderProfile{
					ConnectMode: connect.ExtenderConnectModeTcpTls,
					ServerName:  "front.example",
					Port:        fixture.tcpPort,
				},
				Ip:        netip.MustParseAddr("127.0.0.1"),
				PublicKey: fixture.extender().publicKey,
			},
			&connect.ExtenderDial{
				DestinationHost: testProvideExtenderHost,
				DestinationPort: 443,
			},
		)
		if err != nil {
			t.Fatalf("DialExtender error: %v", err)
		}
		return conn
	}

	// Session 1: open
	conn1 := dialClient()
	defer func() {
		if conn1 != nil {
			conn1.Close()
		}
	}()

	waitServeCondition(t, 5*time.Second, func() bool {
		s := fixture.device.ExtenderServeStats()
		return s.Connected == 1 && s.ServedProcess == 1 && s.PeakConnected == 1 && s.LastServed != 0
	})
	s1 := fixture.device.ExtenderServeStats()
	if s1.Connected != 1 {
		t.Fatalf("expected Connected=1, got %d", s1.Connected)
	}
	if s1.ServedProcess != 1 {
		t.Fatalf("expected ServedProcess=1, got %d", s1.ServedProcess)
	}
	if s1.PeakConnected != 1 {
		t.Fatalf("expected PeakConnected=1, got %d", s1.PeakConnected)
	}
	firstServedTime := s1.LastServed

	// Session 2: open concurrently while session 1 is still open
	conn2 := dialClient()
	defer func() {
		if conn2 != nil {
			conn2.Close()
		}
	}()

	waitServeCondition(t, 5*time.Second, func() bool {
		s := fixture.device.ExtenderServeStats()
		return s.Connected == 2 && s.ServedProcess == 2 && s.PeakConnected == 2
	})
	s2 := fixture.device.ExtenderServeStats()
	if s2.Connected != 2 {
		t.Fatalf("expected Connected=2, got %d", s2.Connected)
	}
	if s2.ServedProcess != 2 {
		t.Fatalf("expected ServedProcess=2, got %d", s2.ServedProcess)
	}
	if s2.PeakConnected != 2 {
		t.Fatalf("expected PeakConnected=2, got %d", s2.PeakConnected)
	}
	if s2.LastServed < firstServedTime {
		t.Fatalf("LastServed should update on new session, got %d vs %d", s2.LastServed, firstServedTime)
	}

	// Close Session 1: Connected drops to 1, but PeakConnected MUST REMAIN 2 (peak only grows)
	conn1.Close()
	conn1 = nil
	waitServeCondition(t, 5*time.Second, func() bool {
		s := fixture.device.ExtenderServeStats()
		return s.Connected == 1
	})
	sAfterClose1 := fixture.device.ExtenderServeStats()
	if sAfterClose1.Connected != 1 {
		t.Fatalf("expected Connected=1 after closing session 1, got %d", sAfterClose1.Connected)
	}
	if sAfterClose1.PeakConnected != 2 {
		t.Fatalf("peak should not decrease; expected PeakConnected=2, got %d", sAfterClose1.PeakConnected)
	}
	if sAfterClose1.ServedProcess != 2 {
		t.Fatalf("expected ServedProcess=2, got %d", sAfterClose1.ServedProcess)
	}

	// Close Session 2: Connected returns to 0, PeakConnected MUST REMAIN 2
	conn2.Close()
	conn2 = nil
	waitServeCondition(t, 5*time.Second, func() bool {
		s := fixture.device.ExtenderServeStats()
		return s.Connected == 0
	})
	sAfterClose2 := fixture.device.ExtenderServeStats()
	if sAfterClose2.Connected != 0 {
		t.Fatalf("expected Connected=0 after closing session 2, got %d", sAfterClose2.Connected)
	}
	if sAfterClose2.PeakConnected != 2 {
		t.Fatalf("peak should not decrease; expected PeakConnected=2, got %d", sAfterClose2.PeakConnected)
	}
	if sAfterClose2.ServedProcess != 2 {
		t.Fatalf("expected ServedProcess=2, got %d", sAfterClose2.ServedProcess)
	}

	// Session 3: open another session, Connected goes to 1, ServedProcess to 3, Peak remains 2
	conn3 := dialClient()
	defer func() {
		if conn3 != nil {
			conn3.Close()
		}
	}()

	waitServeCondition(t, 5*time.Second, func() bool {
		s := fixture.device.ExtenderServeStats()
		return s.Connected == 1 && s.ServedProcess == 3
	})
	s3 := fixture.device.ExtenderServeStats()
	if s3.Connected != 1 {
		t.Fatalf("expected Connected=1, got %d", s3.Connected)
	}
	if s3.ServedProcess != 3 {
		t.Fatalf("expected ServedProcess=3, got %d", s3.ServedProcess)
	}
	if s3.PeakConnected != 2 {
		t.Fatalf("peak only grows; expected PeakConnected=2, got %d", s3.PeakConnected)
	}

	// Close Session 3: Connected returns to 0
	conn3.Close()
	conn3 = nil
	waitServeCondition(t, 5*time.Second, func() bool {
		s := fixture.device.ExtenderServeStats()
		return s.Connected == 0
	})
	sFinal := fixture.device.ExtenderServeStats()
	if sFinal.Connected != 0 {
		t.Fatalf("expected Connected=0, got %d", sFinal.Connected)
	}
	if sFinal.PeakConnected != 2 {
		t.Fatalf("expected PeakConnected=2, got %d", sFinal.PeakConnected)
	}
	if sFinal.ServedProcess != 3 {
		t.Fatalf("expected ServedProcess=3, got %d", sFinal.ServedProcess)
	}
}

// Requirement: The lifetime counter is carried through whatever persistence you used.
// Verifies that ServedLifetime survives across device restart using the SDK's existing store
// (.extender_served_lifetime in LocalState / NetworkSpace).
func TestExtenderServeStatsLifetimePersistence(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	endpointAddr := listener.Addr().String()

	fixture := newTestProvideExtenderFixtureWithDevice(
		t,
		func(settings *DeviceLocalSettings) {
			settings.ProviderDialContextSettings = &connect.DialContextSettings{
				DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", endpointAddr)
				},
			}
		},
		nil,
	)

	fixture.waitStatus("listening", func(status *ExtenderProvideStatus) bool {
		return status.Enabled && status.Listening
	})

	dialClient := func(dev *DeviceLocal) net.Conn {
		connectSettings := connect.DefaultConnectSettings()
		connectSettings.ConnectTimeout = 10 * time.Second
		connectSettings.TlsTimeout = 10 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		dev.stateLock.Lock()
		provider := dev.provider
		dev.stateLock.Unlock()
		var pubKey []byte
		if provider != nil {
			provider.stateLock.Lock()
			if provider.extender != nil {
				pubKey = provider.extender.publicKey
			}
			provider.stateLock.Unlock()
		}

		conn, _, err := connect.DialExtender(
			ctx,
			connectSettings,
			&connect.ExtenderConfig{
				Profile: connect.ExtenderProfile{
					ConnectMode: connect.ExtenderConnectModeTcpTls,
					ServerName:  "front.example",
					Port:        fixture.tcpPort,
				},
				Ip:        netip.MustParseAddr("127.0.0.1"),
				PublicKey: pubKey,
			},
			&connect.ExtenderDial{
				DestinationHost: testProvideExtenderHost,
				DestinationPort: 443,
			},
		)
		if err != nil {
			t.Fatalf("DialExtender error: %v", err)
		}
		return conn
	}

	// Serve 1 session on device 1
	conn1 := dialClient(fixture.device)
	waitServeCondition(t, 5*time.Second, func() bool {
		s := fixture.device.ExtenderServeStats()
		return s.ServedProcess == 1 && s.ServedLifetime == 1
	})
	conn1.Close()

	waitServeCondition(t, 5*time.Second, func() bool {
		return fixture.device.ExtenderServeStats().Connected == 0
	})

	// Verify persistence in local state directly
	waitPersistedLifetime(t, fixture.networkSpace, 1)
	persistedLifetime, err := fixture.networkSpace.getExtenderServedLifetime()
	if err != nil {
		t.Fatal(err)
	}
	if persistedLifetime != 1 {
		t.Fatalf("expected persisted lifetime 1, got %d", persistedLifetime)
	}

	// Close device 1
	_ = fixture.device.CloseAndWait(context.Background())

	// Start device 2 using the same networkSpace (same storage directory)
	settings2 := DefaultDeviceLocalSettings()
	settings2.AllowProvider = true
	settings2.Verbose = false
	settings2.DisableLogging = true
	settings2.ProviderDialContextSettings = &connect.DialContextSettings{
		DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", endpointAddr)
		},
	}
	settings2.providerExtenderSettings = func(extenderSettings *deviceLocalExtenderSettings) {
		fixture.configureExtender(extenderSettings)
	}

	device2, err := newDeviceLocalWithOverrides(
		fixture.networkSpace, "", "", "", "", NewId(), settings2, connect.NewId(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = device2.CloseAndWait(context.Background())
	})

	device2.SetProvideMode(ProvideModePublic)

	// Wait for extender to be active/listening
	waitServeCondition(t, 10*time.Second, func() bool {
		s := device2.ExtenderServeStats()
		return s.Listening && s.Enabled
	})

	// Verify device 2 carried the lifetime counter over from persistent store!
	// ServedProcess is 0 (new process), but ServedLifetime is 1!
	s2Init := device2.ExtenderServeStats()
	if s2Init.ServedProcess != 0 {
		t.Fatalf("expected ServedProcess=0 on new device, got %d", s2Init.ServedProcess)
	}
	if s2Init.ServedLifetime != 1 {
		t.Fatalf("expected ServedLifetime carried through persistence to be 1, got %d", s2Init.ServedLifetime)
	}

	// Serve another session on device 2
	conn2 := dialClient(device2)
	waitServeCondition(t, 5*time.Second, func() bool {
		s := device2.ExtenderServeStats()
		return s.ServedProcess == 1 && s.ServedLifetime == 2
	})
	conn2.Close()

	s2Final := device2.ExtenderServeStats()
	if s2Final.ServedProcess != 1 {
		t.Fatalf("expected device 2 ServedProcess=1, got %d", s2Final.ServedProcess)
	}
	if s2Final.ServedLifetime != 2 {
		t.Fatalf("expected device 2 ServedLifetime=2, got %d", s2Final.ServedLifetime)
	}

	// Check persisted store again
	waitPersistedLifetime(t, fixture.networkSpace, 2)
	postPersisted, err := fixture.networkSpace.getExtenderServedLifetime()
	if err != nil {
		t.Fatal(err)
	}
	if postPersisted != 2 {
		t.Fatalf("expected persisted lifetime 2, got %d", postPersisted)
	}
}

// Requirement: The lifetime counter hook is documented with a test showing it is called.
func TestExtenderServeStatsLifetimeHook(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	endpointAddr := listener.Addr().String()

	var loadCalled atomic.Bool
	var lastSaved atomic.Uint64
	const initialLifetime uint64 = 100

	fixture := newTestProvideExtenderFixtureWithDevice(
		t,
		func(settings *DeviceLocalSettings) {
			settings.ExtenderLoadServedLifetime = func() (uint64, error) {
				loadCalled.Store(true)
				return initialLifetime, nil
			}
			settings.ExtenderSaveServedLifetime = func(lifetime uint64) error {
				lastSaved.Store(lifetime)
				return nil
			}
			settings.ProviderDialContextSettings = &connect.DialContextSettings{
				DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", endpointAddr)
				},
			}
		},
		nil,
	)

	fixture.waitStatus("listening", func(status *ExtenderProvideStatus) bool {
		return status.Enabled && status.Listening
	})

	if !loadCalled.Load() {
		t.Fatal("expected ExtenderLoadServedLifetime hook to be called on initialization")
	}

	initStats := fixture.device.ExtenderServeStats()
	if initStats.ServedLifetime != int64(initialLifetime) {
		t.Fatalf("expected ServedLifetime initialized from hook to be %d, got %d", initialLifetime, initStats.ServedLifetime)
	}

	// Dial client session
	connectSettings := connect.DefaultConnectSettings()
	connectSettings.ConnectTimeout = 10 * time.Second
	connectSettings.TlsTimeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, _, err := connect.DialExtender(
		ctx,
		connectSettings,
		&connect.ExtenderConfig{
			Profile: connect.ExtenderProfile{
				ConnectMode: connect.ExtenderConnectModeTcpTls,
				ServerName:  "front.example",
				Port:        fixture.tcpPort,
			},
			Ip:        netip.MustParseAddr("127.0.0.1"),
			PublicKey: fixture.extender().publicKey,
		},
		&connect.ExtenderDial{
			DestinationHost: testProvideExtenderHost,
			DestinationPort: 443,
		},
	)
	if err != nil {
		t.Fatalf("DialExtender error: %v", err)
	}
	defer conn.Close()

	waitServeCondition(t, 5*time.Second, func() bool {
		return lastSaved.Load() == initialLifetime+1
	})

	stats := fixture.device.ExtenderServeStats()
	if stats.ServedProcess != 1 {
		t.Fatalf("expected ServedProcess=1, got %d", stats.ServedProcess)
	}
	if stats.ServedLifetime != int64(initialLifetime+1) {
		t.Fatalf("expected ServedLifetime=%d, got %d", initialLifetime+1, stats.ServedLifetime)
	}
	if lastSaved.Load() != initialLifetime+1 {
		t.Fatalf("expected ExtenderSaveServedLifetime hook called with %d, got %d", initialLifetime+1, lastSaved.Load())
	}
}

// An extender whose server has not started or is nil answers false for
// tcpCarrierServing and does not panic when its state is read.
func TestExtenderStateWhenServerNilDoesNotPanic(t *testing.T) {
	extender := &deviceLocalExtender{}
	if extender.tcpCarrierServing() {
		t.Fatal("expected tcpCarrierServing=false when server is nil")
	}
	state := extender.state()
	if state.Listening {
		t.Fatal("expected Listening=false when server is nil")
	}
}

