package sdk

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// The served counters and the last-served time reach the mobile API as the
// bindable types the other status fields use: gomobile has no unsigned type
// and no time.Time, so the counters are int64 and the time is unix
// milliseconds.
func TestExtenderServedFieldsAreBindable(t *testing.T) {
	bindableKinds := map[reflect.Kind]bool{
		reflect.Bool:    true,
		reflect.Int:     true,
		reflect.Int32:   true,
		reflect.Int64:   true,
		reflect.Float32: true,
		reflect.Float64: true,
		reflect.String:  true,
	}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(ExtenderProvideStatus{}),
		reflect.TypeOf(ExtenderServeStats{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if !bindableKinds[field.Type.Kind()] {
				t.Errorf("%s.%s is %s, which gomobile does not bind", typ.Name(), field.Name, field.Type)
			}
			switch field.Name {
			case "ServedProcess", "ServedLifetime", "LastServed":
				if field.Type.Kind() != reflect.Int64 {
					t.Errorf("%s.%s is %s, expected int64", typ.Name(), field.Name, field.Type)
				}
			}
		}
	}
}

// A session that is accepted reaches the status without another event: the
// role loop is woken by the session, not only by whatever else changes next.
// The status reports the session with the accept time in unix milliseconds.
func TestExtenderProvideStatusReportsServedSession(t *testing.T) {
	endpointAddr := startServedSessionEndpoint(t)
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

	// the fixture clock does not move unless a test advances it, so the accept
	// time is exact
	acceptedMs := fixture.clock.Now().UnixMilli()
	conn := dialServedSession(t, fixture)
	defer conn.Close()

	// bounded well under the fixture's 60s wait: a status that only follows the
	// next unrelated event is what this test must catch
	deadline := time.After(10 * time.Second)
	for {
		select {
		case status := <-fixture.statuses:
			if status.ServedProcess == 1 && status.ServedLifetime == 1 && status.LastServed == acceptedMs {
				return
			}
		case <-deadline:
			t.Fatalf("the session was not in the status within 10s, last = %+v", fixture.device.GetExtenderProvideStatus())
		}
	}
}

// A local endpoint that accepts every client and reads what it sends, for the
// extender to relay a served session to.
func startServedSessionEndpoint(t *testing.T) string {
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
	return listener.Addr().String()
}

// One client session dialed through the fixture's extender.
func dialServedSession(t *testing.T, fixture *testProvideExtenderFixture) net.Conn {
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
