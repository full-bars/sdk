//go:build !ios && !android && !js

package sdk

import (
	"math"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

func TestExtenderServeStatsClampsMobileCounts(t *testing.T) {
	when := time.UnixMilli(123456789)
	tracker := &extenderServeTracker{loaded: true, servedProcess: math.MaxUint64, servedLifetime: math.MaxUint64, lastServed: when}
	role := &deviceLocalExtender{serveTracker: tracker, statusMonitor: connect.NewMonitorValue(extenderProvideState{})}
	check := func(name string, stats ExtenderServeStats) {
		t.Helper()
		if stats.ServedProcess != math.MaxInt64 || stats.ServedLifetime != math.MaxInt64 || stats.LastServed != when.UnixMilli() {
			t.Fatalf("%s: stats = %+v", name, stats)
		}
	}
	check("no server", role.serveStats())
	fixture := newTestProvideExtenderFixture(t, nil)
	fixture.waitStatus("listening", func(status *ExtenderProvideStatus) bool { return status.Listening })
	live := fixture.extender()
	live.serveTracker.lock.Lock()
	live.serveTracker.servedProcess = math.MaxUint64
	live.serveTracker.servedLifetime = math.MaxUint64
	live.serveTracker.lastServed = when
	live.serveTracker.lock.Unlock()
	check("live server", live.serveStats())
	status := (extenderProvideState{ServedProcess: math.MaxUint64, ServedLifetime: math.MaxUint64, LastServed: when}).status(0)
	if status.ServedProcess != math.MaxInt64 || status.ServedLifetime != math.MaxInt64 || status.LastServed != when.UnixMilli() {
		t.Fatalf("status = %+v", status)
	}
	zero := (extenderProvideState{}).status(0)
	if zero.LastServed != 0 {
		t.Fatalf("zero time = %d", zero.LastServed)
	}
}
