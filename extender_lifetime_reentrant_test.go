package sdk

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestExtenderLifetimeLoadHookCanReadSnapshot(t *testing.T) {
	var tracker *extenderServeTracker
	var fail atomic.Bool
	fail.Store(true)
	tracker = &extenderServeTracker{loadHook: func() (uint64, error) {
		tracker.snapshot(0)
		if fail.Load() {
			return 0, errors.New("unavailable")
		}
		return 10, nil
	}}
	done := make(chan struct{})
	go func() {
		tracker.initLifetime()
		tracker.snapshot(0)
		fail.Store(false)
		tracker.record(1, time.Now())
		tracker.record(1, time.Now())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reentrant lifetime load blocked")
	}
	if _, lifetime, _, _ := tracker.snapshot(0); lifetime != 12 {
		t.Fatalf("lifetime = %d, want 12", lifetime)
	}
}
