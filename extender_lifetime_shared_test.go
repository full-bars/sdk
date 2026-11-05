package sdk

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestExtenderLifetimeConcurrentTrackersShareSpace(t *testing.T) {
	state := newLocalState(context.Background(), t.TempDir())
	defer state.Close()
	space := &NetworkSpace{asyncLocalState: &AsyncLocalState{localState: state}}
	const trackers = 30
	all := make([]*extenderServeTracker, trackers)
	for i := range all {
		all[i] = newExtenderServeTracker(space, nil, nil)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, tracker := range all {
		wg.Add(1)
		go func(tracker *extenderServeTracker) {
			defer wg.Done()
			<-start
			tracker.record(1, time.Now())
		}(tracker)
	}
	close(start)
	wg.Wait()
	got, err := space.getExtenderServedLifetime()
	if err != nil || got != trackers {
		t.Fatalf("stored lifetime = %d, err = %v; want %d", got, err, trackers)
	}
}
