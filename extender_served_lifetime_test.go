package sdk

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A failed load leaves the store alone. Nothing is saved over the persisted
// count while the load fails, and once it succeeds the sessions counted in the
// meantime are added to the count the store holds.
func TestExtenderServeTrackerFailedLoadDoesNotOverwrite(t *testing.T) {
	var failLoad atomic.Bool
	failLoad.Store(true)
	load := func() (uint64, error) {
		if failLoad.Load() {
			return 0, errors.New("store unreadable")
		}
		return 100, nil
	}
	var savedLock sync.Mutex
	var saved []uint64
	save := func(lifetime uint64) error {
		savedLock.Lock()
		defer savedLock.Unlock()
		saved = append(saved, lifetime)
		return nil
	}
	tracker := newExtenderServeTracker(nil, load, save)

	tracker.record(1, time.Now())
	tracker.record(1, time.Now())
	savedLock.Lock()
	if len(saved) != 0 {
		savedLock.Unlock()
		t.Fatalf("saved %v while the store could not be read", saved)
	}
	savedLock.Unlock()

	failLoad.Store(false)
	tracker.record(1, time.Now())
	savedLock.Lock()
	defer savedLock.Unlock()
	// the store held 100, the two sessions counted while it was unreadable
	// add to it, and this session is the last one
	if len(saved) != 1 || saved[0] != 103 {
		t.Fatalf("expected one save of 103 after the load succeeded, got %v", saved)
	}
}

// Two saves that overlap land in count order. The first save stalls with count
// 1 while a second session raises the count to 2. The second save must be
// the last write, so the store ends on 2 and not on the stalled 1.
func TestExtenderServeTrackerSavesDoNotRegress(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	var savedLock sync.Mutex
	var saved []uint64
	save := func(lifetime uint64) error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		savedLock.Lock()
		defer savedLock.Unlock()
		saved = append(saved, lifetime)
		return nil
	}
	tracker := newExtenderServeTracker(nil, nil, save)

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		tracker.record(1, time.Now())
	}()
	<-entered

	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		tracker.record(1, time.Now())
	}()
	waitServeCondition(t, 5*time.Second, func() bool {
		_, lifetime, _, _ := tracker.snapshot(0)
		return lifetime == 2
	})
	close(release)
	<-firstDone
	<-secondDone

	savedLock.Lock()
	defer savedLock.Unlock()
	if len(saved) != 2 || saved[len(saved)-1] != 2 {
		t.Fatalf("expected the last save to be the count 2, saves were %v", saved)
	}
}

// The count is replaced by renaming a staged file over it, not by writing the
// file in place: an in-place write truncates first, so a crash between the two
// steps reads back as zero. The file is never left behind.
func TestExtenderServedLifetimeWriteReplacesFile(t *testing.T) {
	localState := newLocalState(context.Background(), t.TempDir())
	t.Cleanup(localState.Close)
	if err := localState.SetExtenderServedLifetime(7); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(localState.localStorageDir, extenderServedLifetimeFileName)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := localState.SetExtenderServedLifetime(8); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("the count was written in place, not replaced")
	}
	if got := localState.GetExtenderServedLifetime(); got != 8 {
		t.Fatalf("expected the count 8 to read back, got %d", got)
	}

	entries, err := os.ReadDir(localState.localStorageDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), extenderServedLifetimeFileName+".tmp-") {
			t.Fatalf("staged file left behind: %s", entry.Name())
		}
	}
}

// A write that cannot stage its file fails and keeps the count it had. The
// directory is made read-only so the staged file cannot be created; the file
// itself stays writable, which an in-place write would use.
func TestExtenderServedLifetimeFailedWriteKeepsCount(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	localState := newLocalState(context.Background(), t.TempDir())
	t.Cleanup(localState.Close)
	if err := localState.SetExtenderServedLifetime(7); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(localState.localStorageDir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(localState.localStorageDir, LocalStorageDirectoryPermissions)
	})
	if err := localState.SetExtenderServedLifetime(8); err == nil {
		t.Fatal("expected the write to fail in a read-only directory")
	}
	if got := localState.GetExtenderServedLifetime(); got != 7 {
		t.Fatalf("expected the count 7 to survive the failed write, got %d", got)
	}
}
