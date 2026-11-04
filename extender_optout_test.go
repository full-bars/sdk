//go:build !js

package sdk

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/gossip"
)

func TestExtenderNetworkOptedOut(t *testing.T) {
	if extenderNetworkOptedOut(nil) {
		t.Fatal("nil settings opted out")
	}
	settings := connect.DefaultClientStrategySettings()
	if extenderNetworkOptedOut(settings) {
		t.Fatal("default settings opted out")
	}
	settings.DisableExtenderNetwork = true
	if !extenderNetworkOptedOut(settings) {
		t.Fatal("DisableExtenderNetwork did not opt out")
	}
}

// A space on a real dns name would normally build both; the opt-out is the
// only thing that makes the client and the node come back nil here.
func TestExtenderOptOutBuildsNoClientNoNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key := NewNetworkSpaceKey("space.example", "main")
	values := &NetworkSpaceValues{}
	if !extenderNetworkClientRuns(key, values) {
		t.Fatal("test space must be one that runs an extender network client")
	}

	settings := connect.DefaultClientStrategySettings()
	settings.DisableExtenderNetwork = true
	directory := newSpaceExtenderDirectory(ctx, key, values, nil, settings.Log)

	client := newSpaceExtenderNetworkClient(
		ctx,
		key,
		values,
		ExtenderRoleFeed,
		nil,
		settings,
		directory,
		"https://api.space.example",
		settings.Log,
	)
	if client != nil {
		t.Fatal("opted-out space built an extender network client")
	}

	node := newSpaceExtenderNodeWithRole(
		ctx,
		key,
		values,
		gossip.NodeRoleMember,
		nil,
		nil,
		directory,
		nil,
		nil,
		settings,
		settings.Log,
	)
	if node != nil {
		t.Fatal("opted-out space built a gossip node")
	}
}

// The functions that create the per-space extender goroutines: the directory's
// run loop, the status watch, the release fetcher, the block reporter's two,
// the camouflage reporter and the seed bootstrap.
var extenderGoroutineCreators = map[string]int{
	"connect.NewExtenderDirectory":                 1,
	"sdk.(*NetworkSpace).startExtenderStatusWatch": 1,
	"sdk.newExtenderReleaseFetcher":                1,
	"sdk.(*extenderBlockReporter).start":           2,
	"connect.NewExtenderCamouflageReporter":        1,
	"sdk.newSpaceExtenderSeed":                     1,
}

// Counts the live goroutines created by each of extenderGoroutineCreators.
func countExtenderGoroutines() map[string]int {
	buf := make([]byte, 1<<22)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	counts := map[string]int{}
	for _, line := range strings.Split(string(buf), "\n") {
		rest, ok := strings.CutPrefix(line, "created by github.com/urnetwork/")
		if !ok {
			continue
		}
		creator, _, _ := strings.Cut(rest, " in goroutine")
		if _, ok := extenderGoroutineCreators[creator]; ok {
			counts[creator] += 1
		}
	}
	return counts
}

// Builds one url space on a real dns name and reports the extender goroutines
// it added to the process, and how many times each extender seam was entered.
func buildOptOutProbeSpace(t *testing.T, optOut bool, name string) (*NetworkSpace, map[string]int, map[string]int) {
	t.Helper()
	seams := map[string]int{}
	var seamLock sync.Mutex
	count := func(seam string) {
		seamLock.Lock()
		defer seamLock.Unlock()
		seams[seam] += 1
	}
	apiUrl := "https://api." + name + ".example"

	hook := func(networkSpace *NetworkSpace) {
		if networkSpace.apiUrl == apiUrl || networkSpace.values.ApiUrl == apiUrl {
			count("statusWatch")
		}
	}
	testingBeforeExtenderStatusWatch.Store(&hook)
	previousRelease := extenderReleaseConfigure
	extenderReleaseConfigure = func(settings *extenderReleaseSettings) { count("release") }
	previousSeed := extenderSeedSettingsConfigure
	extenderSeedSettingsConfigure = func(settings *extenderSeedSettings) { count("seed") }
	previousCamouflage := extenderCamouflageReportConfigure
	extenderCamouflageReportConfigure = func(settings *connect.ExtenderCamouflageReporterSettings) { count("camouflage") }
	t.Cleanup(func() {
		testingBeforeExtenderStatusWatch.Store(nil)
		extenderReleaseConfigure = previousRelease
		extenderSeedSettingsConfigure = previousSeed
		extenderCamouflageReportConfigure = previousCamouflage
	})

	before := countExtenderGoroutines()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	strategySettings := testOfflineClientStrategySettings()
	strategySettings.Log = connect.NewNoopLogger()
	strategySettings.DisableExtenderNetwork = optOut
	networkSpace := NewNetworkSpaceWithUrls(ctx, apiUrl, "wss://connect."+name+".example", strategySettings)
	t.Cleanup(networkSpace.Close)

	// a goroutine is listed from its `go` statement on, so the constructor's
	// own are all counted by the time it returns
	added := map[string]int{}
	after := countExtenderGoroutines()
	for creator := range extenderGoroutineCreators {
		added[creator] = after[creator] - before[creator]
	}
	seamLock.Lock()
	defer seamLock.Unlock()
	return networkSpace, added, maps.Clone(seams)
}

func TestExtenderOptOutSpaceBuildsNoDirectoryAndStartsNoGoroutine(t *testing.T) {
	networkSpace, added, seams := buildOptOutProbeSpace(t, true, "optout-none")

	if networkSpace.extenderDirectory != nil {
		t.Fatal("opted-out space built an extender directory")
	}
	if networkSpace.clientStrategySettings.ExtenderDirectory != nil {
		t.Fatal("opted-out space installed an extender directory in its strategy")
	}
	if networkSpace.extenderNetworkClient != nil || networkSpace.getExtenderNode() != nil {
		t.Fatal("opted-out space built a network client or a node")
	}
	for creator, count := range added {
		if count != 0 {
			t.Fatalf("opted-out space started %d goroutine(s) from %s", count, creator)
		}
	}
	for seam, count := range seams {
		if count != 0 {
			t.Fatalf("opted-out space entered the %s seam %d time(s)", seam, count)
		}
	}
	if networkSpace.extenderRelease.fetcher.Load() != nil ||
		networkSpace.extenderCamouflageReport.reporter.Load() != nil ||
		networkSpace.getExtenderSeed() != nil {
		t.Fatal("opted-out space holds a release fetcher, camouflage reporter or seed bootstrap")
	}
}

// The direct slot, the one without the flag, keeps every piece of the extender
// machinery: the regression that would cost the fleet its extender capability.
func TestExtenderOptOutAbsentKeepsDirectoryAndEveryGoroutine(t *testing.T) {
	networkSpace, added, seams := buildOptOutProbeSpace(t, false, "optout-direct")

	if networkSpace.extenderDirectory == nil {
		t.Fatal("space without the flag built no extender directory")
	}
	if networkSpace.clientStrategySettings.ExtenderDirectory != networkSpace.extenderDirectory {
		t.Fatal("space without the flag did not install its directory in its strategy")
	}
	for creator, want := range extenderGoroutineCreators {
		if added[creator] != want {
			t.Fatalf("space without the flag started %d goroutine(s) from %s, want %d", added[creator], creator, want)
		}
	}
	for _, seam := range []string{"statusWatch", "release", "seed", "camouflage"} {
		if seams[seam] != 1 {
			t.Fatalf("space without the flag entered the %s seam %d time(s), want 1", seam, seams[seam])
		}
	}
}

// An opted-out space still serves: its api and strategy work against a local
// server, and tearing it down with a nil directory neither panics nor hangs.
func TestExtenderOptOutSpaceServesAndClosesWithoutDirectory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	strategySettings := connect.DefaultClientStrategySettings()
	strategySettings.Log = connect.NewNoopLogger()
	strategySettings.DisableExtenderNetwork = true
	networkSpace := NewNetworkSpaceWithUrls(ctx, server.URL, "ws://127.0.0.1:1", strategySettings)
	if networkSpace.extenderDirectory != nil {
		t.Fatal("opted-out space built an extender directory")
	}

	// the strategy dials without a directory
	body, err := connect.HttpGetWithStrategyRaw(ctx, networkSpace.clientStrategy, server.URL, "")
	if err != nil {
		t.Fatalf("opted-out space could not reach a local server: %s", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("opted-out space read %q", body)
	}

	// a device on the space, whose extender role cannot start without a
	// directory, builds and closes like any other
	settings := testExtenderStatusDeviceSettings()
	settings.DefaultProvideExtender = true
	deviceLocal, err := newDeviceLocalWithOverrides(
		networkSpace, "", "", "", "", NewId(), settings, connect.NewId(),
	)
	if err != nil {
		t.Fatalf("opted-out space could not host a device: %s", err)
	}
	if deviceLocal.GetNetworkSpace() != networkSpace {
		t.Fatal("the device is on another space")
	}
	deviceLocal.Close()

	// every reader of the directory answers for its absence
	status := networkSpace.GetExtenderStatus()
	if status == nil {
		t.Fatal("opted-out space has no extender status")
	}
	_ = networkSpace.extenderControlReachOrder()
	remove := networkSpace.addExtenderControlReach(nil)
	remove()
	networkSpace.restartExtenderNetwork("")
	networkSpace.restartExtenderNetwork("reset-1")

	done := make(chan struct{})
	go func() {
		defer close(done)
		networkSpace.Close()
		// closing twice is as safe as it is for a space with a directory
		networkSpace.Close()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("closing an opted-out space did not return")
	}
}
