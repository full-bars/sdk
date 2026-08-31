package sdk

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/glog"
)

// restoreTestingLogVerbosity puts the process verbosity back after a test.
// The -v flag is process-global state that init() sets to 0, so a test that
// raises it and leaves it raised turns every later test's log output to noise.
func restoreTestingLogVerbosity(t *testing.T) {
	t.Helper()
	level := GetLogVerbosity()
	t.Cleanup(func() {
		flag.Set("v", strconv.Itoa(level))
	})
}

// TestLogVerbosityTakesEffectAtRuntime pins the claim the whole feature rests
// on: setting the -v flag after init, with no restart and no flag.Parse,
// changes what V() reports on the very next call.
//
// glog registers -v as a flag.Value over its Level type and V() re-reads it
// per call, so this holds -- but it is an implementation detail of the glog
// fork, and if a future glog snapshots the level at parse time instead, the
// sdk's verbosity control silently becomes a no-op with nothing else to catch
// it.
func TestLogVerbosityTakesEffectAtRuntime(t *testing.T) {
	restoreTestingLogVerbosity(t)

	// the logger `connect` actually logs through, resolved the same way its
	// components resolve it, so this covers the real path and not just
	// glog.V's own bookkeeping
	log := connect.NewGlogLogger()

	for _, testCase := range []struct {
		level  int
		wantV1 bool
		wantV2 bool
	}{
		{LogVerbosityDefault, false, false},
		{LogVerbosityTrace, true, false},
		{LogVerbosityDetail, true, true},
		// and back down again: raising verbosity for a repro must be
		// reversible in the same process
		{LogVerbosityDefault, false, false},
	} {
		if err := SetLogVerbosity(testCase.level); err != nil {
			t.Fatalf("SetLogVerbosity(%d) = %v, want nil", testCase.level, err)
		}

		connect.AssertEqual(t, GetLogVerbosity(), testCase.level)
		connect.AssertEqual(t, bool(glog.V(glog.Level(1))), testCase.wantV1)
		connect.AssertEqual(t, bool(glog.V(glog.Level(2))), testCase.wantV2)
		connect.AssertEqual(t, log.V(1).Enabled(), testCase.wantV1)
		connect.AssertEqual(t, log.V(2).Enabled(), testCase.wantV2)
	}
}

// TestLogVerbosityClampsOutOfRange: a level outside 0..2 is clamped, not
// rejected. `connect` only gates on V(1) and V(2), so a 7 would be an
// unbounded promise the sdk cannot keep, and a negative level is nonsense --
// but neither is worth failing a support workflow over.
func TestLogVerbosityClampsOutOfRange(t *testing.T) {
	restoreTestingLogVerbosity(t)

	if err := SetLogVerbosity(7); err != nil {
		t.Fatalf("SetLogVerbosity(7) = %v, want nil", err)
	}
	connect.AssertEqual(t, GetLogVerbosity(), LogVerbosityDetail)
	// clamped, not merely reported as clamped: V(7) must be off, or the
	// process is logging at a level nothing in `connect` writes at while
	// every V() call site pays for the check
	connect.AssertEqual(t, bool(glog.V(glog.Level(7))), false)
	connect.AssertEqual(t, bool(glog.V(glog.Level(2))), true)

	if err := SetLogVerbosity(-3); err != nil {
		t.Fatalf("SetLogVerbosity(-3) = %v, want nil", err)
	}
	connect.AssertEqual(t, GetLogVerbosity(), LogVerbosityDefault)
	connect.AssertEqual(t, bool(glog.V(glog.Level(1))), false)
}

// TestDeviceLocalSetLogVerbosity: the device-level setter raises the process
// it runs in, which on ios is the network extension -- the process that writes
// the contract and transport lines a bundle is collected for.
func TestDeviceLocalSetLogVerbosity(t *testing.T) {
	restoreTestingLogVerbosity(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	device, _ := testing_newBlockDevice(ctx, t, false)
	defer device.Close()

	connect.AssertEqual(t, device.GetLogVerbosity(), LogVerbosityDefault)

	device.SetLogVerbosity(LogVerbosityDetail)
	connect.AssertEqual(t, device.GetLogVerbosity(), LogVerbosityDetail)
	connect.AssertEqual(t, GetLogVerbosity(), LogVerbosityDetail)
	connect.AssertEqual(t, connect.NewGlogLogger().V(2).Enabled(), true)
}

// A hosted device shares one process with unrelated customers' devices, and
// the verbosity flag is process-global. One tenant raising it would put every
// other tenant's traffic into the host's logs at V(2), which is both a volume
// and a disclosure problem.
func TestDeviceLocalHostedSetLogVerbosityIsIgnored(t *testing.T) {
	restoreTestingLogVerbosity(t)

	if err := SetLogVerbosity(LogVerbosityDefault); err != nil {
		t.Fatalf("SetLogVerbosity: %v", err)
	}

	hosted := &DeviceLocal{
		settings: &DeviceLocalSettings{HostedIncompatible: true},
		log:      connect.NewNoopLogger(),
	}
	hosted.SetLogVerbosity(LogVerbosityDetail)

	connect.AssertEqual(t, GetLogVerbosity(), LogVerbosityDefault)
}

// TestDeviceLogVerbosityBridgeReachesTheDeviceProcess is the reason the rpc
// bridge exists: on ios `connect` runs in the network extension, a separate
// process with its own glog state, so a level set in the app reaches the logs
// that matter only if it crosses the rpc.
//
// The two devices share this test process, so the remote's own process-local
// set would be indistinguishable from a delivered one. This drives the rpc
// method directly, with the process level reset first, so only the crossing
// can explain the result.
func TestDeviceLogVerbosityBridgeReachesTheDeviceProcess(t *testing.T) {
	restoreTestingLogVerbosity(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deviceLocal, deviceRemote := testing_newSyncedDeviceLocalRemote(t, ctx)

	if err := flag.Set("v", strconv.Itoa(LogVerbosityDefault)); err != nil {
		t.Fatalf("flag.Set: %v", err)
	}

	deviceRemote.stateLock.Lock()
	service := deviceRemote.service
	deviceRemote.stateLock.Unlock()
	if service == nil {
		t.Fatal("the remote synced but has no rpc service, so the bridge cannot be exercised")
	}

	err := rpcCallVoidAllowMissingMethod(
		service,
		"DeviceLocalRpc.SetLogVerbosity",
		LogVerbosityDetail,
		func() {},
	)
	connect.AssertEqual(t, err, nil)
	connect.AssertEqual(t, deviceLocal.GetLogVerbosity(), LogVerbosityDetail)
}

// TestLocalStateLogVerbosityRoundTrip: the level survives the process, which
// is the whole point of persisting it -- the bug the user is capturing is
// normally reproduced by reconnecting, and the tunnel process re-runs
// initGlog on the way up.
func TestLocalStateLogVerbosityRoundTrip(t *testing.T) {
	localState := newLocalState(context.Background(), t.TempDir())

	// unset reads as the level a process starts at anyway
	connect.AssertEqual(t, localState.GetLogVerbosity(), LogVerbosityDefault)

	if err := localState.SetLogVerbosity(LogVerbosityDetail); err != nil {
		t.Fatalf("SetLogVerbosity: %v", err)
	}
	connect.AssertEqual(t, localState.GetLogVerbosity(), LogVerbosityDetail)

	// a level from a future build with a wider range must not read back as a
	// level this build does not honor
	if err := localState.SetLogVerbosity(9); err != nil {
		t.Fatalf("SetLogVerbosity: %v", err)
	}
	connect.AssertEqual(t, localState.GetLogVerbosity(), LogVerbosityDetail)

	// a corrupt file is not a reason to start a process logging at an unknown
	// level
	path := filepath.Join(localState.localStorageDir, ".log_verbosity")
	if err := os.WriteFile(path, []byte("loud"), LocalStorageFilePermissions); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	connect.AssertEqual(t, localState.GetLogVerbosity(), LogVerbosityDefault)
}

// TestDeviceLocalLogVerbosityPersistRestore is the user's actual workflow:
// raise the level, reproduce the bug -- which means reconnecting -- then
// export. The reconnect starts a new tunnel process whose initGlog resets the
// level to 0, so without the restore the session being captured is the one
// session that is not captured.
func TestDeviceLocalLogVerbosityPersistRestore(t *testing.T) {
	restoreTestingLogVerbosity(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	networkSpace, byJwt, err := testing_newNetworkSpace(ctx)
	if err != nil {
		t.Fatalf("network space: %v", err)
	}
	localState := networkSpace.GetAsyncLocalState().GetLocalState()

	device := testing_newBlockDeviceWithNetworkSpace(t, networkSpace, byJwt, false)
	connect.AssertEqual(t, localState.GetLogVerbosity(), LogVerbosityDefault)

	// the set persists asynchronously to local state
	device.SetLogVerbosity(LogVerbosityDetail)
	persisted := false
	for i := 0; i < 100; i += 1 {
		if localState.GetLogVerbosity() == LogVerbosityDetail {
			persisted = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	connect.AssertEqual(t, persisted, true)
	device.Close()

	// stand in for the tunnel restart: a new process runs initGlog, which sets
	// the level back to 0 before any device exists
	if err := flag.Set("v", strconv.Itoa(LogVerbosityDefault)); err != nil {
		t.Fatalf("flag.Set: %v", err)
	}

	restored := testing_newBlockDeviceWithNetworkSpace(t, networkSpace, byJwt, false)
	defer restored.Close()
	connect.AssertEqual(t, restored.GetLogVerbosity(), LogVerbosityDetail)
}

// TestDeviceRemoteSetLogVerbosityPersistsWithTheTunnelDown covers the state
// the user is actually in when they raise the level: disconnected, about to
// connect and reproduce. There is no device process to take the call, so if
// the app does not record it the tunnel it is about to start comes up at 0 and
// captures nothing.
func TestDeviceRemoteSetLogVerbosityPersistsWithTheTunnelDown(t *testing.T) {
	restoreTestingLogVerbosity(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	networkSpace, byJwt, err := testing_newNetworkSpace(ctx)
	if err != nil {
		t.Fatalf("network space: %v", err)
	}
	localState := networkSpace.GetAsyncLocalState().GetLocalState()

	// a level chosen in an earlier session, and an app process that has just
	// restarted: initGlog has reset this process to 0
	if err := localState.SetLogVerbosity(LogVerbosityDetail); err != nil {
		t.Fatalf("SetLogVerbosity: %v", err)
	}
	if err := flag.Set("v", strconv.Itoa(LogVerbosityDefault)); err != nil {
		t.Fatalf("flag.Set: %v", err)
	}

	// nothing is listening on this address, so the remote never has a service:
	// the tunnel is down
	settings := defaultDeviceRpcSettings()
	settings.Address = requireRemoteAddress(testing_freeHostPort())
	deviceRemote, err := newDeviceRemoteWithOverrides(
		networkSpace,
		byJwt,
		NewId(),
		settings,
		connect.NewId(),
		NewWebsocketDeviceRpcDialer(settings.Address, "", "", settings),
	)
	if err != nil {
		t.Fatalf("device remote: %v", err)
	}
	defer deviceRemote.Close()
	connect.AssertEqual(t, deviceRemote.GetRemoteConnected(), false)

	// the remote restores the persisted level into the app process too, so
	// what the app reports is what the extension it is about to start will be
	// logging at, rather than the 0 this process was reset to
	connect.AssertEqual(t, deviceRemote.GetLogVerbosity(), LogVerbosityDetail)

	deviceRemote.SetLogVerbosity(LogVerbosityTrace)

	// the app process is raised immediately, so its own lines match the level
	// the bundle will report
	connect.AssertEqual(t, deviceRemote.GetLogVerbosity(), LogVerbosityTrace)

	persisted := false
	for i := 0; i < 100; i += 1 {
		if localState.GetLogVerbosity() == LogVerbosityTrace {
			persisted = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	connect.AssertEqual(t, persisted, true)
}
