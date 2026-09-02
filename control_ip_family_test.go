package sdk

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

func TestControlIpFamilyPolicyRoundTrips(t *testing.T) {
	defer SetControlIpFamilyPolicy(IpFamilyPolicyAuto)
	tests := []struct {
		name string
		set  int
		want int
	}{
		{"auto", IpFamilyPolicyAuto, IpFamilyPolicyAuto},
		{"force4", IpFamilyPolicyForce4, IpFamilyPolicyForce4},
		{"force6", IpFamilyPolicyForce6, IpFamilyPolicyForce6},
		{"above range clamps to auto", 7, IpFamilyPolicyAuto},
		{"below range clamps to auto", -1, IpFamilyPolicyAuto},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SetControlIpFamilyPolicy(test.set)
			if got := GetControlIpFamilyPolicy(); got != test.want {
				t.Fatalf("got %d, want %d", got, test.want)
			}
		})
	}
}

// TestClampIpFamilyPolicy exercises the sdk layer's own clampIpFamilyPolicy
// directly, independent of connect.SetControlIpFamilyPolicy's own fallback to
// Auto for an unrecognized value. TestControlIpFamilyPolicyRoundTrips above
// cannot distinguish sdk.go's clamp from connect's: both converge on the same
// Auto result for an out-of-range input, so that round trip would still pass
// even if clampIpFamilyPolicy were skipped entirely. Calling the unexported
// function in this same-package test is the only way to pin the sdk-layer
// clamp's own return value in isolation.
func TestClampIpFamilyPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy int
		want   int
	}{
		{"auto", IpFamilyPolicyAuto, IpFamilyPolicyAuto},
		{"force4", IpFamilyPolicyForce4, IpFamilyPolicyForce4},
		{"force6", IpFamilyPolicyForce6, IpFamilyPolicyForce6},
		{"above range clamps to auto", 7, IpFamilyPolicyAuto},
		{"below range clamps to auto", -1, IpFamilyPolicyAuto},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := clampIpFamilyPolicy(test.policy); got != test.want {
				t.Fatalf("got %d, want %d", got, test.want)
			}
		})
	}
}

// THE departure from the log-verbosity template, and the reason for it.
//
// A user who forces IPv4, kills the app and relaunches hits the LOGIN api call
// before any Device exists. That is precisely the call they are stuck on. The
// log verbosity is restored from the two Device constructors, which would
// leave this setting inert during the one request that matters -- while the
// developer menu read back the correct value the whole time.
func TestPolicyIsInForceAfterNetworkSpaceConstructionWithNoDevice(t *testing.T) {
	defer SetControlIpFamilyPolicy(IpFamilyPolicyAuto)
	SetControlIpFamilyPolicy(IpFamilyPolicyAuto)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	storagePath := t.TempDir()
	localState := newLocalState(ctx, storagePath)
	if err := localState.SetControlIpFamilyPolicy(IpFamilyPolicyForce4); err != nil {
		t.Fatal(err)
	}

	networkSpace := newNetworkSpace(
		ctx,
		*NewNetworkSpaceKey("example.test", "main"),
		NetworkSpaceValues{
			NetExposeServerIps:       true,
			NetExposeServerHostNames: true,
		},
		storagePath,
	)
	defer networkSpace.close()
	defer networkSpace.asyncLocalState.Close()

	if got := GetControlIpFamilyPolicy(); got != IpFamilyPolicyForce4 {
		t.Fatalf("policy is %d after constructing a network space, want force4 -- "+
			"the restore did not happen before the first api call could be made", got)
	}
}

func TestNetworkSpaceSetControlIpFamilyPolicyPersists(t *testing.T) {
	defer SetControlIpFamilyPolicy(IpFamilyPolicyAuto)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	storagePath := t.TempDir()
	networkSpace := newNetworkSpace(
		ctx,
		*NewNetworkSpaceKey("example.test", "main"),
		NetworkSpaceValues{
			NetExposeServerIps:       true,
			NetExposeServerHostNames: true,
		},
		storagePath,
	)
	defer networkSpace.close()
	defer networkSpace.asyncLocalState.Close()

	networkSpace.SetControlIpFamilyPolicy(IpFamilyPolicyForce6)
	// the PROCESS is set synchronously -- that half is not deferred
	if got := GetControlIpFamilyPolicy(); got != IpFamilyPolicyForce6 {
		t.Fatalf("process policy is %d, want force6", got)
	}

	// the FILE is not. NetworkSpace.SetControlIpFamilyPolicy hands the write to
	// asyncLocalState.serialAsync, which runs it on a worker goroutine, so
	// reading the file on the next line races the write and fails most of the
	// time. Poll, bounded -- the same shape as log_verbosity_test.go:556-565.
	localState := newLocalState(ctx, storagePath)
	persisted := false
	for i := 0; i < 100; i += 1 {
		if got, ok := localState.controlIpFamilyPolicyIfSet(); ok && got == IpFamilyPolicyForce6 {
			persisted = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !persisted {
		t.Fatal("force6 was never persisted, so a relaunch comes back up under auto")
	}
}

func TestUnsetPolicyDoesNotOverrideTheProcessValue(t *testing.T) {
	defer SetControlIpFamilyPolicy(IpFamilyPolicyAuto)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	localState := newLocalState(ctx, t.TempDir())
	if _, ok := localState.controlIpFamilyPolicyIfSet(); ok {
		t.Fatal("a fresh local state reports a policy it was never given")
	}
	SetControlIpFamilyPolicy(IpFamilyPolicyForce4)
	if _, applied := applyPersistedControlIpFamilyPolicy(localState, nil); applied {
		t.Fatal("an unset policy must not be applied")
	}
	if got := GetControlIpFamilyPolicy(); got != IpFamilyPolicyForce4 {
		t.Fatalf("policy is %d, want the process value left alone", got)
	}
}

// newTestDeviceRemoteWithNoService builds a DeviceRemote whose rpc address has
// nothing listening on it: the ios regime where the app process is up and the
// tunnel process is down. It composes the same pieces the log verbosity tests
// construct inline -- testing_newNetworkSpace, defaultDeviceRpcSettings moved
// onto a free port (never the fixed production default, which collides with a
// concurrent suite run), and testing_deviceRpcDialer -- and ties the context
// and the device to t.
func newTestDeviceRemoteWithNoService(t *testing.T) *DeviceRemote {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	networkSpace, byJwt, err := testing_newNetworkSpace(ctx)
	if err != nil {
		t.Fatalf("network space: %v", err)
	}
	return newTestDeviceRemoteWithNoServiceInSpace(t, networkSpace, byJwt)
}

// newTestDeviceRemoteWithNoServiceInSpace is newTestDeviceRemoteWithNoService
// over a caller-supplied space, for the tests that have to seed that space's
// local state before the device remote is constructed.
func newTestDeviceRemoteWithNoServiceInSpace(t *testing.T, networkSpace *NetworkSpace, byJwt string) *DeviceRemote {
	t.Helper()

	settings := defaultDeviceRpcSettings()
	settings.Address = requireRemoteAddress(testing_freeHostPort())

	deviceRemote, err := newDeviceRemoteWithOverrides(
		networkSpace,
		byJwt,
		NewId(),
		settings,
		connect.NewId(),
		testing_deviceRpcDialer(settings),
	)
	if err != nil {
		t.Fatalf("device remote: %v", err)
	}
	t.Cleanup(deviceRemote.Close)

	if deviceRemote.GetRemoteConnected() {
		t.Fatal("the test device remote found a service, so the tunnel-down path is not the one under test")
	}
	return deviceRemote
}

// Both Device implementations are compile-time asserted, so a missing method
// is a build failure -- but the QUEUE behavior is not, and it is what covers
// the ios regime where the tunnel is down. A policy set with no rpc service
// must be replayed to the device when one appears, or the extension keeps
// dialing under the old policy while the menu reads back the new one.
func TestDeviceRemoteQueuesThePolicyWhenTheTunnelIsDown(t *testing.T) {
	defer SetControlIpFamilyPolicy(IpFamilyPolicyAuto)
	deviceRemote := newTestDeviceRemoteWithNoService(t)

	deviceRemote.SetControlIpFamilyPolicy(IpFamilyPolicyForce4)

	if got := GetControlIpFamilyPolicy(); got != IpFamilyPolicyForce4 {
		t.Fatalf("this process is at %d, want force4 -- the app process dials while the tunnel is down", got)
	}
	// FIELDS, not methods. deviceRemoteValue[T] (device_rpc.go:5806) is
	//   struct { Value T; IsSet bool }
	// with exactly one accessor, Get(defaultValue T) T -- so `.IsSet()` does
	// not compile and `.Get()` is missing its argument. Read under stateLock,
	// copying the pattern at log_verbosity_test.go:303-307 (and :243).
	deviceRemote.stateLock.Lock()
	queued := deviceRemote.state.ControlIpFamilyPolicy
	deviceRemote.stateLock.Unlock()
	if !queued.IsSet {
		t.Fatal("the policy was not queued for replay")
	}
	if queued.Value != IpFamilyPolicyForce4 {
		t.Fatalf("queued %d, want force4", queued.Value)
	}
}

// TestDeviceRemoteControlIpFamilyPolicyCrossesToTheDeviceProcess is the test
// the queue test above cannot be: the rpc handler's argument shape is a
// RUNTIME contract, not a compile-time one. RpcVoid is already `*any`
// (device_rpc.go:7556), so a handler written `_ *RpcVoid` builds cleanly, is
// registered by net/rpc, and simply fails every call -- and the tunnel-down
// test still passes, because it never reaches a live service at all.
//
// This drives DeviceRemote.SetControlIpFamilyPolicy over a LIVE rpc, the call
// the app actually makes, and looks for the policy in the DEVICE's own
// storage. The two devices share this test process, so the process-global
// policy proves nothing; they do NOT share a network space, so a policy in the
// device's file can only have come across the rpc.
func TestDeviceRemoteControlIpFamilyPolicyCrossesToTheDeviceProcess(t *testing.T) {
	defer SetControlIpFamilyPolicy(IpFamilyPolicyAuto)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, deviceRemote, localSpaceState, _ := testing_newSyncedDeviceLocalRemoteSeparateSpaces(t, ctx)

	deviceRemote.SetControlIpFamilyPolicy(IpFamilyPolicyForce6)

	// delivered now, over the live connection, not left for a later sync
	deviceRemote.stateLock.Lock()
	pending := deviceRemote.state.ControlIpFamilyPolicy.IsSet
	deviceRemote.stateLock.Unlock()
	if pending {
		t.Fatal("the policy is queued for a later sync, so the connected device never took the call")
	}

	if !awaitPersistedControlIpFamilyPolicy(t, localSpaceState, IpFamilyPolicyForce6) {
		t.Fatal("the device process never recorded the policy, so nothing crossed the rpc")
	}
}

// The user's real order of operations on ios: force a family from the
// developer menu with the tunnel down, then start the tunnel. The extension
// reads its own Documents container, so the file the app wrote is one it never
// opens -- the queued sync state is the only thing that carries the policy,
// and this covers the apply on the device side of the sync
// (`DeviceLocalRpc.syncState`), which the live-rpc test above bypasses.
func TestDeviceRemoteQueuedPolicyCrossesWhenTheTunnelComesUp(t *testing.T) {
	defer SetControlIpFamilyPolicy(IpFamilyPolicyAuto)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	localSpace, localByJwt, err := testing_newNetworkSpace(ctx)
	if err != nil {
		t.Fatalf("network space: %v", err)
	}
	remoteSpace, remoteByJwt, err := testing_newNetworkSpace(ctx)
	if err != nil {
		t.Fatalf("network space: %v", err)
	}
	localSpaceState := localSpace.GetAsyncLocalState().GetLocalState()

	clientId := connect.NewId()
	instanceId := NewId()
	settings := defaultDeviceRpcSettings()

	// the tunnel is down: nothing is listening on the rpc address yet
	deviceRemote, err := newDeviceRemoteWithOverrides(
		remoteSpace, remoteByJwt, instanceId, settings, clientId, testing_deviceRpcDialer(settings),
	)
	if err != nil {
		t.Fatalf("device remote: %v", err)
	}
	defer deviceRemote.Close()
	connect.AssertEqual(t, deviceRemote.GetRemoteConnected(), false)

	deviceRemote.SetControlIpFamilyPolicy(IpFamilyPolicyForce6)

	// stand in for the tunnel process starting: a fresh device whose own
	// storage has never held a policy
	deviceLocal, err := newDeviceLocalWithOverrides(
		localSpace, localByJwt, "", "", "", instanceId, testDeviceLocalSettingsRpc(), clientId,
	)
	if err != nil {
		t.Fatalf("device local: %v", err)
	}
	defer deviceLocal.Close()
	if _, ok := localSpaceState.controlIpFamilyPolicyIfSet(); ok {
		t.Fatal("the device storage already holds a policy, so a crossing would be unobservable")
	}

	deviceRemote.Sync()
	if !deviceRemote.waitForSync(15 * time.Second) {
		t.Fatal("device remote did not sync after the device came up")
	}

	if !awaitPersistedControlIpFamilyPolicy(t, localSpaceState, IpFamilyPolicyForce6) {
		t.Fatal("the tunnel came up under the old policy, so the extension keeps dialing the stuck family")
	}
}

// A policy this process restored from its own storage is re-queued for the
// device process at construction: on ios the app's copy and the extension's
// are separate files in separate containers, so a reinstall or a cleared
// extension container would otherwise leave the extension on auto while the
// app reported the family the user forced.
func TestDeviceRemoteRestoredPolicyIsQueuedForTheDevice(t *testing.T) {
	defer SetControlIpFamilyPolicy(IpFamilyPolicyAuto)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	networkSpace, byJwt, err := testing_newNetworkSpace(ctx)
	if err != nil {
		t.Fatalf("network space: %v", err)
	}

	// the policy a previous app session chose
	if err := networkSpace.GetAsyncLocalState().GetLocalState().SetControlIpFamilyPolicy(IpFamilyPolicyForce4); err != nil {
		t.Fatalf("SetControlIpFamilyPolicy: %v", err)
	}
	SetControlIpFamilyPolicy(IpFamilyPolicyAuto)

	deviceRemote := newTestDeviceRemoteWithNoServiceInSpace(t, networkSpace, byJwt)

	if got := deviceRemote.GetControlIpFamilyPolicy(); got != IpFamilyPolicyForce4 {
		t.Fatalf("this process is at %d after constructing the device remote, want force4", got)
	}
	deviceRemote.stateLock.Lock()
	queued := deviceRemote.state.ControlIpFamilyPolicy
	deviceRemote.stateLock.Unlock()
	if !queued.IsSet || queued.Value != IpFamilyPolicyForce4 {
		t.Fatalf("queued %+v, want force4 set -- the extension comes up on auto", queued)
	}
}

// awaitPersistedControlIpFamilyPolicy waits for a policy to land in one local
// state. The device persists asynchronously (serialAsync), so the write trails
// the call that caused it.
func awaitPersistedControlIpFamilyPolicy(t *testing.T, localState *LocalState, want int) bool {
	t.Helper()
	for i := 0; i < 500; i += 1 {
		if got, ok := localState.controlIpFamilyPolicyIfSet(); ok && got == want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
