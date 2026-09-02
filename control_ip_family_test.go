package sdk

import (
	"context"
	"testing"
	"time"
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
