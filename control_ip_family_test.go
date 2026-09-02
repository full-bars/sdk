package sdk

import "testing"

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
