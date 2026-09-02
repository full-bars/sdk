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
