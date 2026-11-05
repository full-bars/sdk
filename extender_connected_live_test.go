package sdk

import "testing"

func TestExtenderProvideStatusUsesLiveConnected(t *testing.T) {
	state := extenderProvideState{Connected: 9}
	for _, count := range []int{3, 0} {
		status := state.status(count)
		if status.Connected != count || status.ConnectionCount != count {
			t.Fatalf("live = %d, status = %+v", count, status)
		}
	}
}
