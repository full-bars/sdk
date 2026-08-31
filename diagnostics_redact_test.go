package sdk

import (
	"strings"
	"testing"
)

func TestRedactorMasksAddressesAndIdsButLeavesStructureIntact(t *testing.T) {
	redactor := newLogRedactor()

	cases := []struct {
		name     string
		line     string
		contains []string
		absent   []string
	}{
		{
			name:     "destination ip and port",
			line:     "I0830 10:11:12.131415    4242 ip_remote_multi_client.go:5864] [multi]drop packet ipv4 p6 -> 203.0.113.7:443",
			contains: []string{"I0830 10:11:12.131415", "ip_remote_multi_client.go:5864]", "[multi]drop packet ipv4 p6 ->"},
			absent:   []string{"203.0.113.7"},
		},
		{
			name:     "client uuid",
			line:     "I0830 10:11:12.131415    4242 transport.go:1763] [t]auth error 11111111-1111-1111-1111-111111111111 = bad",
			contains: []string{"[t]auth error", "= bad"},
			absent:   []string{"11111111-1111-1111-1111-111111111111"},
		},
		{
			name:     "continuation line with no header is still redacted",
			line:     "\tat 198.51.100.9:8080 in frame 3",
			contains: []string{"in frame 3"},
			absent:   []string{"198.51.100.9"},
		},
		{
			name:     "non-sensitive text is untouched",
			line:     "I0830 10:11:12.131415    4242 window.go:12] [window]evaluating 4 candidates, target 8",
			contains: []string{"[window]evaluating 4 candidates, target 8"},
			absent:   []string{},
		},
	}

	for _, c := range cases {
		got := redactor.redactLine(c.line)
		for _, want := range c.contains {
			if !strings.Contains(got, want) {
				t.Errorf("%s: redacted line %q lost %q", c.name, got, want)
			}
		}
		for _, unwanted := range c.absent {
			if strings.Contains(got, unwanted) {
				t.Errorf("%s: redacted line %q still contains %q", c.name, got, unwanted)
			}
		}
	}
}

// The same value must map to the same token within one export, so a flow can
// still be followed across lines; a different export must map it differently,
// so tokens cannot be correlated between bundles.
func TestRedactorIsStableWithinAnExportAndDistinctAcross(t *testing.T) {
	line := "peer 203.0.113.7:443 selected"

	first := newLogRedactor()
	a := first.redactLine(line)
	b := first.redactLine(line)
	if a != b {
		t.Fatalf("same redactor produced %q then %q; tokens must be stable within an export", a, b)
	}

	second := newLogRedactor()
	c := second.redactLine(line)
	if a == c {
		t.Fatalf("two redactors both produced %q; tokens must not be correlatable across exports", a)
	}
}
