package sdk

import (
	"strings"
	"testing"
)

func TestRedactorMasksAddressesAndIdsButLeavesStructureIntact(t *testing.T) {
	redactor, err := newLogRedactor()
	if err != nil {
		t.Fatalf("newLogRedactor: %v", err)
	}

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

	first, err := newLogRedactor()
	if err != nil {
		t.Fatalf("newLogRedactor: %v", err)
	}
	a := first.redactLine(line)
	b := first.redactLine(line)
	if a != b {
		t.Fatalf("same redactor produced %q then %q; tokens must be stable within an export", a, b)
	}

	second, err := newLogRedactor()
	if err != nil {
		t.Fatalf("newLogRedactor: %v", err)
	}
	c := second.redactLine(line)
	if a == c {
		t.Fatalf("two redactors both produced %q; tokens must not be correlatable across exports", a)
	}
}

// TestRedactorSaltDoesNotFallBackToPathDerivedValue pins the fix for a past
// defect: newLogRedactor used to fall back, on a crypto/rand failure, to a
// salt derived only from GetLogDir()+GetLogRoot() -- both constant for the
// life of an install. That fallback made every bundle exported by one
// install share a salt, so the same address would map to the same token
// across DIFFERENT bundles, contradicting the bundle's own README ("...and
// differently in any other bundle").
//
// What this test covers: crypto/rand succeeding in the normal case, which is
// the only case exercised here, still produces a fresh salt every call --
// two redactors built back to back, in the same process, with the same
// GetLogDir()/GetLogRoot(), must not agree on a token for the same input.
// The old path-derived fallback would have failed this, since it depended on
// nothing but those two constant paths.
//
// What this test does NOT cover: it cannot force crypto/rand.Read to fail,
// so it does not exercise the newLogRedactor error return or the "no
// fallback exists" guarantee directly -- that guarantee is enforced by
// newLogRedactor no longer containing a fallback branch at all (see its
// source), not by a test that can trigger the failure path.
func TestRedactorSaltDoesNotFallBackToPathDerivedValue(t *testing.T) {
	line := "peer 203.0.113.7:443 selected"

	first, err := newLogRedactor()
	if err != nil {
		t.Fatalf("newLogRedactor: %v", err)
	}
	second, err := newLogRedactor()
	if err != nil {
		t.Fatalf("newLogRedactor: %v", err)
	}

	a := first.redactLine(line)
	b := second.redactLine(line)
	if a == b {
		t.Fatalf("two redactors in the same process, same GetLogDir()/GetLogRoot(), produced the same token %q; salt must not be path-derived", a)
	}
}

// TestRedactorMasksCompressedIPv6AndLeavesLookalikesAlone pins both halves of
// the address pattern's job.
//
// Under-redaction was the live defect: the pattern required at least three
// colon groups, so every compressed literal netip.Addr.String() prints with
// exactly two -- 2001::1, fd00::1234, fe80::1, ::1 -- passed through a
// REDACTED bundle verbatim, on the one mode whose entire purpose is not to
// leak addresses.
//
// Over-redaction is the other half: a glog HH:MM:SS timestamp and a bracketed
// counter are shaped like the address forms, and the spec requires both to
// survive verbatim.
func TestRedactorMasksCompressedIPv6AndLeavesLookalikesAlone(t *testing.T) {
	redactor, err := newLogRedactor()
	if err != nil {
		t.Fatalf("newLogRedactor: %v", err)
	}

	mustMask := []string{
		"2001::1",
		"fd00::1234",
		"fe80::1",
		"::1",
		"2001:db8::",
		"2001:db8::1",
		"2606:4700:4700::1111",
		"2a00:1450:4001:82f::200e",
		"[fe80::1]:443",
		"[2001:db8::1]",
		"::ffff:192.0.2.128",
		"203.0.113.7",
		"203.0.113.7:443",
	}
	for _, address := range mustMask {
		line := "peer " + address + " selected"
		got := redactor.redactLine(line)
		if strings.Contains(got, address) {
			t.Errorf("redactLine(%q) = %q, still contains the address", line, got)
		}
		if !strings.Contains(got, "<addr:") {
			t.Errorf("redactLine(%q) = %q, no address token", line, got)
		}
	}

	mustSurvive := []string{
		// glog's own header timestamp, the reason the old pattern refused
		// two-colon runs at all
		"I0830 10:11:12.131415    4242 x.go:5864] started",
		// bracketed counters: connect/transfer_control.go, message_pool.go
		"retry [10] of [42]",
		"pool[16] weight [dead] entry",
		"[control][12] window",
		// a component tag and a file:line, neither an address
		"[multi]drop packet ipv4 p6 -> peer",
		"window.go:12] [window]evaluating 4 candidates, target 8",
	}
	for _, line := range mustSurvive {
		if got := redactor.redactLine(line); got != line {
			t.Errorf("redactLine(%q) = %q, want it unchanged", line, got)
		}
	}
}
