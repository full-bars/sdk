package sdk

import (
	"regexp"
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

// Tokens carry a per-export hmac, so a test cannot spell one out. Folding
// every token down to <addr> or <id> lets a case state the WHOLE redacted
// line, which is what catches a partial leak: a case that only asserted the
// full literal was absent would pass on "<addr:...>:2", where the pattern
// masked all but the last group.
var redactTokenPattern = regexp.MustCompile(`<(addr|id):[0-9a-f]{12}>`)

func normalizeRedactionTokens(line string) string {
	return redactTokenPattern.ReplaceAllString(line, "<$1>")
}

// TestRedactorMasksIPv6WhateverSurroundsIt pins the address pattern against
// both defects it has had, which pull in opposite directions.
//
// Under-redaction, the first: the pattern once required three colon groups, so
// every compressed literal netip.Addr.String() prints with exactly two --
// 2001::1, fd00::1234, fe80::1, ::1 -- passed through a REDACTED bundle
// verbatim, on the one mode whose entire purpose is not to leak addresses.
//
// Under-redaction, the second, and the reason this test states whole lines:
// dropping the boundary anchors to admit those compressed forms let a match
// swallow the ':' beside an address. netip.ParseAddr rejects the over-matched
// span, the span is written back verbatim, and the scan resumes PAST it, so
// the address inside is never reconsidered -- "dial 2001:db8::1: connection
// refused" and "{Ip:2001:db8::1 Port:443}", the shapes net.Dial errors and a
// %+v of a struct actually print, leaked in full. The earlier version of this
// test missed it by only ever surrounding an address with spaces.
//
// Over-redaction is the other half: a glog HH:MM:SS timestamp and a bracketed
// counter are shaped like the address forms, and the spec requires both to
// survive verbatim.
func TestRedactorMasksIPv6WhateverSurroundsIt(t *testing.T) {
	redactor, err := newLogRedactor()
	if err != nil {
		t.Fatalf("newLogRedactor: %v", err)
	}

	cases := []struct {
		name string
		line string
		want string
	}{
		// an address with punctuation up against it. Every one of these was
		// redacted before the compressed forms were admitted, leaked after,
		// and must be redacted again.
		{
			name: "net.Dial error, address then a colon",
			line: "dial 2001:db8::1: connection refused",
			want: "dial <addr>: connection refused",
		},
		{
			name: "net.Dial error with the port, exactly as net prints it",
			line: "dial tcp 2001:db8::1:443: connect: connection refused",
			want: "dial tcp <addr>: connect: connection refused",
		},
		{
			name: "%+v of a struct, address preceded by a field colon",
			line: "{Ip:2001:db8::1 Port:443}",
			want: "{Ip:<addr> Port:443}",
		},
		{
			name: "compressed address then a colon",
			line: "peer fe80::1: timeout",
			want: "peer <addr>: timeout",
		},
		{
			name: "address preceded by a colon, at the end of the line",
			line: "addr:2001:db8::1",
			want: "addr:<addr>",
		},
		{
			name: "address with a colon on both sides",
			line: "host:2001:db8::1:2",
			want: "host:<addr>",
		},
		{
			name: "every group present, colon in front",
			line: "src:2001:db8:1:2:3:4:5:6",
			want: "src:<addr>",
		},
		{
			name: "address in parentheses",
			line: "(2001:db8::1)",
			want: "(<addr>)",
		},
		{
			name: "address quoted in json",
			line: `{"addr":"2001:db8::1","port":443}`,
			want: `{"addr":"<addr>","port":443}`,
		},
		{
			name: "address in a key=value pair",
			line: "peer=2001:db8::1;port=443",
			want: "peer=<addr>;port=443",
		},
		{
			name: "address in a url authority",
			line: "GET http://[2001:db8::1]:8080/path",
			want: "GET http://<addr>/path",
		},

		// compressed literals standing alone, the forms
		// netip.Addr.String() prints
		{name: "compressed, two groups", line: "peer 2001::1 selected", want: "peer <addr> selected"},
		{name: "compressed, unique local", line: "peer fd00::1234 selected", want: "peer <addr> selected"},
		{name: "compressed, link local", line: "peer fe80::1 selected", want: "peer <addr> selected"},
		{name: "loopback", line: "peer ::1 selected", want: "peer <addr> selected"},
		{name: "trailing compression", line: "peer 2001:db8:: selected", want: "peer <addr> selected"},
		{name: "compressed, three groups", line: "peer 2001:db8::1 selected", want: "peer <addr> selected"},
		{name: "compressed resolver", line: "peer 2606:4700:4700::1111 selected", want: "peer <addr> selected"},
		{name: "compressed, four groups", line: "peer 2a00:1450:4001:82f::200e selected", want: "peer <addr> selected"},
		{name: "bracketed with a port", line: "peer [fe80::1]:443 selected", want: "peer <addr> selected"},
		{name: "bracketed", line: "peer [2001:db8::1] selected", want: "peer <addr> selected"},
		{name: "bracketed loopback with a port", line: "peer [::1]:53 selected", want: "peer <addr> selected"},
		{name: "ipv4-mapped", line: "peer ::ffff:192.0.2.128 selected", want: "peer <addr> selected"},
		{name: "zone", line: "peer fe80::1%en0 selected", want: "peer <addr> selected"},
		{name: "bracketed zone with a port", line: "peer [fe80::1%en0]:443 selected", want: "peer <addr> selected"},
		{name: "dotted quad", line: "peer 203.0.113.7 selected", want: "peer <addr> selected"},
		{name: "dotted quad with a port", line: "peer 203.0.113.7:443 selected", want: "peer <addr> selected"},

		// a span that is not an address but contains one. The pattern is
		// loose in the middle on purpose, so the rejection path has to look
		// inside rather than skip the span whole.
		{
			name: "two compressions, not an address, but one inside it",
			line: "weird 2001:db8::1::2 tail",
			want: "weird <addr>::2 tail",
		},
		{
			name: "bracketed span that is not an address, but one inside it",
			line: "bracket [2001:db8::1::2] tail",
			want: "bracket [<addr>::2] tail",
		},

		// lookalikes: everything here must come out byte for byte
		{
			name: "glog header timestamp is not an address",
			line: "I0830 10:11:12.131415    4242 x.go:5864] started",
			want: "I0830 10:11:12.131415    4242 x.go:5864] started",
		},
		{
			name: "bracketed counters survive",
			line: "retry [10] of [42]",
			want: "retry [10] of [42]",
		},
		{
			name: "bracketed counter and a hex-looking tag survive",
			line: "pool[16] weight [dead] entry",
			want: "pool[16] weight [dead] entry",
		},
		{
			name: "component tag next to a counter survives",
			line: "[control][12] window",
			want: "[control][12] window",
		},
		{
			name: "component tag survives",
			line: "[multi]drop packet ipv4 p6 -> peer",
			want: "[multi]drop packet ipv4 p6 -> peer",
		},
		{
			name: "file:line and message text survive",
			line: "window.go:12] [window]evaluating 4 candidates, target 8",
			want: "window.go:12] [window]evaluating 4 candidates, target 8",
		},
		{
			name: "an elapsed time is not an address",
			line: "took 1:23:45 total",
			want: "took 1:23:45 total",
		},
		{
			name: "a printed map is not an address",
			line: "map[a:1 b:2 c:3]",
			want: "map[a:1 b:2 c:3]",
		},
		{
			name: "two hex-looking words are not an address",
			line: "cafe:babe not an address",
			want: "cafe:babe not an address",
		},
		{
			name: "the glog header block survives",
			line: "Log line format: [IWEF]mmdd hh:mm:ss.uuuuuu threadid file:line] msg",
			want: "Log line format: [IWEF]mmdd hh:mm:ss.uuuuuu threadid file:line] msg",
		},

		// a whole entry: header, id and address all on one line
		{
			name: "full glog entry",
			line: "I0830 10:11:12.131415    42 transport.go:1] [t]auth 11111111-1111-1111-1111-111111111111 dial 2001:db8::1: refused",
			want: "I0830 10:11:12.131415    42 transport.go:1] [t]auth <id> dial <addr>: refused",
		},
	}

	for _, c := range cases {
		got := normalizeRedactionTokens(redactor.redactLine(c.line))
		if got != c.want {
			t.Errorf("%s: redactLine(%q)\n got %q\nwant %q", c.name, c.line, got, c.want)
		}
	}
}

// Redaction is applied to every line of every log file in a bundle, so it has
// to be a single bounded pass: no rescan of what it just wrote, no growth on
// its own output. A leak-shaped bug would be caught by the table above; this
// catches the other failure, a redactor that does not come back.
func TestRedactorTerminatesAndIsIdempotentOnItsOwnOutput(t *testing.T) {
	redactor, err := newLogRedactor()
	if err != nil {
		t.Fatalf("newLogRedactor: %v", err)
	}

	lines := []string{
		"dial 2001:db8::1:443: connect: connection refused",
		"::::::::::::::::::::::::::::::::",
		"1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:0:1:2:3:4:5:6:7:8",
		"[[[[::1]]]]:443",
		"::",
		":",
		"",
		strings.Repeat("2001:db8::1 ", 64),
		"I0830 10:11:12.131415    4242 x.go:5864] [multi]retry [10] of [42] via [fe80::1%en0]:443",
	}
	for _, line := range lines {
		once := redactor.redactLine(line)
		twice := redactor.redactLine(once)
		if once != twice {
			t.Errorf("redactLine is not idempotent on %q:\n once %q\ntwice %q", line, once, twice)
		}
	}
}
