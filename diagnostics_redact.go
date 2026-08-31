package sdk

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// The pieces the ipv6 pattern is assembled from: one hex group, the dotted
// quad an ipv4-mapped literal ends with, either of those, and an optional
// zone.
const (
	addrGroup = `[0-9a-fA-F]{1,4}`
	addrQuad  = `\d{1,3}(?:\.\d{1,3}){3}`
	addrPart  = `(?:` + addrQuad + `|` + addrGroup + `)`
	addrZone  = `(?:%[0-9a-zA-Z._-]{1,16})?`
)

// The patterns the redactor rewrites. Everything else in a line -- timestamps,
// the file:line header, component tags, counters, message text -- is left
// exactly as written, so a redacted bundle is still readable as a log.
var (
	// dotted-quad with an optional :port
	redactIPv4Pattern = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b(?::\d{1,5})?`)
	// uuid, the shape of client, network, device and instance ids
	redactUUIDPattern = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
	// ipv6, bracketed with an optional :port or bare, with an optional zone
	// and an optional trailing dotted quad for the ipv4-mapped forms.
	//
	// The pattern is loose in the MIDDLE and strict at the EDGES, and the
	// split is what makes both halves of the job hold at once.
	//
	// Loose in the middle: a bare candidate is any run of hex groups joined by
	// ':' or '::', down to two groups, and isAddrLiteral decides what is
	// really an address. That is what admits the compressed literals
	// netip.Addr.String() prints -- 2001::1, fd00::1234, fe80::1, ::1 -- which
	// an older three-colon floor missed entirely. Parsing the candidate
	// protects a glog HH:MM:SS timestamp exactly, since 12:34:56 is not an
	// address, and it is also what keeps a bracketed counter like [10] or [42]
	// from being rewritten as one.
	//
	// Strict at the edges: a bare candidate begins at a word boundary on a hex
	// group, or on the '::' of a leading compression, and it ends on a group,
	// on a dotted quad, or on the '::' of a trailing compression -- never on a
	// bare ':'. An edge that over-matches is unrecoverable in a way a middle
	// that over-matches is not: swallowing the ':' beside an address makes the
	// whole span unparseable, and a rejected span is skipped whole, so the
	// address inside it goes out in the clear. That is what a pattern without
	// these anchors did to "dial 2001:db8::1: connection refused" and
	// "{Ip:2001:db8::1 Port:443}", the two commonest address shapes in a Go
	// network log.
	redactIPv6Pattern = regexp.MustCompile(
		`\[[0-9a-fA-F:.]{2,45}` + addrZone + `\](?::\d{1,5})?` +
			`|\b` + addrGroup + `(?:(?::{1,2}` + addrPart + `){1,7}(?:::|\b)|::)` + addrZone +
			`|::` + addrPart + `(?::{1,2}` + addrPart + `){0,6}\b` + addrZone)
)

// isAddrLiteral reports whether one candidate match is really an ip address
// literal, in any of the forms the patterns can hand it: bare, bracketed,
// bracketed with a port, or a dotted quad with a port.
//
// This is the guard that lets the patterns be generous. Timestamps, bracketed
// counters and hex-looking tags reach it and are rejected, which is what the
// spec means by "timestamps, component tags, counters and message structure
// survive verbatim".
func isAddrLiteral(match string) bool {
	host := match
	if strings.HasPrefix(host, "[") {
		// [addr] or [addr]:port -- what follows the closing bracket is a port
		// and says nothing about whether the inside is an address
		end := strings.LastIndex(host, "]")
		if end <= 1 {
			return false
		}
		host = host[1:end]
	} else if i := strings.LastIndex(host, ":"); 0 < i && strings.Contains(host[:i], ".") {
		// a dotted quad with a trailing :port. Only the v4 pattern and the
		// ipv4-mapped tail can produce one; bare ipv6 is matched without a
		// port, so nothing here can strip a group off a real address.
		host = host[:i]
	}
	_, err := netip.ParseAddr(host)
	return err == nil
}

// longestAddrLiteral returns the bounds of the longest address literal inside
// one candidate span, or an empty range when the span holds none.
//
// It is what makes the rejection path fail safe. A span that does not parse
// whole is written back verbatim and the scan resumes past it, so whatever the
// span swallowed is never reconsidered -- an over-match leaks, it does not
// merely add noise. So instead of trusting the pattern to be exact, a
// rejected span is searched: every substring that begins and ends on a group
// boundary (the span's own ends, and either side of a ':' or a bracket) is
// parsed, and the longest that parses wins. "2001:db8::1::2" is not an
// address, and neither is "[2001:db8::1::2]:443", but the address inside each
// is still masked.
//
// The search is bounded by the span, which the pattern holds well under a
// hundred characters, and it neither recurses nor rescans its own output, so
// redaction stays one pass over the line and always terminates.
func longestAddrLiteral(candidate string) (int, int) {
	// the ends of the span, and either side of every separator the patterns
	// can leave inside one
	bounds := []int{0}
	for i := 0; i < len(candidate); i += 1 {
		switch candidate[i] {
		case ':', '[', ']':
			bounds = append(bounds, i, i+1)
		}
	}
	bounds = append(bounds, len(candidate))

	start, end := 0, 0
	for _, lo := range bounds {
		for _, hi := range bounds {
			if hi-lo <= end-start {
				continue
			}
			if _, err := netip.ParseAddr(candidate[lo:hi]); err == nil {
				start, end = lo, hi
			}
		}
	}
	return start, end
}

// logRedactor maps sensitive values to stable per-export tokens.
//
// Stability within one export is what keeps a redacted bundle useful: the same
// address reads as the same token on every line, so a flow can still be
// followed. The salt is random per export and is never written into the bundle
// or logged, so tokens cannot be correlated between bundles or reversed.
type logRedactor struct {
	salt []byte
}

// newLogRedactor creates a redactor with a fresh, random per-export salt. It
// fails closed: when crypto/rand cannot supply real randomness, it returns an
// error instead of substituting anything derived from process-constant state
// (like the log paths). A path-derived salt would be the same for every
// bundle this install ever exports, letting tokens be correlated across
// bundles -- exactly the property redaction exists to prevent -- so there is
// no safe fallback here, only success or an error.
func newLogRedactor() (*logRedactor, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating redaction salt: %w", err)
	}
	return &logRedactor{salt: salt}, nil
}

func (self *logRedactor) token(prefix string, value string) string {
	mac := hmac.New(sha256.New, self.salt)
	mac.Write([]byte(value))
	return prefix + hex.EncodeToString(mac.Sum(nil))[:12] + ">"
}

// redactLine rewrites one line. It is applied to EVERY line of a log file,
// including the plaintext header block, the rotation footer, and backtrace
// continuation lines, which carry no [IWEF] header prefix -- so it must never
// depend on a line being a well-formed glog entry.
func (self *logRedactor) redactLine(line string) string {
	line = redactUUIDPattern.ReplaceAllStringFunc(line, func(match string) string {
		return self.token("<id:", match)
	})
	line = redactIPv6Pattern.ReplaceAllStringFunc(line, self.addrToken)
	line = redactIPv4Pattern.ReplaceAllStringFunc(line, self.addrToken)
	return line
}

// addrToken rewrites a candidate address match, and leaves anything that is
// not an address exactly as it was.
func (self *logRedactor) addrToken(match string) string {
	if isAddrLiteral(match) {
		return self.token("<addr:", match)
	}
	// Not an address whole. Either the span is a lookalike the pattern was
	// generous enough to offer -- a timestamp, a counter -- and holds no
	// address at all, or it took in more than the address inside it, in which
	// case the address is masked and the surplus is written back untouched.
	start, end := longestAddrLiteral(match)
	if start == end {
		return match
	}
	return match[:start] + self.token("<addr:", match[start:end]) + match[end:]
}
