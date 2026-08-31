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

// The patterns the redactor rewrites. Everything else in a line -- timestamps,
// the file:line header, component tags, counters, message text -- is left
// exactly as written, so a redacted bundle is still readable as a log.
var (
	// dotted-quad with an optional :port
	redactIPv4Pattern = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b(?::\d{1,5})?`)
	// uuid, the shape of client, network, device and instance ids
	redactUUIDPattern = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
	// ipv6, bracketed with an optional :port or bare, with an optional zone
	// and an optional trailing dotted quad for the v4-mapped forms.
	//
	// Both alternatives deliberately over-match, down to two colon groups, and
	// isAddrLiteral decides what is actually an address. The previous
	// three-colon floor existed to protect a glog HH:MM:SS timestamp, and it
	// cost every compressed literal netip.Addr.String() prints: 2001::1,
	// fd00::1234, fe80::1 and ::1 all passed through a redacted bundle
	// verbatim. Parsing the candidate protects the timestamp exactly (12:34:56
	// is not an address) without giving up the compressed forms, and it is
	// also what stops a bracketed counter -- retry [10] of [42] -- from being
	// rewritten as an address.
	redactIPv6Pattern = regexp.MustCompile(
		`\[[0-9a-fA-F:.]{2,45}(?:%[0-9a-zA-Z._-]{1,16})?\](?::\d{1,5})?` +
			`|(?:[0-9a-fA-F]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4})(?:%[0-9a-zA-Z._-]{1,16})?`)
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
		// v4-mapped tail can produce one; bare ipv6 is matched without a port,
		// so nothing here can strip a group off a real address.
		host = host[:i]
	}
	_, err := netip.ParseAddr(host)
	return err == nil
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
	if !isAddrLiteral(match) {
		return match
	}
	return self.token("<addr:", match)
}
