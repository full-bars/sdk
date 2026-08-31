package sdk

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

// The patterns the redactor rewrites. Everything else in a line -- timestamps,
// the file:line header, component tags, counters, message text -- is left
// exactly as written, so a redacted bundle is still readable as a log.
var (
	// dotted-quad with an optional :port
	redactIPv4Pattern = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b(?::\d{1,5})?`)
	// uuid, the shape of client, network, device and instance ids
	redactUUIDPattern = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
	// bracketed ipv6 (any colon count), optional :port when bracketed; bare
	// (unbracketed) ipv6 requires at least three colons -- a bare two-colon
	// run is indistinguishable from a glog HH:MM:SS timestamp, since digits
	// are valid hex, and the timestamp must survive redaction untouched.
	redactIPv6Pattern = regexp.MustCompile(`\[[0-9a-fA-F:]{2,}\](?::\d{1,5})?|\b(?:[0-9a-fA-F]{0,4}:){3,7}[0-9a-fA-F]{0,4}\b`)
)

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
	line = redactIPv6Pattern.ReplaceAllStringFunc(line, func(match string) string {
		return self.token("<addr:", match)
	})
	line = redactIPv4Pattern.ReplaceAllStringFunc(line, func(match string) string {
		return self.token("<addr:", match)
	})
	return line
}
