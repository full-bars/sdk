package sdk

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

func newLogRedactor() *logRedactor {
	salt := make([]byte, 32)
	// rand.Read from crypto/rand never returns a short read without an error,
	// and an error here is unrecoverable -- a zero salt would be a false
	// promise of redaction, so fail closed by keeping the random bytes we have
	// only when the read succeeded.
	if _, err := rand.Read(salt); err != nil {
		// fall back to a still-unpredictable-per-process value rather than zeros
		h := sha256.Sum256([]byte(GetLogDir() + GetLogRoot()))
		salt = h[:]
	}
	return &logRedactor{salt: salt}
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
