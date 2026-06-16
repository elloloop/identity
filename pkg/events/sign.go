package events

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// SignatureHeader is the HTTP header carrying the hex-encoded HMAC-SHA256
// signature of the raw request body. A subscriber recomputes
// HMAC-SHA256(secret, body) and constant-time-compares it to verify the
// webhook originated from this server and was not tampered with.
const SignatureHeader = "X-Identity-Signature"

// EventIDHeader carries the event id so a subscriber can deduplicate
// at-least-once redeliveries without parsing the body.
const EventIDHeader = "X-Identity-Event-Id"

// sign returns the hex-encoded HMAC-SHA256 of payload under secret.
func sign(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature constant-time-compares the provided hex signature
// against HMAC-SHA256(secret, body). Exposed so subscribers (and tests)
// share the exact verification the server expects.
func VerifySignature(secret string, body []byte, signature string) bool {
	want := sign(secret, body)
	return hmac.Equal([]byte(want), []byte(signature))
}
