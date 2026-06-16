package samlidp

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// samlTime renders t in the SAML/XSD UTC instant format
// (RFC3339 without sub-second precision, e.g. 2026-06-16T12:00:00Z).
func samlTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// randID returns a 128-bit random hex string used for SAML element @ID
// values (which must be XML NCNames, hence the leading underscore the
// callers prepend).
func randID() string {
	var buf [16]byte
	// crypto/rand.Read never returns an error on supported platforms; a
	// failure here is unrecoverable, so panicking is acceptable at the
	// boundary of an ID generator that must not produce predictable IDs.
	if _, err := rand.Read(buf[:]); err != nil {
		panic("samlidp: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(buf[:])
}

// escape XML-escapes text content (the five predefined entities). Attribute
// values are emitted via %q which Go escapes for double-quoted attributes.
func escape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}

// sortedKeys returns the map keys in deterministic order so the serialized
// AttributeStatement is stable (required for a reproducible signature).
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
