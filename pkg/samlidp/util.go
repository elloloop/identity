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

// escape XML-escapes a string for safe inclusion in XML — both element
// content and double-quoted attribute values — covering all five predefined
// entities (& < > " '). Every dynamic value emitted into the SAML XML MUST
// pass through escape; never use fmt %q for XML attributes (Go-literal
// quoting is not XML escaping: it renders " as \" — the quote still
// terminates the attribute, enabling attribute/element injection into the
// signed assertion).
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

// isValidNCName reports whether s is a syntactically valid XML NCName: a
// non-empty name that starts with a letter or underscore, contains only
// letters, digits, '.', '-' or '_', and (being "non-colonized") has no ':'.
// SAML element @ID values must be NCNames; validating an inbound
// AuthnRequest @ID before it is echoed into the signed Response
// (InResponseTo) is defense-in-depth on top of attribute escaping.
func isValidNCName(s string) bool {
	if s == "" {
		return false
	}
	for idx, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
			// Always allowed.
		case (r >= '0' && r <= '9') || r == '.' || r == '-':
			// Allowed only after the first character.
			if idx == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
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
