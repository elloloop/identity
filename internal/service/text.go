package service

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// normalizeText trims a line of text a person typed for others to read and
// refuses one that is blank, longer than maxRunes, not valid UTF-8, or
// carrying control or invisible formatting characters, such as the
// bidirectional overrides, which would let one text render as another, or
// the line and paragraph separators (U+2028, U+2029), which break the line
// it is shown on and are neither controls nor formatting characters. The
// zero-width joiner and non-joiner are formatting characters too, but
// Persian, the Indic scripts and emoji sequences need them, so they are
// allowed. field names the text in the refusal.
func normalizeText(field, text string, maxRunes int) (string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", fmt.Errorf("%w: %s is required", ErrInvalidArgument, field)
	}
	if !utf8.ValidString(text) {
		return "", fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidArgument, field)
	}
	if utf8.RuneCountInString(text) > maxRunes {
		return "", fmt.Errorf("%w: %s is longer than %d characters", ErrInvalidArgument, field, maxRunes)
	}
	if strings.ContainsFunc(text, refusedTextRune) {
		return "", fmt.Errorf("%w: %s contains control or invisible formatting characters", ErrInvalidArgument, field)
	}
	return text, nil
}

// refusedTextRune reports whether r may not appear in normalizeText's text: a
// control character, a line or paragraph separator, or a formatting
// character other than the zero-width non-joiner (U+200C) and joiner (U+200D).
func refusedTextRune(r rune) bool {
	if r == '\u200c' || r == '\u200d' {
		return false
	}
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}
