package service

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// An invitation note is free text an inviter puts in an email the service
// sends under its own name, so it is kept short and unable to carry a link:
// at most maxInvitationNoteRunes characters on at most maxInvitationNoteLines
// lines.
const (
	maxInvitationNoteRunes = 280
	maxInvitationNoteLines = 4
)

// ErrInvitationNoteNotAllowed refuses a note on an invitation that may not
// carry one: the project has not turned notes on (tenants.invitation_notes,
// or GATEWAY_TENANT_INVITATION_NOTES_ENABLED for the default project), or the
// tenant is one a user created and the project has not turned them on there
// (tenants.invitation_notes_self_service, or
// GATEWAY_TENANT_INVITATION_NOTES_SELF_SERVICE_ENABLED). Mapped to
// CodeFailedPrecondition.
var ErrInvitationNoteNotAllowed = errors.New("this invitation cannot carry a note")

// noteURLSchemes are the schemes a mail client turns into a link without a
// "//" after the colon. A scheme followed by "//" is refused whatever it is.
var noteURLSchemes = []string{"mailto", "tel", "sms", "callto", "javascript", "vbscript", "data", "file"}

// normalizeInvitationNote returns the note an invitation email shows, or ""
// for none. It trims the note and each of its lines, writes a CRLF line break
// as LF, and refuses (ErrInvalidArgument) a note that is not valid UTF-8,
// that is longer than maxInvitationNoteRunes or has more than
// maxInvitationNoteLines lines, that has a blank line, that carries a
// character normalizeText refuses (a control other than the line break, a
// bidirectional control or another invisible formatting character), or that
// reads as a link (noteLinkLike).
func normalizeInvitationNote(note string) (string, error) {
	if !utf8.ValidString(note) {
		return "", fmt.Errorf("%w: note is not valid UTF-8", ErrInvalidArgument)
	}
	note = strings.TrimSpace(strings.ReplaceAll(note, "\r\n", "\n"))
	if note == "" {
		return "", nil
	}
	lines := strings.Split(note, "\n")
	if len(lines) > maxInvitationNoteLines {
		return "", fmt.Errorf("%w: note has more than %d lines", ErrInvalidArgument, maxInvitationNoteLines)
	}
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
		if lines[i] == "" {
			return "", fmt.Errorf("%w: note has a blank line", ErrInvalidArgument)
		}
		if strings.ContainsFunc(lines[i], refusedTextRune) {
			return "", fmt.Errorf("%w: note contains control or invisible formatting characters", ErrInvalidArgument)
		}
	}
	note = strings.Join(lines, "\n")
	if utf8.RuneCountInString(note) > maxInvitationNoteRunes {
		return "", fmt.Errorf("%w: note is longer than %d characters", ErrInvalidArgument, maxInvitationNoteRunes)
	}
	if noteLinkLike(note) {
		return "", fmt.Errorf("%w: note may not contain a link, a web address or markup; an email address is allowed", ErrInvalidArgument)
	}
	return note, nil
}

// noteLinkLike reports whether note reads as, or would be turned by a mail
// client into, a link. It judges the note as foldNote spells it, so a
// lookalike spelling (fullwidth letters, an ideographic full stop for a dot)
// is judged as the text it imitates; a letter of another script that only
// looks Latin is still a letter, so "example.com" spelled with a Cyrillic
// small letter a in place of the Latin one reads as a domain like any
// other. Refused:
//
//   - "<" or ">", which HTML markup and autolinks need, and "](", which a
//     markdown link needs;
//   - "://" anywhere, a scheme of noteURLSchemes directly followed by ":"
//     and a non-space, and any word directly followed by ":" and an address,
//     such as "sip:jane@example.com";
//   - a word holding "@" that is not, as the note spells it before folding, a
//     plain ASCII email address (noteEmailAddress);
//   - any other word of at least two dot-separated labels ending in a label of
//     two or more letters, or in a punycode label, such as "www.example",
//     "example.com" or "пример.рф", and a dotted IPv4 address.
//
// The email address is the one thing allowed that folding could forge: a
// fullwidth or small at sign, or a fullwidth dot, folds into one, while the
// email shows the unfolded note, whose ASCII remainder a mail client links.
// So an address is recognised only in the note as sent, and blanked out
// before the rest is folded and judged; whatever still holds "@" after
// folding was not typed as a plain address and is refused.
//
// A word is a run of letters, marks, digits and "-", ".", "_", "+", "@", with
// any leading or trailing "-", ".", "_" or "+" dropped, so "e.g." and "v1.2"
// pass and so does a full stop ending a sentence; one without the space after
// it ("done.see") reads as a domain.
func noteLinkLike(note string) bool {
	folded := foldNote(note)
	if strings.ContainsAny(folded, "<>") || strings.Contains(folded, "](") || strings.Contains(folded, "://") {
		return true
	}
	for _, scheme := range noteURLSchemes {
		if hasSchemePrefix(folded, scheme) {
			return true
		}
	}
	if hasSchemeBeforeAddress(folded) {
		return true
	}
	for _, word := range strings.FieldsFunc(foldNote(withoutEmailAddresses(note)), func(r rune) bool { return !isNoteWordRune(r) }) {
		word = strings.Trim(word, "-._+")
		if strings.Contains(word, "@") || noteDomainLike(word) {
			return true
		}
	}
	return false
}

// withoutEmailAddresses is note with each word that is a plain ASCII email
// address (noteEmailAddress) replaced by a space.
func withoutEmailAddresses(note string) string {
	var b strings.Builder
	word := 0
	blank := func(end int) {
		if noteEmailAddress(strings.Trim(note[word:end], "-._+")) {
			b.WriteByte(' ')
		} else {
			b.WriteString(note[word:end])
		}
	}
	for i, r := range note {
		if isNoteWordRune(r) {
			continue
		}
		blank(i)
		b.WriteRune(r)
		word = i + utf8.RuneLen(r)
	}
	blank(len(note))
	return b.String()
}

// foldNote is note in the form noteLinkLike judges: without the zero-width
// joiner and non-joiner, which normalizeText admits but which would split a
// domain without showing it; compatibility-normalized (NFKC, which writes
// fullwidth, circled and mathematical letters as the letters they imitate);
// lower-cased; and with an ideographic full stop, which IDNA reads as a dot,
// written as one between two word characters of a script other than Chinese,
// Japanese or Korean, where it ends a sentence instead.
func foldNote(note string) string {
	note = strings.NewReplacer("\u200c", "", "\u200d", "").Replace(note)
	runes := []rune(strings.ToLower(norm.NFKC.String(note)))
	for i, r := range runes {
		if r == ideographicFullStop && i > 0 && i < len(runes)-1 && readsAsLabel(runes[i-1]) && readsAsLabel(runes[i+1]) {
			runes[i] = '.'
		}
	}
	return string(runes)
}

// ideographicFullStop is U+3002, which NFKC also makes of the halfwidth one.
const ideographicFullStop = '\u3002'

func readsAsLabel(r rune) bool {
	return isNoteWordRune(r) && !unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul, unicode.Bopomofo)
}

// hasSchemePrefix reports whether scheme+":" starts a word of s and is
// directly followed by a character other than a space.
func hasSchemePrefix(s, scheme string) bool {
	prefix := scheme + ":"
	for offset := 0; ; {
		i := strings.Index(s[offset:], prefix)
		if i < 0 {
			return false
		}
		i += offset
		rest := s[i+len(prefix):]
		if (i == 0 || !isNoteWordRune(lastRune(s[:i]))) && rest != "" && !unicode.IsSpace(firstRune(rest)) {
			return true
		}
		offset = i + len(prefix)
	}
}

// hasSchemeBeforeAddress reports whether a word of s is directly followed by
// ":" and a word holding "@", the shape of a link to an address under any
// scheme, listed in noteURLSchemes or not.
func hasSchemeBeforeAddress(s string) bool {
	for i, r := range s {
		if r != ':' || i == 0 || !isNoteWordRune(lastRune(s[:i])) {
			continue
		}
		rest := s[i+1:]
		if end := strings.IndexFunc(rest, func(r rune) bool { return !isNoteWordRune(r) }); end >= 0 {
			rest = rest[:end]
		}
		if strings.Contains(rest, "@") {
			return true
		}
	}
	return false
}

func isNoteWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsDigit(r) || strings.ContainsRune("-._+@", r)
}

// noteEmailAddress reports whether word is a plain ASCII email address: one
// "@", a local part of letters, digits and ".", "_", "+", "-" that neither
// starts nor ends with a dot nor holds two in a row, and a domain that
// noteDomainLike recognises, made of ASCII letters, digits and "-" only.
func noteEmailAddress(word string) bool {
	local, domain, ok := strings.Cut(word, "@")
	if !ok || local == "" || strings.Contains(domain, "@") {
		return false
	}
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return false
	}
	if strings.ContainsFunc(local, func(r rune) bool { return !isASCIIAlnum(r) && !strings.ContainsRune("._+-", r) }) {
		return false
	}
	if strings.ContainsFunc(domain, func(r rune) bool { return !isASCIIAlnum(r) && !strings.ContainsRune(".-", r) }) {
		return false
	}
	return noteDomainLike(domain)
}

// noteDomainLike reports whether word is at least two non-empty
// dot-separated labels whose last is two or more letters or a punycode
// ("xn--") label, or a dotted IPv4 address. A letter's combining marks count
// as letters, as a top-level domain in an Indic script needs them.
func noteDomainLike(word string) bool {
	labels := strings.Split(word, ".")
	if len(labels) < 2 {
		return false
	}
	numeric := true
	for _, label := range labels {
		if label == "" {
			return false
		}
		numeric = numeric && !strings.ContainsFunc(label, func(r rune) bool { return r < '0' || r > '9' })
	}
	if numeric {
		return len(labels) == 4
	}
	last := labels[len(labels)-1]
	if strings.HasPrefix(last, "xn--") {
		return true
	}
	return utf8.RuneCountInString(last) >= 2 && !strings.ContainsFunc(last, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsMark(r) })
}

func isASCIIAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

func firstRune(s string) rune {
	r, _ := utf8.DecodeRuneInString(s)
	return r
}

func lastRune(s string) rune {
	r, _ := utf8.DecodeLastRuneInString(s)
	return r
}
