package service

import (
	"errors"
	"fmt"
	"regexp"
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

// normalizeInvitationNote returns the note an invitation email shows, or ""
// for none. It trims the note and each of its lines, writes a CRLF line break
// as LF, and refuses (ErrInvalidArgument) a note that is not valid UTF-8,
// that is longer than maxInvitationNoteRunes or has more than
// maxInvitationNoteLines lines, that has a blank line, that carries a
// character normalizeText refuses (a control other than the line break, a
// bidirectional control or another invisible formatting character), or that
// refuseLinkLikeNote refuses.
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
	if err := refuseLinkLikeNote(note); err != nil {
		return "", err
	}
	return note, nil
}

// refuseLinkLikeNote refuses a note a mail client could turn into a link, or
// that could pass for one, with ErrInvalidArgument. It judges the note as
// foldNote spells it, by classes of character rather than by what a link
// looks like, so a lookalike spelling (fullwidth letters, a fullwidth or
// ideographic full stop) is judged as the text it imitates, and a letter of
// any script counts as a letter. Refused:
//
//   - "<", ">", "](" or "://", which markup, autolinks and links need;
//   - "@" anywhere outside a plain ASCII email address as the note spells it
//     before folding (noteEmailAddress);
//   - an ASCII letter followed by any ASCII letters, digits, "+", "." or "-"
//     and then ":" directly followed by a character other than a space: the
//     shape of every URL scheme, listed anywhere or not;
//   - outside such an email address, a "." with a letter, mark or number on
//     both sides, which every domain and dotted IPv4 address has; so are
//     "e.g", "v1.2" and "Node.js", and two sentences with no space between,
//     other than CJK ones joined by an ideographic full stop (foldNote);
//   - seven or more digits with only spaces, "-", ".", "(", ")" or "+"
//     between them, the shape of a phone number; so is a date such as
//     "2026-11-27".
//
// The email address is the one exemption, and the one thing folding could
// forge: a fullwidth or small at sign, or a fullwidth dot, folds into one,
// while the email shows the unfolded note. So an address is recognised only
// in the note as sent and blanked out before the rest is folded and judged.
func refuseLinkLikeNote(note string) error {
	folded := foldNote(note)
	if strings.ContainsAny(folded, "<>") || strings.Contains(folded, "](") || strings.Contains(folded, "://") {
		return fmt.Errorf("%w: note may not contain a link or markup", ErrInvalidArgument)
	}
	rest := foldNote(withoutEmailAddresses(note))
	if strings.Contains(rest, "@") {
		return fmt.Errorf("%w: note may hold an email address only in plain ASCII, with no dot before the at sign", ErrInvalidArgument)
	}
	if hasSchemeBeforeText(folded) {
		return fmt.Errorf("%w: note may not contain a link: a word directly followed by a colon and text", ErrInvalidArgument)
	}
	if hasDottedWord(rest) {
		return fmt.Errorf("%w: note may hold no web addresses or dotted words", ErrInvalidArgument)
	}
	if hasPhoneNumber(folded) {
		return fmt.Errorf("%w: note may not contain a phone number or another run of %d or more digits", ErrInvalidArgument, notePhoneDigits)
	}
	return nil
}

// notePhoneDigits is how many digits, with only phone punctuation between
// them, read as a phone number.
const notePhoneDigits = 7

// withoutEmailAddresses is note with each word that is a plain ASCII email
// address (noteEmailAddress) replaced by a space. A word is a run of letters,
// marks, numbers and "-", ".", "_", "+", "@", judged without its leading and
// trailing "-", ".", "_" and "+", so a full stop ending a sentence does not
// stop an address ending it from counting.
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
		if isNoteLabelRune(r) || strings.ContainsRune("-._+@", r) {
			continue
		}
		blank(i)
		b.WriteRune(r)
		word = i + utf8.RuneLen(r)
	}
	blank(len(note))
	return b.String()
}

// noteEmailAddress reports whether word is a plain ASCII email address: one
// "@" between a local part of ASCII letters, digits, "_", "+" and "-" only (no
// dot, so "www.example.com@example.org" is not one) and a domain of two or
// more dot-separated labels of ASCII letters, digits and "-", the last of two
// or more letters.
func noteEmailAddress(word string) bool {
	local, domain, ok := strings.Cut(word, "@")
	if !ok || local == "" || strings.ContainsFunc(local, func(r rune) bool { return !isASCIIAlnum(r) && !strings.ContainsRune("_+-", r) }) {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || strings.ContainsFunc(label, func(r rune) bool { return !isASCIIAlnum(r) && r != '-' }) {
			return false
		}
	}
	last := labels[len(labels)-1]
	return len(last) >= 2 && !strings.ContainsFunc(last, func(r rune) bool { return !isASCIIAlnum(r) || r >= '0' && r <= '9' })
}

// foldNote is note in the form refuseLinkLikeNote judges: without the
// zero-width joiner and non-joiner, which normalizeText admits but which would
// split a word without showing it; compatibility-normalized (NFKC, which
// writes fullwidth, circled and mathematical characters as the ones they
// imitate, a fullwidth full stop as "." and a halfwidth ideographic one as
// the ideographic full stop); lower-cased; and with the ideographic full
// stop, which IDNA reads as a dot, written as one unless a CJK character
// (isCJKRune) is on each side of it, where it ends a sentence instead.
func foldNote(note string) string {
	note = strings.NewReplacer("\u200c", "", "\u200d", "").Replace(note)
	runes := []rune(strings.ToLower(norm.NFKC.String(note)))
	for i, r := range runes {
		if r == ideographicFullStop && (i == 0 || i == len(runes)-1 || !isCJKRune(runes[i-1]) || !isCJKRune(runes[i+1])) {
			runes[i] = '.'
		}
	}
	return string(runes)
}

// ideographicFullStop is U+3002, which NFKC also makes of the halfwidth one.
const ideographicFullStop = '\u3002'

// isCJKRune reports whether r is a character of Chinese, Japanese or Korean
// writing: of the Han, Hiragana, Katakana, Hangul or Bopomofo script, or the
// prolonged sound mark, which Unicode assigns to no one script but which ends
// Japanese words.
func isCJKRune(r rune) bool {
	return unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul, unicode.Bopomofo) || r == '\u30fc'
}

// noteSchemeRE matches the shape of a URL scheme and its colon.
var noteSchemeRE = regexp.MustCompile(`[a-z][a-z0-9+.\-]*:`)

// hasSchemeBeforeText reports whether folded holds a scheme's shape
// (noteSchemeRE) directly followed by a character other than a space.
func hasSchemeBeforeText(folded string) bool {
	for _, m := range noteSchemeRE.FindAllStringIndex(folded, -1) {
		if r, size := utf8.DecodeRuneInString(folded[m[1]:]); size > 0 && !unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// hasDottedWord reports whether folded holds a "." with a letter, mark or
// number directly on each side.
func hasDottedWord(folded string) bool {
	runes := []rune(folded)
	for i := 1; i < len(runes)-1; i++ {
		if runes[i] == '.' && isNoteLabelRune(runes[i-1]) && isNoteLabelRune(runes[i+1]) {
			return true
		}
	}
	return false
}

// hasPhoneNumber reports whether folded holds notePhoneDigits or more digits
// with nothing but spaces, "-", ".", "(", ")" and "+" between them.
func hasPhoneNumber(folded string) bool {
	digits := 0
	for _, r := range folded {
		switch {
		case unicode.IsDigit(r):
			digits++
			if digits >= notePhoneDigits {
				return true
			}
		case unicode.IsSpace(r) || strings.ContainsRune("-.()+", r):
		default:
			digits = 0
		}
	}
	return false
}

// isNoteLabelRune reports whether r is a letter, a mark or a number, of any
// script: what a domain label is made of. A letter's combining marks count,
// as a label in an Indic script needs them.
func isNoteLabelRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsNumber(r)
}

func isASCIIAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}
