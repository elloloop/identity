package service

// FoldEmail returns the key under which two account email addresses are the
// same address: ASCII letters fold to lower case and every other byte is kept
// as it is. Every driver matches and de-duplicates account emails under this
// one rule, and so does any service code that pairs a presented address with
// a stored one.
//
// The rule is ASCII-only because it is the only case folding all three
// stores evaluate identically. Postgres lower() folds by the database's
// locale — ASCII-only under C, most of Unicode under en_US.UTF-8 — SQLite's
// built-in lower() is ASCII-only, and Go's strings.ToLower is Unicode. A
// Unicode rule would also merge distinct addresses: U+212A KELVIN SIGN lowers
// to an ASCII "k", so a different address would resolve to an existing
// account. Postgres stores the key as users.email_fold,
// lower(email COLLATE "C"); SQLite computes it with its built-in lower().
func FoldEmail(email string) string {
	i := 0
	for i < len(email) && !isASCIIUpper(email[i]) {
		i++
	}
	if i == len(email) {
		return email
	}
	b := []byte(email)
	for ; i < len(b); i++ {
		if isASCIIUpper(b[i]) {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func isASCIIUpper(c byte) bool {
	return 'A' <= c && c <= 'Z'
}
