package service

// FoldEmail is the storage comparison rule for account emails: two addresses
// are the same stored address when their FoldEmail keys are equal. It lowers
// ASCII letters and keeps every other byte. Every driver matches and keeps
// addresses unique under it, and the service pairs rows a driver returned
// with the addresses that asked for them under it.
//
// It is not the service's normalization. The service canonicalizes an
// address before it reaches a store (CanonicalizeEmail, which also lowers
// non-ASCII letters); FoldEmail only makes the stores agree on the addresses
// they are given. It is ASCII-only because that is the one fold all three
// stores evaluate identically: Postgres lower() folds by the database's
// locale, SQLite's built-in lower() folds ASCII only. Postgres stores the key
// as users.email_fold, lower(email COLLATE "C"); SQLite computes it with its
// built-in lower().
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
