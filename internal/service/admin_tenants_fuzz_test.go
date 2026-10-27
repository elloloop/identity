package service

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzDecodeTenantCursor: any string an operator sends as a cursor either is
// refused with ErrInvalidArgument or decodes to a position the store can
// query, one whose id is valid UTF-8 with no NUL and that encodes back to
// the same position.
func FuzzDecodeTenantCursor(f *testing.F) {
	for _, seed := range []string{
		"",
		"not base64!",
		encodeTenantCursor(TenantPosition{CreatedAtMs: 1_700_000_000_000, ID: "t-1"}),
		encodeTenantCursor(TenantPosition{CreatedAtMs: 5, ID: "id.with.dots"}),
		encodeTenantCursor(TenantPosition{CreatedAtMs: 12, ID: "t-\x00-1"}),
		encodeTenantCursor(TenantPosition{CreatedAtMs: 12, ID: "t-\xff\xfe"}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, cursor string) {
		p, err := decodeTenantCursor(cursor)
		if err != nil {
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("decode(%q): err = %v, want ErrInvalidArgument", cursor, err)
			}
			return
		}
		if p.ID == "" || p.CreatedAtMs < 0 || !utf8.ValidString(p.ID) || strings.ContainsRune(p.ID, 0) {
			t.Fatalf("decode(%q) = %+v, which the store cannot query", cursor, p)
		}
		again, err := decodeTenantCursor(encodeTenantCursor(p))
		if err != nil || again != p {
			t.Fatalf("decode(encode(%+v)) = %+v, %v", p, again, err)
		}
	})
}
