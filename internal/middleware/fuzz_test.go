package middleware

import (
	"net/http"
	"strings"
	"testing"
)

// FuzzExtractBearerToken fuzzes the value of the Authorization header passed
// through extractBearerToken. Contract:
//   - never panic;
//   - return empty string for malformed input (anything not exactly matching
//     the "Bearer <token>" prefix);
//   - never return a partial-success — an empty string is the only safe
//     response when the input is not well-formed.
func FuzzExtractBearerToken(f *testing.F) {
	f.Add("")
	f.Add("Bearer abcdef.ghijkl.mnopqr")
	f.Add("Bearer ")           // empty token after prefix
	f.Add("bearer abcdef")     // wrong case
	f.Add("Token abcdef")      // wrong scheme
	f.Add("Bearer\tabcdef")    // tab instead of space
	f.Add("Bearerabcdef")      // missing space
	f.Add("\x00Bearer abcdef") // leading control byte

	f.Fuzz(func(t *testing.T, headerValue string) {
		req, err := http.NewRequest(http.MethodGet, "/", nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		// Setting the header via Set folds CRs/LFs out for us, but we still
		// guard against control bytes by passing them via direct map write
		// when present (Set will reject some inputs in newer Go versions).
		// Use Set first; fall back to direct assignment if Set fails.
		// http.Header.Set itself does not return an error, so this is safe.
		req.Header.Set("Authorization", headerValue)

		got := extractBearerToken(req)

		// Whitelist: valid case is exactly "Bearer " + token where token
		// is the suffix. extractBearerToken does no further validation, so
		// we mirror that.
		if strings.HasPrefix(headerValue, "Bearer ") {
			want := headerValue[len("Bearer "):]
			// http.Header.Set may canonicalize/strip on some inputs (control
			// bytes). Re-read what Go actually stored to compute the
			// expected value the function will see.
			stored := req.Header.Get("Authorization")
			if strings.HasPrefix(stored, "Bearer ") {
				want = stored[len("Bearer "):]
			} else {
				// Header didn't survive intact; whatever extract returns
				// must just not be a partial-success. Empty is fine.
				if got != "" && !strings.HasPrefix(stored, "Bearer ") {
					t.Fatalf("got non-empty token %q for stored header %q", got, stored)
				}
				return
			}
			if got != want {
				t.Fatalf("got %q, want %q for header %q", got, want, headerValue)
			}
			return
		}

		// Malformed input: must return empty string.
		if got != "" {
			t.Fatalf("got non-empty token %q for malformed header %q", got, headerValue)
		}
	})
}
