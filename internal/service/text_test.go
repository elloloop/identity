package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The joiners Persian, the Indic scripts and emoji sequences need are kept;
// the bidirectional overrides that make one name render as another, and the
// line and paragraph separators that break the line it is shown on, are not.
func TestNormalizeText_FormattingCharacters(t *testing.T) {
	for _, ok := range []string{"\u0645\u06cc\u200c\u062e\u0648\u0627\u0645", "\u0915\u094d\u200d\u0937", "Acme \U0001F468\u200d\U0001F4BB"} {
		got, err := normalizeText("name", ok, tenantNameMaxRunes)
		require.NoError(t, err, "%q", ok)
		assert.Equal(t, ok, got)
	}
	for _, bad := range []string{"Acme\u202egnp.exe", "Ac\u2066me", "Acme\u200b", "Acme\x00", "Ac\tme", "Acme\u2028Corp", "Acme\u2029Corp"} {
		_, err := normalizeText("name", bad, tenantNameMaxRunes)
		require.ErrorIs(t, err, ErrInvalidArgument, "%q", bad)
	}
}
