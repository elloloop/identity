package connect

import (
	"math"
	"testing"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
)

// TestIntToProtoInt32 covers the bounds clamp used when converting an
// in-memory int (counts, limits) to the proto int32 wire type. The
// overflow/underflow branches guard a #nosec G115 narrowing conversion,
// so they are exactly the paths worth proving.
func TestIntToProtoInt32(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int32
	}{
		{"zero", 0, 0},
		{"small positive", 42, 42},
		{"small negative", -42, -42},
		{"max int32 stays", math.MaxInt32, math.MaxInt32},
		{"min int32 stays", math.MinInt32, math.MinInt32},
		{"overflow clamps to max", math.MaxInt32 + 1, math.MaxInt32},
		{"underflow clamps to min", math.MinInt32 - 1, math.MinInt32},
		{"large overflow clamps to max", math.MaxInt64, math.MaxInt32},
		{"large underflow clamps to min", math.MinInt64, math.MinInt32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := intToProtoInt32(tc.in); got != tc.want {
				t.Fatalf("intToProtoInt32(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestUserStatusRoundTrip covers the service-string <-> proto-enum mapping
// for every known UserStatus, including the COPPA pending_parental_consent
// state, plus the unknown -> unspecified / "" fallbacks on both sides.
func TestUserStatusRoundTrip(t *testing.T) {
	cases := []struct {
		str string
		pb  identitypb.UserStatus
	}{
		{"active", identitypb.UserStatus_USER_STATUS_ACTIVE},
		{"invited", identitypb.UserStatus_USER_STATUS_INVITED},
		{"deactivated", identitypb.UserStatus_USER_STATUS_DEACTIVATED},
		{"suspended", identitypb.UserStatus_USER_STATUS_SUSPENDED},
		{"pending_parental_consent", identitypb.UserStatus_USER_STATUS_PENDING_PARENTAL_CONSENT},
	}
	for _, tc := range cases {
		t.Run(tc.str, func(t *testing.T) {
			if got := userStatusToProto(tc.str); got != tc.pb {
				t.Fatalf("userStatusToProto(%q) = %v, want %v", tc.str, got, tc.pb)
			}
			if got := protoToUserStatusString(tc.pb); got != tc.str {
				t.Fatalf("protoToUserStatusString(%v) = %q, want %q", tc.pb, got, tc.str)
			}
		})
	}

	t.Run("unknown string -> unspecified", func(t *testing.T) {
		if got := userStatusToProto("nonsense"); got != identitypb.UserStatus_USER_STATUS_UNSPECIFIED {
			t.Fatalf("userStatusToProto(unknown) = %v, want UNSPECIFIED", got)
		}
	})
	t.Run("unspecified enum -> empty string", func(t *testing.T) {
		if got := protoToUserStatusString(identitypb.UserStatus_USER_STATUS_UNSPECIFIED); got != "" {
			t.Fatalf("protoToUserStatusString(UNSPECIFIED) = %q, want \"\"", got)
		}
	})
}

// TestAgeBandToProto covers the COPPA age-band string -> proto-enum mapping
// for every band plus the unknown/empty -> unspecified fallback.
func TestAgeBandToProto(t *testing.T) {
	cases := []struct {
		in   string
		want identitypb.AgeBand
	}{
		{"CHILD", identitypb.AgeBand_AGE_BAND_CHILD},
		{"TEEN", identitypb.AgeBand_AGE_BAND_TEEN},
		{"ADULT", identitypb.AgeBand_AGE_BAND_ADULT},
		{"", identitypb.AgeBand_AGE_BAND_UNSPECIFIED},
		{"unknown", identitypb.AgeBand_AGE_BAND_UNSPECIFIED},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := ageBandToProto(tc.in); got != tc.want {
				t.Fatalf("ageBandToProto(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
