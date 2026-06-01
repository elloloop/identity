package connect

import (
	"math"
	"testing"
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
