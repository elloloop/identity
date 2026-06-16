package agegate

import (
	"testing"
	"time"
)

var refNow = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

func dobYearsAgo(years, monthsOffset int) int64 {
	t := refNow.AddDate(-years, monthsOffset, 0)
	return t.UnixMilli()
}

func TestNoop_AlwaysAdultNonMinor(t *testing.T) {
	d := NewNoop()
	if d.Enabled() {
		t.Fatal("noop must be disabled")
	}
	if d.Name() != "noop" {
		t.Fatalf("name = %q", d.Name())
	}
	// Even a 5-year-old DOB classifies as unknown/non-minor under noop.
	dec := d.Determine(dobYearsAgo(5, 0), refNow)
	if dec.IsMinor || dec.HasDOB || dec.Band != BandUnknown {
		t.Fatalf("noop decision = %+v", dec)
	}
}

func TestThreshold_InvalidConfig(t *testing.T) {
	if _, err := NewThreshold(-1, 18); err == nil {
		t.Fatal("expected error for negative childMaxAge")
	}
	if _, err := NewThreshold(18, 18); err == nil {
		t.Fatal("expected error for adultAge <= childMaxAge")
	}
	if _, err := NewThreshold(12, 18); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestThreshold_Bands(t *testing.T) {
	d, err := NewThreshold(12, 18)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Enabled() || d.Name() != "threshold" {
		t.Fatalf("enabled/name wrong: %v %q", d.Enabled(), d.Name())
	}

	cases := []struct {
		name     string
		dobMs    int64
		wantBand AgeBand
		wantMin  bool
		wantHas  bool
	}{
		{"unknown-zero", 0, BandUnknown, false, false},
		{"future-dob", refNow.AddDate(1, 0, 0).UnixMilli(), BandUnknown, false, false},
		{"age-8-child", dobYearsAgo(8, 0), BandChild, true, true},
		{"age-12-child-boundary", dobYearsAgo(12, 0), BandChild, true, true},
		{"age-13-teen", dobYearsAgo(13, 0), BandTeen, true, true},
		{"age-17-teen", dobYearsAgo(17, 0), BandTeen, true, true},
		{"age-18-adult-boundary", dobYearsAgo(18, 0), BandAdult, false, true},
		{"age-40-adult", dobYearsAgo(40, 0), BandAdult, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := d.Determine(tc.dobMs, refNow)
			if dec.Band != tc.wantBand || dec.IsMinor != tc.wantMin || dec.HasDOB != tc.wantHas {
				t.Fatalf("got %+v, want band=%s minor=%v has=%v", dec, tc.wantBand, tc.wantMin, tc.wantHas)
			}
		})
	}
}

func TestThreshold_BirthdayNotYetThisYear(t *testing.T) {
	d, _ := NewThreshold(12, 18)
	// DOB exactly 18 years ago but +1 month means the 18th birthday is one
	// month in the future, so the user is still 17 (TEEN/minor).
	dob := refNow.AddDate(-18, 1, 0).UnixMilli()
	dec := d.Determine(dob, refNow)
	if dec.Band != BandTeen || !dec.IsMinor {
		t.Fatalf("expected teen/minor just before 18th birthday, got %+v", dec)
	}
}
