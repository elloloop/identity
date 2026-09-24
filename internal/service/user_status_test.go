package service

import "testing"

func TestIsActiveStatus(t *testing.T) {
	for _, tc := range []struct {
		status string
		want   bool
	}{
		{"", true},
		{StatusActive, true},
		{" Active ", true},
		{"invited", false},
		{StatusDeactivated, false},
		{"suspended", false},
		{StatusPendingDeletion, false},
		{StatusPendingParentalConsent, false},
	} {
		if got := isActiveStatus(tc.status); got != tc.want {
			t.Errorf("isActiveStatus(%q) = %v, want %v", tc.status, got, tc.want)
		}
	}
}
