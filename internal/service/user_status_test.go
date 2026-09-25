package service

import (
	"context"
	"errors"
	"testing"
)

func TestIsActiveStatus(t *testing.T) {
	for _, tc := range []struct {
		status string
		want   bool
	}{
		{"", true},
		{StatusActive, true},
		{"ACTIVE", true},
		{" active", false},
		{"active ", false},
		{" Active ", false},
		{" ", false},
		{StatusInvited, false},
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

func TestCheckAccountStatus_RejectsPaddedStatus(t *testing.T) {
	svc := newTestAuthService(t, newFakeRepo())
	for _, status := range []string{" active", "active ", "\tactive\n", " "} {
		err := svc.checkAccountStatus(context.Background(), &User{Status: status}, "", "")
		if !errors.Is(err, ErrAccountNotActive) {
			t.Errorf("checkAccountStatus(%q) = %v, want ErrAccountNotActive", status, err)
		}
	}
}

func TestDeleteMyAccount_RejectsPaddedStatus(t *testing.T) {
	ctx := context.Background()
	for _, status := range []string{" active", "active ", " "} {
		repo := newFakeRepo()
		svc := newTestProfileServiceForDeletion(repo, newRecordingAuditWriter())
		u := seedUser(repo, "padded@example.com", "hash", status)

		_, err := svc.DeleteMyAccount(ctx, u.ID, "")
		if !errors.Is(err, ErrAccountDeletionNotAllowed) {
			t.Errorf("DeleteMyAccount with status %q = %v, want ErrAccountDeletionNotAllowed", status, err)
		}
	}
}
