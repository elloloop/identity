package idv_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elloloop/identity/pkg/idv"
)

func TestStubProvider_Name(t *testing.T) {
	t.Parallel()
	if got := idv.NewStubProvider().Name(); got != "stub" {
		t.Fatalf("Name() = %q, want %q", got, "stub")
	}
}

func TestStubProvider_BeginVerification(t *testing.T) {
	t.Parallel()

	p := idv.NewStubProvider()
	sess, err := p.BeginVerification(context.Background(), idv.Request{UserID: "u-1"})
	if err != nil {
		t.Fatalf("BeginVerification: %v", err)
	}
	if sess.ProviderSessionID == "" {
		t.Fatal("ProviderSessionID is empty")
	}
	if sess.SessionToken == "" {
		t.Fatal("SessionToken is empty")
	}
	if sess.ExpiresAt.IsZero() || !sess.ExpiresAt.After(time.Now()) {
		t.Fatalf("ExpiresAt = %v; want future", sess.ExpiresAt)
	}

	// Two sessions get distinct identifiers.
	sess2, err := p.BeginVerification(context.Background(), idv.Request{UserID: "u-1"})
	if err != nil {
		t.Fatalf("BeginVerification 2: %v", err)
	}
	if sess.ProviderSessionID == sess2.ProviderSessionID {
		t.Fatal("two BeginVerification calls returned the same ProviderSessionID")
	}
}

func TestStubProvider_GetVerification_DefaultApproves(t *testing.T) {
	t.Parallel()

	p := idv.NewStubProvider()
	sess, err := p.BeginVerification(context.Background(), idv.Request{UserID: "u-1"})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	got, err := p.GetVerification(context.Background(), sess.ProviderSessionID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != idv.StatusApproved {
		t.Fatalf("Status = %q; want %q", got.Status, idv.StatusApproved)
	}
	if got.CompletedAt.IsZero() {
		t.Fatal("CompletedAt is zero on a resolved verdict")
	}
}

func TestStubProvider_GetVerification_ConfigurableVerdict(t *testing.T) {
	t.Parallel()

	p := idv.NewStubProvider()
	p.Verdict = idv.StatusRejected

	sess, err := p.BeginVerification(context.Background(), idv.Request{UserID: "u-1"})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	got, err := p.GetVerification(context.Background(), sess.ProviderSessionID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != idv.StatusRejected {
		t.Fatalf("Status = %q; want %q", got.Status, idv.StatusRejected)
	}
	if got.RejectionReason == "" {
		t.Fatal("RejectionReason is empty on a rejected verdict")
	}
}

func TestStubProvider_SetVerdict(t *testing.T) {
	t.Parallel()

	p := idv.NewStubProvider()
	sess, err := p.BeginVerification(context.Background(), idv.Request{UserID: "u-1"})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	p.SetVerdict(sess.ProviderSessionID, idv.StatusRejected, "doc_unreadable")

	got, err := p.GetVerification(context.Background(), sess.ProviderSessionID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != idv.StatusRejected || got.RejectionReason != "doc_unreadable" {
		t.Fatalf("Get = %+v; want rejected/doc_unreadable", got)
	}
}

func TestStubProvider_GetVerification_UnknownSession(t *testing.T) {
	t.Parallel()

	p := idv.NewStubProvider()
	_, err := p.GetVerification(context.Background(), "does-not-exist")
	if !errors.Is(err, idv.ErrSessionNotFound) {
		t.Fatalf("err = %v; want %v", err, idv.ErrSessionNotFound)
	}
}
