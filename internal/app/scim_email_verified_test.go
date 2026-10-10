package app

import (
	"context"
	"net/http"
	"testing"

	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
)

// An IdP asserts an account's address; it does not prove the user receives
// mail there. A SCIM write that moves a verified account to another mailbox
// leaves it unverified, and one that keeps the mailbox keeps the proof.
func TestSCIM_EmailChangeUnverifiesAnotherMailbox(t *testing.T) {
	cases := []struct {
		name, method, body string
		wantVerified       bool
	}{
		{"patch to another mailbox", http.MethodPatch, `{
			"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations":[{"op":"replace","path":"userName","value":"other@example.com"}]}`, false},
		{"put to another mailbox", http.MethodPut, `{
			"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName":"other@example.com","active":true}`, false},
		{"patch to the same mailbox", http.MethodPatch, `{
			"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations":[{"op":"replace","path":"userName","value":"FirstLast@gmail.com"}]}`, true},
		{"patch to a tagged gmail address", http.MethodPatch, `{
			"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations":[{"op":"replace","path":"userName","value":"firstlast+work@gmail.com"}]}`, true},
		{"put without an email change", http.MethodPut, `{
			"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName":"first.last@gmail.com","active":true}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, repo := newSCIMTestHandler(t, true)
			ctx := context.Background()
			id, err := repo.CreateUser(ctx, &service.User{
				Email: "first.last@gmail.com", EmailVerified: true, EmailVerifiedAt: 1, Status: "active",
			})
			if err != nil {
				t.Fatal(err)
			}
			rec := scimReq(t, h, tc.method, "/scim/v2/Users/"+id, testSCIMToken, tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
			}
			u, err := repo.GetUser(ctx, id)
			if err != nil || u == nil {
				t.Fatalf("GetUser: %v %v", u, err)
			}
			if u.EmailVerified != tc.wantVerified {
				t.Fatalf("email %q verified = %v, want %v", u.Email, u.EmailVerified, tc.wantVerified)
			}
			if !tc.wantVerified && u.EmailVerifiedAt != 0 {
				t.Fatalf("email_verified_at = %d, want 0", u.EmailVerifiedAt)
			}
		})
	}
}

// An account stored with a "+tag" outside Gmail is stored without it on its
// next SCIM write. The tag-less address is not provably the same mailbox, so
// the account reads unverified, even though the IdP sent the same address.
func TestSCIM_TaggedAddressOutsideGmailUnverifiesOnRewrite(t *testing.T) {
	h, repo := newSCIMTestHandler(t, true)
	ctx := context.Background()
	id, err := repo.CreateUser(ctx, &service.User{
		Email: "someone+work@example.com", EmailVerified: true, EmailVerifiedAt: 1, Status: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := scimReq(t, h, http.MethodPut, "/scim/v2/Users/"+id, testSCIMToken, `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"someone+work@example.com","active":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	u, err := repo.GetUser(ctx, id)
	if err != nil || u == nil {
		t.Fatalf("GetUser: %v %v", u, err)
	}
	if u.Email != "someone@example.com" || u.EmailVerified || u.EmailVerifiedAt != 0 {
		t.Fatalf("email %q verified %v at %d", u.Email, u.EmailVerified, u.EmailVerifiedAt)
	}
}

// An account that was never verified stays unverified through a change of
// mailbox; the write gains no verification time.
func TestSCIM_UnverifiedAccountStaysUnverified(t *testing.T) {
	h, repo := newSCIMTestHandler(t, true)
	ctx := context.Background()
	id, err := repo.CreateUser(ctx, &service.User{Email: "before@example.com", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	rec := scimReq(t, h, http.MethodPatch, "/scim/v2/Users/"+id, testSCIMToken, `{
		"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"userName","value":"after@example.com"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	u, err := repo.GetUser(ctx, id)
	if err != nil || u == nil {
		t.Fatalf("GetUser: %v %v", u, err)
	}
	if u.EmailVerified || u.EmailVerifiedAt != 0 {
		t.Fatalf("verified %v at %d", u.EmailVerified, u.EmailVerifiedAt)
	}
}

// A SCIM write that leaves the email unverified is audited against the
// account, without the address; one that keeps the mailbox is not.
func TestSCIM_EmailUnverifiedIsAudited(t *testing.T) {
	cases := []struct {
		name, method, body string
		wantAudit          bool
	}{
		{"patch to another mailbox", http.MethodPatch, `{
			"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations":[{"op":"replace","path":"userName","value":"other@example.com"}]}`, true},
		{"put to another mailbox", http.MethodPut, `{
			"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName":"other@example.com","active":true}`, true},
		{"patch to the same mailbox", http.MethodPatch, `{
			"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations":[{"op":"replace","path":"userName","value":"FirstLast@gmail.com"}]}`, false},
		{"patch without an email", http.MethodPatch, `{
			"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations":[{"op":"replace","path":"externalId","value":"ext-1"}]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, repo, _, aud := newSCIMObservedHandler(t)
			id, err := repo.CreateUser(context.Background(), &service.User{
				Email: "first.last@gmail.com", EmailVerified: true, EmailVerifiedAt: 1, Status: "active",
			})
			if err != nil {
				t.Fatal(err)
			}
			rec := scimReq(t, h, tc.method, "/scim/v2/Users/"+id, testSCIMToken, tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
			}
			var got []auditWrite
			for _, w := range aud.all() {
				if w.eventType == string(audit.EventEmailUnverified) {
					got = append(got, w)
				}
			}
			if !tc.wantAudit {
				if len(got) != 0 {
					t.Fatalf("email_unverified written for a write that kept the mailbox: %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("email_unverified writes = %+v, want one", got)
			}
			w := got[0]
			if w.projectID != testSCIMProjectID || w.data[fieldTarget] != id || w.data[fieldActor] != scimAuditActor {
				t.Fatalf("email_unverified entry = %+v, want target %q by %q under %q", w, id, scimAuditActor, testSCIMProjectID)
			}
			details, _ := w.data[fieldDetails].(string)
			if details != `{"source":"scim","was_verified":true}` {
				t.Fatalf("details = %s", details)
			}
		})
	}
}
