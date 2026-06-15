//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// TestRedesign_LoginPolicy_Enforced drives a domain to CLAIMED via the verify
// flow, sets a LoginPolicy that allows ONLY password, then asserts a user on
// that domain can PasswordLogin but is DENIED an email_otp login.
func TestRedesign_LoginPolicy_Enforced(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()

	policyDomain := claimDomainWithPolicy(t, h, "password")

	// A user on the claimed, password-only domain.
	user := fmt.Sprintf("member-%d@%s", time.Now().UnixNano(), policyDomain)
	if _, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    user,
		Password: validPassword,
	})); err != nil {
		t.Fatalf("PasswordSignup on policy domain: %v", err)
	}

	// Password login is allowed by the policy.
	if _, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    user,
		Password: validPassword,
	})); err != nil {
		t.Fatalf("PasswordLogin under password-only policy: want success, got %v", err)
	}

	// Email-OTP login is denied by the policy. Enforcement is at the
	// complete/verify step (after proof of email control), so request the
	// code, then assert VerifyEmailLoginCode is PermissionDenied.
	h.Mailer.Reset()
	if _, err := h.Client.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{
		Email: user,
	})); err != nil {
		t.Fatalf("RequestEmailLoginCode: %v", err)
	}
	code := extractRedesignLoginCode(t, h)
	_, err := h.Client.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{
		Email: user,
		Code:  code,
	}))
	if err == nil {
		t.Fatal("VerifyEmailLoginCode under password-only policy: want PermissionDenied, got nil")
	}
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("email_otp denial code = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

// TestRedesign_LoginPolicy_NoPolicyNoRestriction asserts a claimed tenant with
// NO LoginPolicy imposes no restriction: both password and email_otp succeed.
func TestRedesign_LoginPolicy_NoPolicyNoRestriction(t *testing.T) {
	h := startRedesignHarness(t)
	ctx := context.Background()

	// Claim a domain but set NO policy (empty methods → no policy row).
	domain := claimDomainWithPolicy(t, h, "")

	user := fmt.Sprintf("free-%d@%s", time.Now().UnixNano(), domain)
	if _, err := h.Client.PasswordSignup(ctx, connect.NewRequest(&identitypb.PasswordSignupRequest{
		Email:    user,
		Password: validPassword,
	})); err != nil {
		t.Fatalf("PasswordSignup: %v", err)
	}

	if _, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    user,
		Password: validPassword,
	})); err != nil {
		t.Fatalf("PasswordLogin with no policy: %v", err)
	}

	if _, err := h.Client.RequestEmailLoginCode(ctx, connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{
		Email: user,
	})); err != nil {
		t.Fatalf("RequestEmailLoginCode: %v", err)
	}
	code := extractRedesignLoginCode(t, h)
	if _, err := h.Client.VerifyEmailLoginCode(ctx, connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{
		Email: user,
		Code:  code,
	})); err != nil {
		t.Fatalf("VerifyEmailLoginCode with no policy: want success, got %v", err)
	}
}

// claimDomainWithPolicy creates an owner, a tenant, and a fresh domain it
// verifies via the real CreateDomain→VerifyDomain RPC flow (so the domain is
// genuinely VERIFIED and the tenant genuinely CLAIMED), then sets a
// LoginPolicy with allowedMethods. An empty allowedMethods sets NO policy
// (the "no restriction" case). Returns the verified domain name.
func claimDomainWithPolicy(t *testing.T, h *RedesignHarness, allowedMethods string) string {
	t.Helper()
	ctx := context.Background()

	caller := signupOwner(t, h, "policy")
	domain := fmt.Sprintf("policy-%d.com", time.Now().UnixNano())

	created, err := caller.client.CreateDomain(ctx, connect.NewRequest(&identitypb.CreateDomainRequest{
		TenantId:           caller.tenantID,
		Domain:             domain,
		VerificationMethod: service.DomainVerificationDNSTXT,
	}))
	if err != nil {
		t.Fatalf("claimDomainWithPolicy CreateDomain: %v", err)
	}
	h.DNS.publish(created.Msg.GetDnsTxtName(), created.Msg.GetDnsTxtValue())
	if _, err := caller.client.VerifyDomain(ctx, connect.NewRequest(&identitypb.VerifyDomainRequest{
		DomainId: created.Msg.GetDomain().GetId(),
	})); err != nil {
		t.Fatalf("claimDomainWithPolicy VerifyDomain: %v", err)
	}

	if strings.TrimSpace(allowedMethods) != "" {
		if _, err := h.Stores.policies.UpsertLoginPolicy(ctx, &service.LoginPolicy{
			ProjectID:      h.ProjectID,
			TenantID:       caller.tenantID,
			AllowedMethods: allowedMethods,
		}); err != nil {
			t.Fatalf("claimDomainWithPolicy UpsertLoginPolicy: %v", err)
		}
	}
	return domain
}

// extractRedesignLoginCode pulls the 6-digit OTP from the most recent code
// email the harness mailer captured.
func extractRedesignLoginCode(t *testing.T, h *RedesignHarness) string {
	t.Helper()
	sent := h.Mailer.Sent()
	if len(sent) == 0 {
		t.Fatal("no code email captured")
	}
	body := sent[len(sent)-1].Text
	for _, line := range strings.Split(body, "\n") {
		s := strings.TrimSpace(line)
		if len(s) != 6 {
			continue
		}
		allDigits := true
		for _, r := range s {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return s
		}
	}
	t.Fatalf("no 6-digit code in body: %q", body)
	return ""
}
