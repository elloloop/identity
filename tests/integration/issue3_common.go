//go:build integration || realpostgres

package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/passwords"
)

const issue3Password = "Sw0rdfish!42"

type issue3Harness struct {
	BaseURL string
	Client  identityconnectgen.IdentityServiceClient
	HTTP    *http.Client
	Repo    service.Repository
}

type issue3SilentMailer struct{}

func (issue3SilentMailer) Send(context.Context, email.Message) error { return nil }

type issue3BearerHTTPClient struct {
	base  *http.Client
	token string
}

func (b issue3BearerHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.Do(req)
}

func (h *issue3Harness) AuthedClient(accessToken string) identityconnectgen.IdentityServiceClient {
	return identityconnectgen.NewIdentityServiceClient(
		issue3BearerHTTPClient{base: h.HTTP, token: accessToken},
		h.BaseURL,
	)
}

func seedIssue3User(t *testing.T, h *issue3Harness, email, name, role, status, plainPassword string) string {
	t.Helper()

	email = strings.ToLower(email)
	passwordHash := ""
	if plainPassword != "" {
		var err error
		passwordHash, err = passwords.Hash(plainPassword)
		if err != nil {
			t.Fatalf("hash password for %s: %v", email, err)
		}
	}

	now := time.Now()
	id, err := h.Repo.CreateUser(context.Background(), &service.User{
		Email:        email,
		Name:         name,
		Role:         role,
		Status:       status,
		PasswordHash: passwordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("CreateUser(%s): %v", email, err)
	}
	waitForIssue3User(t, h, email, id)
	return id
}

func loginViaPassword(t *testing.T, h *issue3Harness, email, password string) *identitypb.PasswordLoginResponse {
	t.Helper()

	resp, err := h.Client.PasswordLogin(context.Background(), connect.NewRequest(&identitypb.PasswordLoginRequest{
		Email:    email,
		Password: password,
	}))
	if err != nil {
		t.Fatalf("PasswordLogin(%s): %v", email, err)
	}
	return resp.Msg
}

func newIssue3TestConfig() *config.Config {
	return &config.Config{
		DefaultTenantID: "test-tenant",
		// Open-signup deployment fixture (default-DENY requires an explicit mode).
		DefaultProjectAccessMode:      "open",
		AuthAllowLocal:                true,
		PasswordSignupEnabled:         true,
		PasswordResetEnabled:          true,
		JWTExpirySeconds:              900,
		RefreshExpirySeconds:          604800,
		LoginMaxFailedAttempts:        5,
		LoginLockoutSeconds:           900,
		LoginChallengeExpirySeconds:   300,
		PasskeyRPID:                   "localhost",
		PasskeyRPName:                 "IdentityIntegrationTests",
		PasskeyOrigin:                 "http://localhost:9002",
		PasskeyChallengeExpirySeconds: 300,
		QRLoginBaseURL:                "http://localhost:9002",
		QRLoginExpirySeconds:          300,
		TOTPIssuer:                    "Glassa Test",
		AllowedOrigins:                "http://localhost:9002",
		AppBaseURL:                    "https://app.test",
		EmailTokenExpirySeconds:       3600,
		SMTPFrom:                      "no-reply@test.local",
	}
}

func waitForIssue3User(t *testing.T, h *issue3Harness, email, wantID string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		user, err := h.Repo.FindUserByEmail(context.Background(), email)
		if err == nil && user != nil && user.ID == wantID {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("seeded user %s not visible via FindUserByEmail after write (id=%q err=%v user=%+v)", email, wantID, err, user)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func issue3Email(t *testing.T, email string) string {
	t.Helper()

	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		t.Fatalf("invalid issue3 email %q", email)
	}
	// Use '-' rather than '+' so the per-test slug doesn't get stripped
	// by the service-layer Gmail-style canonicalization (which drops
	// everything after '+' in the local part). The slug-via-hyphen
	// still gives every test a unique local part for isolation.
	return fmt.Sprintf("%s-%s%s", email[:at], issue3Slug(t.Name()), email[at:])
}

func issue3Slug(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
