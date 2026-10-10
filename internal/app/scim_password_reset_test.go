package app

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passwords"
)

type capturedMail struct {
	mu   sync.Mutex
	sent []email.Message
}

func (c *capturedMail) Send(_ context.Context, m email.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, m)
	return nil
}

var resetLinkRe = regexp.MustCompile(`https?://\S+`)

// A reset link mailed before a SCIM write moved the account to another mailbox
// must not reset the password: whoever keeps the old mailbox has no way back in.
func TestSCIM_EmailChangeVoidsAnOutstandingPasswordResetLink(t *testing.T) {
	h, repo := newSCIMTestHandler(t, true)
	ctx := context.Background()
	const oldPassword = "OldStr0ng!Pass"
	hash, err := passwords.Hash(oldPassword)
	if err != nil {
		t.Fatal(err)
	}
	id, err := repo.CreateUser(ctx, &service.User{
		Email: "before@example.com", EmailVerified: true, EmailVerifiedAt: 1,
		PasswordHash: hash, Status: "active",
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := newTestConfig()
	cfg.DefaultProjectID = testSCIMProjectID
	cfg.AppBaseURL = "https://app.example.test"
	cfg.SMTPFrom = "no-reply@example.test"
	cfg.EmailTokenExpirySeconds = 3600
	mail := &capturedMail{}
	auth := service.NewAuthService(repo, cfg, jwttest.NewSigner(t, "scim-reset"), nil,
		audit.NewLogger(nil, "test", zap.NewNop()),
		[]byte("01234567890123456789012345678901"), []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		mail, nil, zap.NewNop())
	if err := auth.RequestPasswordReset(ctx, "before@example.com", service.EmailLinkParams{}); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if len(mail.sent) != 1 {
		t.Fatalf("sent %d mails, want 1", len(mail.sent))
	}
	link, err := url.Parse(resetLinkRe.FindString(mail.sent[0].Text))
	if err != nil {
		t.Fatalf("reset link: %v", err)
	}
	token := link.Query().Get("token")
	if token == "" {
		t.Fatalf("no token in reset mail: %q", mail.sent[0].Text)
	}

	rec := scimReq(t, h, http.MethodPatch, "/scim/v2/Users/"+id, testSCIMToken, `{
		"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"userName","value":"after@example.com"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("SCIM PATCH status = %d body=%s", rec.Code, rec.Body.String())
	}

	if err := auth.ConfirmPasswordReset(ctx, token, "NewStr0ng!Pass"); !errors.Is(err, service.ErrUnauthenticated) {
		t.Fatalf("ConfirmPasswordReset after a SCIM email change: want ErrUnauthenticated, got %v", err)
	}
	u, err := repo.GetUser(ctx, id)
	if err != nil || u == nil {
		t.Fatalf("GetUser: %v %v", u, err)
	}
	if !passwords.Verify(oldPassword, u.PasswordHash) {
		t.Fatal("a link mailed to the old address reset the password")
	}
}
