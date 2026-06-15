package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

func TestHandler_RequestEmailLoginCode_AlwaysOK(t *testing.T) {
	h := newHarness(t)
	// Unknown email — anti-enumeration means a normal success response.
	_, err := h.client.RequestEmailLoginCode(context.Background(),
		withClientHeaders(connect.NewRequest(&identitypb.RequestEmailLoginCodeRequest{Email: "nobody@test.com"})))
	require.NoError(t, err)
}

func TestHandler_VerifyEmailLoginCode_HappyPath(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Seed a code directly with a known hash (the handler mailer is a
	// no-op in the harness, so we can't read the plaintext from email).
	_, err := h.repo.UpsertEmailLoginCode(ctx, &service.EmailLoginCodeRecord{
		Email: "otp@test.com", CodeHash: sha256Hex("123456"),
		ExpiresAt: 9_000_000_000_000, CreatedAt: 1, MaxAttempts: 5,
	})
	require.NoError(t, err)

	resp, err := h.client.VerifyEmailLoginCode(ctx,
		withClientHeaders(connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{
			Email: "otp@test.com", Code: "123456",
		})))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.AccessToken)
	assert.NotEmpty(t, resp.Msg.RefreshToken)
	assert.Equal(t, "otp@test.com", resp.Msg.User.Email)
}

func TestHandler_VerifyEmailLoginCode_WrongCodeUnauthenticated(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, err := h.repo.UpsertEmailLoginCode(ctx, &service.EmailLoginCodeRecord{
		Email: "otp2@test.com", CodeHash: sha256Hex("111111"),
		ExpiresAt: 9_000_000_000_000, CreatedAt: 1, MaxAttempts: 5,
	})
	require.NoError(t, err)

	_, err = h.client.VerifyEmailLoginCode(ctx,
		connect.NewRequest(&identitypb.VerifyEmailLoginCodeRequest{Email: "otp2@test.com", Code: "000000"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestHandler_RequestMagicLink_RejectsBadReturnTo(t *testing.T) {
	h := newHarness(t)
	_, err := h.client.RequestMagicLink(context.Background(),
		connect.NewRequest(&identitypb.RequestMagicLinkRequest{
			Email: "ml@test.com", ReturnTo: "https://evil.test/",
		}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestHandler_RedeemMagicLink_HappyPath(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, err := h.repo.CreateMagicLinkToken(ctx, &service.MagicLinkTokenRecord{
		TokenHash: sha256Hex("rawtok"), Email: "mlredeem@test.com", ReturnTo: "https://app.test/done",
		ExpiresAt: 9_000_000_000_000, CreatedAt: 1,
	})
	require.NoError(t, err)

	resp, err := h.client.RedeemMagicLink(ctx,
		withClientHeaders(connect.NewRequest(&identitypb.RedeemMagicLinkRequest{Token: "rawtok"})))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.AccessToken)
	assert.Equal(t, "https://app.test/done", resp.Msg.ReturnTo)
	assert.Equal(t, "mlredeem@test.com", resp.Msg.User.Email)
}

func TestHandler_RedeemMagicLink_ReplayUnauthenticated(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, err := h.repo.CreateMagicLinkToken(ctx, &service.MagicLinkTokenRecord{
		TokenHash: sha256Hex("rawtok2"), Email: "mlreplay@test.com", ReturnTo: "https://app.test/done",
		ExpiresAt: 9_000_000_000_000, CreatedAt: 1,
	})
	require.NoError(t, err)

	_, err = h.client.RedeemMagicLink(ctx,
		connect.NewRequest(&identitypb.RedeemMagicLinkRequest{Token: "rawtok2"}))
	require.NoError(t, err)
	_, err = h.client.RedeemMagicLink(ctx,
		connect.NewRequest(&identitypb.RedeemMagicLinkRequest{Token: "rawtok2"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}
