package identityserver

import (
	"context"
	"testing"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestAccountClassificationNativeLiveStanding(t *testing.T) {
	client, repo, pair := nativeChildFixture(t)
	req := &identitypb.ClassifyAccountsRequest{UserIds: []string{pair.GuardianUserId, pair.ChildUserId}}
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-project-key", "pk_native", "x-account-classifier-key", "ak_native.fixture-secret"))
	result, err := client.ClassifyAccounts(ctx, req)
	require.NoError(t, err)
	require.Equal(t, identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_ACTIVE_KNOWN_ADULT, result.Accounts[0].Classification)
	require.Equal(t, identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_ACTIVE_KNOWN_MINOR, result.Accounts[1].Classification)
	require.NoError(t, repo.UpdateUser(context.Background(), pair.ChildUserId, map[string]any{"status": service.StatusPendingDeletion}))
	result, err = client.ClassifyAccounts(ctx, req)
	require.NoError(t, err)
	require.Equal(t, identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_DENIED, result.Accounts[1].Classification)
	for _, key := range []string{"", "pk_invalid", "pk_other", "pk_empty"} {
		bad := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-project-key", key, "x-account-classifier-key", "ak_native.fixture-secret"))
		_, err = client.ClassifyAccounts(bad, req)
		require.Equal(t, codes.Unauthenticated, status.Code(err))
	}
	bad := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-project-key", "pk_error", "x-account-classifier-key", "ak_native.fixture-secret"))
	_, err = client.ClassifyAccounts(bad, req)
	require.Equal(t, codes.Unavailable, status.Code(err))
}
