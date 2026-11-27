package app

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/elloloop/identity/internal/service"
)

// An owner's standing that could not be read is a server error the client
// may retry, never invalid_grant, which would tell it to drop the grant.
func TestOAuthProtocolError_StandingUnreadIsRetryable(t *testing.T) {
	var got *oidc.Error
	require.True(t, errors.As(oauthProtocolError(fmt.Errorf("%w: %w: unread", service.ErrUnavailable, service.ErrAccountNotActive)), &got))
	require.Equal(t, oidc.ServerError, got.ErrorType)
	require.True(t, errors.As(oauthProtocolError(fmt.Errorf("%w: suspended", service.ErrAccountNotActive)), &got))
	require.Equal(t, oidc.InvalidGrant, got.ErrorType)
}
