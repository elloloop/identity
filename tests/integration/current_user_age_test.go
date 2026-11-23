//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt"
)

func TestGetCurrentUser_PersistedAgeProfileBothCodecs(t *testing.T) {
	t.Parallel()
	var projectID string
	h := StartServer(t, WithConfig(func(cfg *config.Config) {
		cfg.AgeGateEnabled = true
		cfg.AgeGateChildMaxAge = 12
		cfg.AgeGateAdultAge = 18
		projectID = cfg.DefaultProjectID
	}))
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		dob   *int64
		band  identitypb.AgeBand
		minor bool
	}{
		{name: "unknown", band: identitypb.AgeBand_AGE_BAND_UNSPECIFIED},
		{name: "child", dob: new(time.Now().AddDate(-8, 0, 0).UnixMilli()), band: identitypb.AgeBand_AGE_BAND_CHILD, minor: true},
		{name: "teen", dob: new(time.Now().AddDate(-16, 0, 0).UnixMilli()), band: identitypb.AgeBand_AGE_BAND_TEEN, minor: true},
		{name: "adult", dob: new(time.Now().AddDate(-30, 0, 0).UnixMilli()), band: identitypb.AgeBand_AGE_BAND_ADULT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Seed the backing store so a fresh request cannot reuse a signup's derived fields.
			id, err := h.Repo.CreateUser(ctx, &service.User{Email: tc.name + "@example.test", Kind: service.UserKindPerson, Status: service.StatusActive, Role: "member", DateOfBirthMs: tc.dob})
			require.NoError(t, err)
			token, err := h.Signer.SignAccessToken(ctx, jwt.Claims{Sub: id, Tenant: h.TenantID, Project: projectID, Role: "member"}, time.Minute)
			require.NoError(t, err)
			for _, codec := range []struct {
				name    string
				options []connect.ClientOption
			}{
				{name: "protobuf"},
				{name: "json", options: []connect.ClientOption{connect.WithProtoJSON()}},
			} {
				t.Run(codec.name, func(t *testing.T) {
					client := identityconnectgen.NewIdentityServiceClient(bearerHTTPClient{base: h.HTTP, token: token}, h.BaseURL, codec.options...)
					response, err := client.GetCurrentUser(ctx, connect.NewRequest(&identitypb.GetCurrentUserRequest{}))
					require.NoError(t, err)
					user := response.Msg.GetUser()
					require.Equal(t, id, user.GetId())
					require.Equal(t, identitypb.UserKind_USER_KIND_PERSON, user.GetKind())
					require.Equal(t, identitypb.UserStatus_USER_STATUS_ACTIVE, user.GetStatus())
					require.Equal(t, tc.band, user.GetAgeBand())
					require.Equal(t, tc.minor, user.GetIsMinor())
					require.Equal(t, tc.dob, user.DateOfBirthUnixMs)
				})
			}
		})
	}
}
