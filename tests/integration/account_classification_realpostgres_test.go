//go:build integration && realpostgres

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/config"
	identityconnect "github.com/elloloop/identity/internal/connect"
	"github.com/elloloop/identity/internal/middleware"
	"github.com/elloloop/identity/internal/service"
)

func TestAccountClassificationRealPostgres(t *testing.T) {
	for _, mode := range []config.RevocationMode{config.RevocationModeTTL, config.RevocationModeSession} {
		for _, codec := range []struct {
			name    string
			options []connect.ClientOption
		}{
			{name: "protobuf"},
			{name: "json", options: []connect.ClientOption{connect.WithProtoJSON()}},
		} {
			t.Run(fmt.Sprintf("%s/%s", mode, codec.name), func(t *testing.T) {
				h := startRedesignHarnessWith(t, func(cfg *config.Config) {
					cfg.AgeGateEnabled = true
					cfg.AgeGateChildMaxAge = 12
					cfg.AgeGateAdultAge = 18
					cfg.RevocationMode = mode
				})
				ctx := context.Background()
				admin := h.adminClient(harnessAdminSecret)
				mint := func(project, kind string) *identitypb.AdminCreateProjectCredentialResponse {
					t.Helper()
					result, err := admin.AdminCreateProjectCredential(ctx, connect.NewRequest(&identitypb.AdminCreateProjectCredentialRequest{ProjectId: project, Kind: kind}))
					require.NoError(t, err)
					return result.Msg
				}
				classifier := mint(h.ProjectID, service.CredentialKindAccountClassifier)
				routing := mint(h.ProjectID, service.CredentialKindPublishable)
				client := func(key, route string) identityconnectgen.IdentityServiceClient {
					return identityconnectgen.NewIdentityServiceClient(&redesignHTTPClient{base: h.HTTP, headers: map[string]string{
						identityconnect.AccountClassifierKeyHeader: key, middleware.ProjectKeyHeader: route,
					}}, h.BaseURL, codec.options...)
				}
				users := h.Stores.users.WithProject(h.ProjectID)
				seed := func(name string, dob *int64) string {
					t.Helper()
					id, err := users.CreateUser(ctx, &service.User{Username: name, Email: name + "@example.test", Name: "Private profile", Kind: service.UserKindPerson, Status: service.StatusActive, DateOfBirthMs: dob})
					require.NoError(t, err)
					return id
				}
				adult := seed("adult", new(time.Now().AddDate(-35, 0, 0).UnixMilli()))
				minor := seed("minor", new(time.Now().AddDate(-8, 0, 0).UnixMilli()))
				young := seed("young", new(time.Now().AddDate(-19, 0, 0).UnixMilli()))
				unknown := seed("unknown", nil)
				read := func(ids ...string) []*identitypb.ClassifiedAccount {
					t.Helper()
					result, err := client(classifier.GetRawKey(), routing.GetPublicId()).ClassifyAccounts(ctx, connect.NewRequest(&identitypb.ClassifyAccountsRequest{UserIds: ids}))
					require.NoError(t, err)
					require.Len(t, result.Msg.Accounts, len(ids))
					for i, id := range ids {
						require.Equal(t, id, result.Msg.Accounts[i].UserId)
					}
					return result.Msg.Accounts
				}
				got := read(adult, minor)
				require.Equal(t, identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_ACTIVE_KNOWN_ADULT, got[0].Classification)
				require.Equal(t, identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_ACTIVE_KNOWN_MINOR, got[1].Classification)
				got = read(unknown, "missing")
				require.Equal(t, identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_DENIED, got[0].Classification)
				require.Equal(t, identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_DENIED, got[1].Classification)

				_, version, err := h.Stores.controlPlane.GetProjectConfig(ctx, h.ProjectID)
				require.NoError(t, err)
				_, _, err = h.Stores.controlPlane.UpdateProjectConfig(ctx, h.ProjectID, version, `{"jurisdictions":{"default":"EX","thresholds":{"EX":{"child_max_age":12,"adult_age":21}}}}`)
				require.NoError(t, err)
				require.Equal(t, identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_ACTIVE_KNOWN_MINOR, read(young)[0].Classification, "live project policy must replace the cached default thresholds")
				require.NoError(t, users.UpdateUser(ctx, adult, map[string]any{"status": service.StatusPendingDeletion}))
				require.Equal(t, identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_DENIED, read(adult)[0].Classification)

				sibling, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{Name: "Sibling", StorageScopeId: "classification-sibling-" + h.ProjectID}))
				require.NoError(t, err)
				siblingID := sibling.Msg.GetProjectId()
				foreign, err := h.Stores.users.WithProject(siblingID).CreateUser(ctx, &service.User{Username: "foreign", Kind: service.UserKindPerson, Status: service.StatusActive, DateOfBirthMs: new(time.Now().AddDate(-35, 0, 0).UnixMilli())})
				require.NoError(t, err)
				require.Equal(t, identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_DENIED, read(foreign)[0].Classification)
				siblingRouting := mint(siblingID, service.CredentialKindPublishable)
				_, err = client(classifier.GetRawKey(), siblingRouting.GetPublicId()).ClassifyAccounts(ctx, connect.NewRequest(&identitypb.ClassifyAccountsRequest{UserIds: []string{minor}}))
				requireConnectCode(t, "foreign resolved project", err, connect.CodeUnauthenticated)

				reader := mint(h.ProjectID, service.CredentialKindManagedChildReader)
				_, err = client(reader.GetRawKey(), routing.GetPublicId()).ClassifyAccounts(ctx, connect.NewRequest(&identitypb.ClassifyAccountsRequest{UserIds: []string{minor}}))
				requireConnectCode(t, "guardian key cannot classify", err, connect.CodeUnauthenticated)
				_, err = h.ClientWithHost("", map[string]string{identityconnect.ManagedChildKeyHeader: classifier.GetRawKey(), middleware.ProjectKeyHeader: routing.GetPublicId()}).GetManagedChildAuthorization(ctx, connect.NewRequest(&identitypb.GetManagedChildAuthorizationRequest{GuardianUserId: young, ChildUserId: minor}))
				requireConnectCode(t, "classifier grants no guardian authorization", err, connect.CodeUnauthenticated)
				_, err = h.directoryClient(classifier.GetRawKey()).LookupUsers(ctx, connect.NewRequest(&identitypb.LookupUsersRequest{Emails: []string{"minor@example.test"}}))
				requireConnectCode(t, "classifier grants no directory lookup", err, connect.CodeUnauthenticated)
				_, err = h.AuthedClient(classifier.GetRawKey()).GetUser(ctx, connect.NewRequest(&identitypb.GetUserRequest{UserId: minor}))
				requireConnectCode(t, "classifier grants no profile read", err, connect.CodeUnauthenticated)

				_, err = admin.AdminRevokeProjectCredential(ctx, connect.NewRequest(&identitypb.AdminRevokeProjectCredentialRequest{ProjectId: h.ProjectID, CredentialId: classifier.GetCredentialId()}))
				require.NoError(t, err)
				_, err = client(classifier.GetRawKey(), routing.GetPublicId()).ClassifyAccounts(ctx, connect.NewRequest(&identitypb.ClassifyAccountsRequest{UserIds: []string{minor}}))
				requireConnectCode(t, "revocation is immediate", err, connect.CodeUnauthenticated)
			})
		}
	}
}
