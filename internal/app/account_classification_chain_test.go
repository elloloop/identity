package app

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnect "github.com/elloloop/identity/internal/connect"
	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func TestAccountClassificationServedChain(t *testing.T) {
	cfg := newTestConfig()
	cfg.DefaultProjectID = chainDirectoryProject
	cfg.AgeGateEnabled = true
	cfg.AgeGateChildMaxAge = 12
	cfg.AgeGateAdultAge = 18
	h, repo := newAccountProofChainApp(t, cfg, managedChildChainResolver{}, service.CredentialKindAccountClassifier)
	id, err := repo.WithProject(chainDirectoryProject).CreateUser(context.Background(), &service.User{Email: "private-profile@example.test", Name: "Private Name", Kind: service.UserKindPerson, Status: service.StatusActive, DateOfBirthMs: new(time.Now().AddDate(-35, 0, 0).UnixMilli())})
	require.NoError(t, err)
	path := "/identity.v1.IdentityService/ClassifyAccounts"
	body := `{"userIds":["` + id + `","missing"]}`
	headers := map[string]string{identityconnect.AccountClassifierKeyHeader: chainDirectoryKey}
	rec := postRPC(t, h, path, body, headers)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var response identitypb.ClassifyAccountsResponse
	require.NoError(t, protojson.Unmarshal(rec.Body.Bytes(), &response))
	require.Len(t, response.Accounts, 2)
	require.Equal(t, identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_ACTIVE_KNOWN_ADULT, response.Accounts[0].Classification)
	require.Equal(t, identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_DENIED, response.Accounts[1].Classification)
	require.False(t, strings.Contains(rec.Body.String(), "Private Name"))
	require.False(t, strings.Contains(rec.Body.String(), "private-profile"))
	rec = postRPC(t, h, path, body, nil)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	rec = postRPC(t, h, "/identity.v1.IdentityService/LookupUsers", `{"emails":["private-profile@example.test"]}`, map[string]string{identityconnect.DirectoryKeyHeader: chainDirectoryKey})
	require.Equal(t, http.StatusUnauthorized, rec.Code, "classifier has no email discovery rights")
	require.NoError(t, repo.WithProject(chainDirectoryProject).UpdateUser(context.Background(), id, map[string]any{"status": service.StatusDeactivated}))
	rec = postRPC(t, h, path, body, headers)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, protojson.Unmarshal(rec.Body.Bytes(), &response))
	require.Equal(t, identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_DENIED, response.Accounts[0].Classification)
}
