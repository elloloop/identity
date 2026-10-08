package app

import (
	"net/http"
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/repo/memory"
	"github.com/elloloop/identity/internal/service"
)

// SCIM is an admin channel: a project with email accounts off refuses to
// provision one through it (403), as it refuses an admin.
func TestSCIM_EmailAccountsOffRefusesProvisioning(t *testing.T) {
	mux := http.NewServeMux()
	(&scimHandler{
		repo:             memory.New(),
		projectID:        testSCIMProjectID,
		bearerToken:      testSCIMToken,
		logger:           zap.NewNop(),
		defaultProjectID: testSCIMProjectID,
		defaultAccounts:  service.ProjectAccountsConfig{EmailSignup: service.SignupOff},
	}).register(mux, true)
	rec := scimReq(t, mux, http.MethodPost, "/scim/v2/Users", testSCIMToken, `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"bob@mail.example.test","active":true
	}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s, want 403", rec.Code, rec.Body.String())
	}
}
