//go:build integration && realpostgres

package integration

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/service"
)

func TestReviewManagedChildAuthorizationRealPostgres(t *testing.T) {
	h := startRedesignHarnessWith(t, func(cfg *config.Config) {
		cfg.AgeGateEnabled = true
		cfg.AgeGateChildMaxAge = 12
		cfg.AgeGateAdultAge = 18
	})
	ctx := context.Background()
	_, version, err := h.Stores.controlPlane.GetProjectConfig(ctx, h.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	policy := `{"access":{"mode":"open"},"guardian":{"require_step_up":true,"require_adult_profile":true},"jurisdictions":{"default":"EX","thresholds":{"EX":{"child_max_age":12,"adult_age":21}}}}`
	if _, _, err := h.Stores.controlPlane.UpdateProjectConfig(ctx, h.ProjectID, version, policy); err != nil {
		t.Fatal(err)
	}
	admin := h.adminClient(harnessAdminSecret)
	mint := func(project, kind string) *identitypb.AdminCreateProjectCredentialResponse {
		t.Helper()
		result, err := admin.AdminCreateProjectCredential(ctx, connect.NewRequest(&identitypb.AdminCreateProjectCredentialRequest{ProjectId: project, Kind: kind}))
		if err != nil {
			t.Fatal(err)
		}
		return result.Msg
	}
	machine := mint(h.ProjectID, service.CredentialKindManagedChildReader)
	routing := mint(h.ProjectID, service.CredentialKindPublishable)
	users := h.Stores.users.WithProject(h.ProjectID)
	seed := func(name string, age int) string {
		t.Helper()
		id, err := users.CreateUser(ctx, &service.User{Username: name, Kind: service.UserKindPerson, Status: service.StatusActive, DateOfBirthMs: time.Now().AddDate(-age, 0, 0).UnixMilli()})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	child := seed("proof-child", 8)
	adult := seed("proof-guardian", 35)
	young := seed("proof-young-guardian", 19)
	for _, guardian := range []string{adult, young} {
		if err := users.UpsertGuardianEdge(ctx, &service.GuardianEdge{ChildUserID: child, GuardianUserID: guardian}); err != nil {
			t.Fatal(err)
		}
	}
	request := func(private, public, guardian string) (bool, error) {
		client := h.ClientWithHost("", map[string]string{"X-Managed-Child-Key": private, "X-Project-Key": public})
		result, err := client.GetManagedChildAuthorization(ctx, connect.NewRequest(&identitypb.GetManagedChildAuthorizationRequest{ChildUserId: child, GuardianUserId: guardian}))
		if err != nil {
			return false, err
		}
		return result.Msg.GetAuthorized(), nil
	}
	if allowed, err := request(machine.GetRawKey(), routing.GetPublicId(), adult); err != nil || !allowed {
		t.Fatalf("live proof: authorized=%v err=%v", allowed, err)
	}
	if allowed, err := request(machine.GetRawKey(), routing.GetPublicId(), young); err != nil || allowed {
		t.Fatalf("authoritative project threshold ignored: authorized=%v err=%v", allowed, err)
	}
	sibling, err := admin.AdminCreateProject(ctx, connect.NewRequest(&identitypb.AdminCreateProjectRequest{Name: "Sibling", StorageScopeId: "proof-sibling"}))
	if err != nil {
		t.Fatal(err)
	}
	siblingRouting := mint(sibling.Msg.GetProjectId(), service.CredentialKindPublishable)
	_, err = request(machine.GetRawKey(), siblingRouting.GetPublicId(), adult)
	requireConnectCode(t, "mismatched project", err, connect.CodeUnauthenticated)
	if err := users.DeleteGuardianEdge(ctx, adult, child); err != nil {
		t.Fatal(err)
	}
	if allowed, err := request(machine.GetRawKey(), routing.GetPublicId(), adult); err != nil || allowed {
		t.Fatalf("edge revocation not live: authorized=%v err=%v", allowed, err)
	}
	if _, err := admin.AdminRevokeProjectCredential(ctx, connect.NewRequest(&identitypb.AdminRevokeProjectCredentialRequest{ProjectId: h.ProjectID, CredentialId: machine.GetCredentialId()})); err != nil {
		t.Fatal(err)
	}
	_, err = request(machine.GetRawKey(), routing.GetPublicId(), adult)
	requireConnectCode(t, "revoked reader key", err, connect.CodeUnauthenticated)
}
