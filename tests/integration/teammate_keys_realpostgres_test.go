//go:build realpostgres

package integration

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	identityconnectgen "github.com/elloloop/identity/gen/go/identity/v1/identityv1connect"
	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	identityconnect "github.com/elloloop/identity/internal/connect"
	"github.com/elloloop/identity/internal/repo"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/identity/pkg/passwords"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	teammateIssuer   = "https://auth.example.test"
	teammateAudience = "https://api.example.test"
)

type teammateHarness struct {
	BaseURL   string
	HTTP      *http.Client
	Client    identityconnectgen.IdentityServiceClient
	ProjectID string
	Users     service.Repository
	Built     *repo.Built
	Metrics   *prometheus.Registry
}

type teammateFixture struct {
	h        *teammateHarness
	keys     identityconnectgen.TeammateKeyServiceClient
	grants   identityconnectgen.HireGrantServiceClient
	agentID  string
	ownerID  string
	unique   string
	managers string
}

func startTeammateHarness(t *testing.T, enabled bool, configure ...func(*config.Config)) *teammateHarness {
	t.Helper()
	dsn := os.Getenv("GATEWAY_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEWAY_POSTGRES_DSN not set")
	}
	project := fmt.Sprintf("teammate-keys-%d", time.Now().UnixNano())
	cfg := newIssue3TestConfig()
	cfg.DefaultTenantID = project
	cfg.DefaultProjectID = project
	cfg.TeammateKeysEnabled = enabled
	cfg.JWTIssuer = teammateIssuer
	cfg.JWTAudience = teammateAudience
	for _, apply := range configure {
		apply(cfg)
	}
	built, err := repo.Build(context.Background(), repo.Config{Driver: repo.DriverPostgres, PostgresDSN: dsn, PostgresMaxConns: 5, PostgresAutoMigrate: true, ProjectID: project}, zap.NewNop())
	if err != nil {
		t.Fatalf("repo.Build: %v", err)
	}
	if closer, ok := built.Repository.(interface{ Close() }); ok {
		t.Cleanup(closer.Close)
	}
	if _, err = built.ProjectStore.EnsureDefaultProject(context.Background(), project, project, "teammate-keys"); err != nil {
		t.Fatalf("seed default project: %v", err)
	}
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{RPID: cfg.PasskeyRPID, RPName: cfg.PasskeyRPName, Origin: cfg.PasskeyOrigin})
	if err != nil {
		t.Fatalf("init webauthn: %v", err)
	}
	metrics := prometheus.NewRegistry()
	appBuilt, err := app.New(app.Deps{
		Config:               cfg,
		Logger:               zap.NewNop(),
		Signer:               jwttest.NewSigner(t, "teammate-keys-kid"),
		Repo:                 built.Repository,
		DB:                   built.DB,
		Passkeys:             pkSvc,
		TOTPKey:              []byte("01234567890123456789012345678901"),
		TOTPRecoveryPepper:   []byte("test-recovery-pepper!@#$%^&*()_+ABCDEFGH"),
		EmailTransport:       issue3SilentMailer{},
		DirectoryCredentials: built.DirectoryCredentialStore(),
		MetricsRegistry:      metrics,
	})
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	appBuilt.Start()
	t.Cleanup(appBuilt.Stop)
	srv := httptest.NewServer(appBuilt.Handler)
	t.Cleanup(srv.Close)
	return &teammateHarness{BaseURL: srv.URL, HTTP: srv.Client(), Client: identityconnectgen.NewIdentityServiceClient(srv.Client(), srv.URL), ProjectID: project, Users: built.Repository, Built: built, Metrics: metrics}
}

func newTeammateFixture(t *testing.T, configure ...func(*config.Config)) *teammateFixture {
	t.Helper()
	h := startTeammateHarness(t, true, configure...)
	ctx := context.Background()
	unique := fmt.Sprintf("%d", time.Now().UnixNano())
	email := "lead-" + unique + "@example.com"
	passwordHash, err := passwords.Hash(issue3Password)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := h.Users.CreateUser(ctx, &service.User{Email: email, Name: "Lead", Status: service.StatusActive, EmailVerified: true, PasswordHash: passwordHash})
	if err != nil {
		t.Fatalf("CreateUser(lead): %v", err)
	}
	agent, err := h.Users.CreateUser(ctx, &service.User{Name: "Teammate", Kind: service.UserKindAgent, OwnerUserID: owner, Status: service.StatusActive})
	if err != nil {
		t.Fatalf("CreateUser(agent): %v", err)
	}
	login, err := h.Client.PasswordLogin(ctx, connect.NewRequest(&identitypb.PasswordLoginRequest{Email: email, Password: issue3Password}))
	if err != nil {
		t.Fatalf("PasswordLogin(lead): %v", err)
	}
	manager := mintTeammateCredential(t, h, service.CredentialKindTeammateKeyManager, "tk_"+unique)
	return &teammateFixture{h: h, keys: teammateKeyClient(h, manager), grants: hireGrantClient(h, login.Msg.AccessToken), agentID: agent, ownerID: owner, unique: unique, managers: manager}
}

func (f *teammateFixture) person(t *testing.T, name, role string) identityconnectgen.HireGrantServiceClient {
	t.Helper()
	grants, _ := f.personWithID(t, name, role)
	return grants
}

func (f *teammateFixture) personWithID(t *testing.T, name, role string) (identityconnectgen.HireGrantServiceClient, string) {
	t.Helper()
	email := name + "-" + f.unique + "@example.com"
	passwordHash, err := passwords.Hash(issue3Password)
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.h.Users.CreateUser(context.Background(), &service.User{Email: email, Name: name, Role: role, Status: service.StatusActive, EmailVerified: true, PasswordHash: passwordHash})
	if err != nil {
		t.Fatalf("CreateUser(%s): %v", name, err)
	}
	login, err := f.h.Client.PasswordLogin(context.Background(), connect.NewRequest(&identitypb.PasswordLoginRequest{Email: email, Password: issue3Password}))
	if err != nil {
		t.Fatalf("PasswordLogin(%s): %v", name, err)
	}
	return hireGrantClient(f.h, login.Msg.AccessToken), id
}

func hireGrantClient(h *teammateHarness, accessToken string) identityconnectgen.HireGrantServiceClient {
	return identityconnectgen.NewHireGrantServiceClient(issue3BearerHTTPClient{base: h.HTTP, token: accessToken}, h.BaseURL)
}

func mintTeammateCredential(t *testing.T, h *teammateHarness, kind, publicID string) string {
	t.Helper()
	secret := "secret-" + publicID
	digest := sha256.Sum256([]byte(secret))
	if _, err := h.Built.ProjectStore.CreateProjectCredential(context.Background(), &service.AdminProjectCredential{ProjectID: h.ProjectID, Kind: kind, PublicID: publicID, SecretHash: hex.EncodeToString(digest[:])}); err != nil {
		t.Fatalf("CreateProjectCredential(%s): %v", kind, err)
	}
	return publicID + "." + secret
}

func requireTeammateCode(t *testing.T, what string, err error, want connect.Code) {
	t.Helper()
	if connect.CodeOf(err) != want {
		t.Fatalf("%s: err = %v, want %v", what, err, want)
	}
}

func teammateKeyClient(h *teammateHarness, rawKey string) identityconnectgen.TeammateKeyServiceClient {
	return identityconnectgen.NewTeammateKeyServiceClient(managerKeyClient{base: h.HTTP, key: rawKey}, h.BaseURL)
}

type managerKeyClient struct {
	base *http.Client
	key  string
}

func (c managerKeyClient) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set(identityconnect.TeammateKeyManagerHeader, c.key)
	return c.base.Do(req)
}

func (f *teammateFixture) claim(name string) string { return name + "-" + f.unique }

func (f *teammateFixture) placement(claim string) string { return "placement-" + claim }

func (f *teammateFixture) grant(t *testing.T, placement string) string {
	t.Helper()
	resp, err := f.grants.CreateHireGrant(context.Background(), connect.NewRequest(&identitypb.CreateHireGrantRequest{TeammateId: f.agentID, PlacementId: placement, CompanyId: "company-1"}))
	if err != nil {
		t.Fatalf("CreateHireGrant: %v", err)
	}
	if resp.Msg.GrantId == "" || time.Until(resp.Msg.ExpiresAt.AsTime()) < 23*time.Hour {
		t.Fatalf("CreateHireGrant = %+v", resp.Msg)
	}
	return resp.Msg.GrantId
}

func (f *teammateFixture) registration(claim string, public []byte, grantID string) *identitypb.RegisterTeammateKeyRequest {
	return &identitypb.RegisterTeammateKeyRequest{ClaimId: claim, TeammateId: f.agentID, CompanyId: "company-1", WorkstationId: "workstation-1", PublicKey: public, Algorithm: identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256, GrantId: grantID, PlacementId: f.placement(claim)}
}

func (f *teammateFixture) send(req *identitypb.RegisterTeammateKeyRequest) (string, error) {
	resp, err := f.keys.RegisterTeammateKey(context.Background(), connect.NewRequest(req))
	if err != nil {
		return "", err
	}
	return resp.Msg.KeyId, nil
}

func (f *teammateFixture) register(t *testing.T, claim string, public []byte) (string, error) {
	t.Helper()
	return f.send(f.registration(claim, public, f.grant(t, f.placement(claim))))
}

func (f *teammateFixture) revoke(claim string, deadline time.Time) (*identitypb.RevokeTeammateKeyResponse, error) {
	req := &identitypb.RevokeTeammateKeyRequest{ClaimId: claim, Reason: identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_RELEASED}
	if !deadline.IsZero() {
		req.Deadline = timestamppb.New(deadline)
	}
	resp, err := f.keys.RevokeTeammateKey(context.Background(), connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func p256Key(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return private, der
}

func signP256(t *testing.T, private *ecdsa.PrivateKey) func([]byte) []byte {
	return func(message []byte) []byte {
		digest := sha256.Sum256(message)
		signature, err := private.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		return signature
	}
}

func (f *teammateFixture) challenge(t *testing.T, keyID string) (*identitypb.CreateAgentMachineChallengeResponse, error) {
	t.Helper()
	resp, err := f.h.Client.CreateAgentMachineChallenge(context.Background(), connect.NewRequest(&identitypb.CreateAgentMachineChallengeRequest{TeammateKeyId: keyID, Operation: identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_EXCHANGE_AGENT}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (f *teammateFixture) exchange(t *testing.T, keyID, challengeID string, signature []byte) (*identitypb.ExchangeAgentMachineCredentialResponse, error) {
	t.Helper()
	resp, err := f.h.Client.ExchangeAgentMachineCredential(context.Background(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{TeammateKeyId: keyID, Proof: &identitypb.AgentMachineProof{ChallengeId: challengeID, Signature: signature}}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (f *teammateFixture) issue(t *testing.T, keyID string, sign func([]byte) []byte) *identitypb.ExchangeAgentMachineCredentialResponse {
	t.Helper()
	challenge, err := f.challenge(t, keyID)
	if err != nil {
		t.Fatalf("CreateAgentMachineChallenge: %v", err)
	}
	tokens, err := f.exchange(t, keyID, challenge.ChallengeId, sign(challenge.Message))
	if err != nil {
		t.Fatalf("ExchangeAgentMachineCredential: %v", err)
	}
	return tokens
}

type teammateTokenClaims struct {
	Sub           string   `json:"sub"`
	Kind          string   `json:"kind"`
	Issuer        string   `json:"iss"`
	Project       string   `json:"project"`
	Audience      []string `json:"aud"`
	ClaimID       string   `json:"claim_id"`
	WorkstationID string   `json:"workstation_id"`
	CompanyID     string   `json:"company_id"`
	IssuedAt      int64    `json:"iat"`
	ExpiresAt     int64    `json:"exp"`
	Scope         *string  `json:"scope"`
	Actor         struct {
		Sub string `json:"sub"`
	} `json:"act"`
}

func verifiedTeammateClaims(t *testing.T, h *teammateHarness, token string) teammateTokenClaims {
	t.Helper()
	keys, err := jwk.Fetch(context.Background(), h.BaseURL+"/.well-known/jwks.json", jwk.WithHTTPClient(h.HTTP))
	if err != nil {
		t.Fatalf("fetch JWKS: %v", err)
	}
	payload, err := jws.Verify([]byte(token), jws.WithKeySet(keys, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		t.Fatalf("verify teammate token: %v", err)
	}
	message, err := jws.Parse([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
	if typ := message.Signatures()[0].ProtectedHeaders().Type(); typ != "at+jwt" {
		t.Fatalf("typ = %q, want at+jwt", typ)
	}
	var claims teammateTokenClaims
	if err = json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestTeammateKeys_P256Exchange(t *testing.T) {
	f := newTeammateFixture(t)
	private, public := p256Key(t)
	claim := f.claim("claim-p256")
	grant := f.grant(t, f.placement(claim))
	keyID, err := f.send(f.registration(claim, public, grant))
	if err != nil || keyID == "" {
		t.Fatalf("RegisterTeammateKey: id=%q err=%v", keyID, err)
	}
	again, err := f.send(f.registration(claim, public, grant))
	if err != nil || again != keyID {
		t.Fatalf("idempotent RegisterTeammateKey: id=%q err=%v, want %q", again, err, keyID)
	}

	tokens := f.issue(t, keyID, signP256(t, private))
	if tokens.ExpiresIn != config.TeammateAccessSeconds || tokens.TokenType != "Bearer" || tokens.Scope != "" {
		t.Fatalf("exchange response = %+v", tokens)
	}
	claims := verifiedTeammateClaims(t, f.h, tokens.AccessToken)
	if claims.Sub != f.agentID || claims.Actor.Sub != f.ownerID || claims.Kind != service.UserKindAgent || claims.Issuer != teammateIssuer || claims.Project != f.h.ProjectID || len(claims.Audience) != 1 || claims.Audience[0] != teammateAudience || claims.ClaimID != claim || claims.WorkstationID != "workstation-1" || claims.CompanyID != "company-1" || claims.ExpiresAt-claims.IssuedAt != config.TeammateAccessSeconds || claims.Scope != nil {
		t.Fatalf("teammate claims = %+v", claims)
	}

	if got := teammateCounter(t, f.h, "identity_teammate_keys_registered_total", map[string]string{"result": "created"}); got != 1 {
		t.Fatalf("registered{created} = %v", got)
	}
	if got := teammateCounter(t, f.h, "identity_teammate_keys_registered_total", map[string]string{"result": "existing"}); got != 1 {
		t.Fatalf("registered{existing} = %v", got)
	}
	if got := teammateCounter(t, f.h, "identity_agent_exchanges_total", map[string]string{"key_kind": "teammate", "result": "issued"}); got != 1 {
		t.Fatalf("exchanges{teammate,issued} = %v", got)
	}
}

func TestTeammateKeys_RegistrationNeedsTheLeadsGrantForThisHire(t *testing.T) {
	f := newTeammateFixture(t)
	_, public := p256Key(t)
	claim := f.claim("claim-granted")
	placement := f.placement(claim)

	for name, req := range map[string]*identitypb.RegisterTeammateKeyRequest{
		"no grant":      f.registration(claim, public, ""),
		"unknown grant": f.registration(claim, public, "grant-that-was-never-made"),
	} {
		_, err := f.send(req)
		requireTeammateCode(t, name, err, connect.CodePermissionDenied)
	}
	forOtherPlacement := f.registration(claim, public, f.grant(t, "placement-other-"+f.unique))
	_, err := f.send(forOtherPlacement)
	requireTeammateCode(t, "a grant for another placement", err, connect.CodePermissionDenied)
	otherCompany, err := f.grants.CreateHireGrant(context.Background(), connect.NewRequest(&identitypb.CreateHireGrantRequest{TeammateId: f.agentID, PlacementId: placement, CompanyId: "company-2"}))
	if err != nil {
		t.Fatalf("CreateHireGrant(company-2): %v", err)
	}
	_, err = f.send(f.registration(claim, public, otherCompany.Msg.GrantId))
	requireTeammateCode(t, "a grant for another company", err, connect.CodePermissionDenied)
	other, err := f.h.Users.CreateUser(context.Background(), &service.User{Name: "Other teammate", Kind: service.UserKindAgent, OwnerUserID: f.ownerID, Status: service.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	otherTeammate, err := f.grants.CreateHireGrant(context.Background(), connect.NewRequest(&identitypb.CreateHireGrantRequest{TeammateId: other, PlacementId: placement, CompanyId: "company-1"}))
	if err != nil {
		t.Fatalf("CreateHireGrant(other teammate): %v", err)
	}
	_, err = f.send(f.registration(claim, public, otherTeammate.Msg.GrantId))
	requireTeammateCode(t, "a grant for another teammate", err, connect.CodePermissionDenied)

	grant := f.grant(t, placement)
	keyID, err := f.send(f.registration(claim, public, grant))
	if err != nil {
		t.Fatalf("RegisterTeammateKey with the grant: %v", err)
	}
	_, second := p256Key(t)
	_, err = f.send(f.registration(claim, second, f.grant(t, placement)))
	requireTeammateCode(t, "a second key for the same claim", err, connect.CodeFailedPrecondition)
	_, err = f.send(f.registration(claim, public, f.grant(t, placement)))
	requireTeammateCode(t, "the same key for the claim under another grant", err, connect.CodeFailedPrecondition)
	if again, err := f.send(f.registration(claim, public, grant)); err != nil || again != keyID {
		t.Fatalf("retry with the used grant: id=%q err=%v, want %q", again, err, keyID)
	}
	reused := f.registration(f.claim("claim-reuse"), second, grant)
	reused.PlacementId = placement
	_, err = f.send(reused)
	requireTeammateCode(t, "a grant another claim used", err, connect.CodePermissionDenied)

	if got := teammateCounter(t, f.h, "identity_teammate_keys_registered_total", map[string]string{"result": "grant_refused"}); got != 6 {
		t.Fatalf("registered{grant_refused} = %v", got)
	}
}

func TestTeammateKeys_HireGrantNeedsTheTeammatesOwnerOrAnAdmin(t *testing.T) {
	f := newTeammateFixture(t)
	request := func(teammate string) *connect.Request[identitypb.CreateHireGrantRequest] {
		return connect.NewRequest(&identitypb.CreateHireGrantRequest{TeammateId: teammate, PlacementId: "placement-1", CompanyId: "company-1"})
	}
	_, err := hireGrantClient(f.h, "").CreateHireGrant(context.Background(), request(f.agentID))
	requireTeammateCode(t, "no session", err, connect.CodeUnauthenticated)
	stranger := f.person(t, "stranger", "")
	for name, teammate := range map[string]string{"another person's teammate": f.agentID, "a person": f.ownerID, "nothing": "no-such-account"} {
		_, err = stranger.CreateHireGrant(context.Background(), request(teammate))
		requireTeammateCode(t, "a non-owner hiring "+name, err, connect.CodePermissionDenied)
	}
	_, err = f.grants.CreateHireGrant(context.Background(), request(f.ownerID))
	requireTeammateCode(t, "the owner hiring a person", err, connect.CodePermissionDenied)
	if _, err = f.person(t, "admin", service.RoleAdmin).CreateHireGrant(context.Background(), request(f.agentID)); err != nil {
		t.Fatalf("a project admin hiring the teammate: %v", err)
	}
	_, err = f.grants.CreateHireGrant(context.Background(), connect.NewRequest(&identitypb.CreateHireGrantRequest{TeammateId: f.agentID, PlacementId: "placement 1", CompanyId: "company-1"}))
	requireTeammateCode(t, "a malformed placement", err, connect.CodeInvalidArgument)
	_, err = f.grants.CreateHireGrant(context.Background(), connect.NewRequest(&identitypb.CreateHireGrantRequest{TeammateId: f.agentID, PlacementId: "placement-1"}))
	requireTeammateCode(t, "no company", err, connect.CodeInvalidArgument)
}

func TestTeammateKeys_ExchangesEndWhenTheGrantorCouldNoLongerGrant(t *testing.T) {
	f := newTeammateFixture(t)
	ctx := context.Background()
	private, public := p256Key(t)
	claim := f.claim("claim-transfer")
	keyID, err := f.register(t, claim, public)
	if err != nil {
		t.Fatalf("RegisterTeammateKey: %v", err)
	}
	f.issue(t, keyID, signP256(t, private))
	_, strangerID := f.personWithID(t, "new-owner", "")
	raw, err := pgx.Connect(ctx, os.Getenv("GATEWAY_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close(ctx) }()
	if _, err = raw.Exec(ctx, `SELECT set_config('app.current_project_id',$1,false)`, f.h.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(ctx, `UPDATE users SET owner_user_id=$1 WHERE id=$2`, strangerID, f.agentID); err != nil {
		t.Fatalf("transfer the teammate: %v", err)
	}
	next, err := f.challenge(t, keyID)
	if err != nil {
		t.Fatalf("CreateAgentMachineChallenge: %v", err)
	}
	_, err = f.exchange(t, keyID, next.ChallengeId, signP256(t, private)(next.Message))
	requireTeammateCode(t, "an exchange after the teammate moved to another owner", err, connect.CodeUnauthenticated)

	admin, adminID := f.personWithID(t, "admin", service.RoleAdmin)
	adminClaim := f.claim("claim-admin")
	grant, err := admin.CreateHireGrant(ctx, connect.NewRequest(&identitypb.CreateHireGrantRequest{TeammateId: f.agentID, PlacementId: f.placement(adminClaim), CompanyId: "company-1"}))
	if err != nil {
		t.Fatalf("CreateHireGrant(admin): %v", err)
	}
	adminPrivate, adminPublic := p256Key(t)
	adminKey, err := f.send(f.registration(adminClaim, adminPublic, grant.Msg.GrantId))
	if err != nil {
		t.Fatalf("RegisterTeammateKey(admin grant): %v", err)
	}
	if claims := verifiedTeammateClaims(t, f.h, f.issue(t, adminKey, signP256(t, adminPrivate)).AccessToken); claims.Actor.Sub != adminID {
		t.Fatalf("act.sub = %q, want the granting admin %q", claims.Actor.Sub, adminID)
	}
	if err = f.h.Users.UpdateUser(ctx, adminID, map[string]any{"role": service.RoleMember}); err != nil {
		t.Fatal(err)
	}
	next, err = f.challenge(t, adminKey)
	if err != nil {
		t.Fatalf("CreateAgentMachineChallenge: %v", err)
	}
	_, err = f.exchange(t, adminKey, next.ChallengeId, signP256(t, adminPrivate)(next.Message))
	requireTeammateCode(t, "an exchange after the granting admin lost the role", err, connect.CodeUnauthenticated)
}

func TestTeammateKeys_Ed25519IsRefused(t *testing.T) {
	f := newTeammateFixture(t)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	claim := f.claim("claim-ed25519")
	req := f.registration(claim, der, f.grant(t, f.placement(claim)))
	req.Algorithm = identitypb.KeyAlgorithm_KEY_ALGORITHM_ED25519
	_, err = f.send(req)
	requireTeammateCode(t, "an Ed25519 key", err, connect.CodeInvalidArgument)
	req.Algorithm = identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256
	_, err = f.send(req)
	requireTeammateCode(t, "an Ed25519 key labelled P-256", err, connect.CodeInvalidArgument)
}

func TestTeammateKeys_RegistrationRefusals(t *testing.T) {
	f := newTeammateFixture(t)
	_, public := p256Key(t)
	_, other := p256Key(t)
	claim := f.claim("claim-a")
	if _, err := f.register(t, claim, public); err != nil {
		t.Fatalf("RegisterTeammateKey: %v", err)
	}
	_, err := f.register(t, claim, other)
	requireTeammateCode(t, "same claim, different key", err, connect.CodeFailedPrecondition)
	_, err = f.register(t, f.claim("claim-b"), public)
	requireTeammateCode(t, "same key, another claim", err, connect.CodeFailedPrecondition)
	unspecified := f.registration(f.claim("claim-c"), other, "grant")
	unspecified.Algorithm = identitypb.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED
	_, err = f.send(unspecified)
	requireTeammateCode(t, "unspecified algorithm", err, connect.CodeInvalidArgument)
	_, err = f.send(f.registration(f.claim("claim-c"), append([]byte{}, other[:len(other)-1]...), "grant"))
	requireTeammateCode(t, "truncated key", err, connect.CodeInvalidArgument)
	noPlacement := f.registration(f.claim("claim-c"), other, "grant")
	noPlacement.PlacementId = ""
	_, err = f.send(noPlacement)
	requireTeammateCode(t, "no placement", err, connect.CodeInvalidArgument)

	human := f.registration(f.claim("claim-human"), other, "grant")
	human.TeammateId = f.ownerID
	_, err = f.send(human)
	requireTeammateCode(t, "a person as teammate", err, connect.CodeInvalidArgument)
	blank := f.registration(f.claim("claim-blank"), other, "grant")
	blank.CompanyId = ""
	_, err = f.send(blank)
	requireTeammateCode(t, "blank company", err, connect.CodeInvalidArgument)

	directory := mintTeammateCredential(t, f.h, service.CredentialKindDirectoryReader, "dk_"+f.unique)
	for name, key := range map[string]string{"no credential": "", "malformed": "nodot", "wrong secret": "dk_" + f.unique + ".wrong", "directory key": directory} {
		_, err = teammateKeyClient(f.h, key).RegisterTeammateKey(context.Background(), connect.NewRequest(f.registration(f.claim("claim-d"), other, "grant")))
		requireTeammateCode(t, name, err, connect.CodePermissionDenied)
	}
	_, err = teammateKeyClient(f.h, f.managers+"x").RevokeTeammateKey(context.Background(), connect.NewRequest(&identitypb.RevokeTeammateKeyRequest{ClaimId: claim, Reason: identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_RELEASED}))
	requireTeammateCode(t, "revoke with a wrong secret", err, connect.CodePermissionDenied)

	if got := teammateCounter(t, f.h, "identity_teammate_keys_registered_total", map[string]string{"result": "conflict"}); got != 2 {
		t.Fatalf("registered{conflict} = %v", got)
	}
	if got := teammateCounter(t, f.h, "identity_teammate_keys_registered_total", map[string]string{"result": "denied"}); got != 4 {
		t.Fatalf("registered{denied} = %v", got)
	}
}

func TestTeammateKeys_ProofRefusals(t *testing.T) {
	f := newTeammateFixture(t)
	private, public := p256Key(t)
	impostor, _ := p256Key(t)
	keyID, err := f.register(t, f.claim("claim-proof"), public)
	if err != nil {
		t.Fatalf("RegisterTeammateKey: %v", err)
	}
	challenge, err := f.challenge(t, keyID)
	if err != nil {
		t.Fatalf("CreateAgentMachineChallenge: %v", err)
	}
	_, err = f.exchange(t, keyID, challenge.ChallengeId, signP256(t, impostor)(challenge.Message))
	requireTeammateCode(t, "another key's signature", err, connect.CodeUnauthenticated)
	digest := sha256.Sum256(challenge.Message)
	r, sv, err := ecdsa.Sign(rand.Reader, private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.exchange(t, keyID, challenge.ChallengeId, append(r.FillBytes(make([]byte, 32)), sv.FillBytes(make([]byte, 32))...))
	requireTeammateCode(t, "a raw r and s signature", err, connect.CodeUnauthenticated)
	signature := signP256(t, private)(challenge.Message)
	if _, err = f.exchange(t, keyID, challenge.ChallengeId, signature); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	_, err = f.exchange(t, keyID, challenge.ChallengeId, signature)
	requireTeammateCode(t, "replayed challenge", err, connect.CodeUnauthenticated)
	_, err = f.exchange(t, "unknown-key", challenge.ChallengeId, signature)
	requireTeammateCode(t, "unknown key", err, connect.CodeUnauthenticated)
	_, err = f.challenge(t, "unknown-key")
	requireTeammateCode(t, "challenge for an unknown key", err, connect.CodeUnauthenticated)

	_, err = f.h.Client.CreateAgentMachineChallenge(context.Background(), connect.NewRequest(&identitypb.CreateAgentMachineChallengeRequest{TeammateKeyId: keyID, MachineId: "machine", Operation: identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_EXCHANGE_AGENT}))
	requireTeammateCode(t, "teammate key with a machine id", err, connect.CodeInvalidArgument)
	_, err = f.h.Client.CreateAgentMachineChallenge(context.Background(), connect.NewRequest(&identitypb.CreateAgentMachineChallengeRequest{TeammateKeyId: keyID, Operation: identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_LIST_AGENTS}))
	requireTeammateCode(t, "teammate key for another operation", err, connect.CodeInvalidArgument)
	_, err = f.h.Client.ExchangeAgentMachineCredential(context.Background(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{TeammateKeyId: keyID, AgentUserId: f.agentID, Proof: &identitypb.AgentMachineProof{ChallengeId: challenge.ChallengeId, Signature: signature}}))
	requireTeammateCode(t, "teammate exchange naming an agent", err, connect.CodeInvalidArgument)

	if err = f.h.Users.UpdateUser(context.Background(), f.ownerID, map[string]any{"status": service.StatusDeactivated}); err != nil {
		t.Fatal(err)
	}
	next, err := f.challenge(t, keyID)
	if err != nil {
		t.Fatalf("CreateAgentMachineChallenge: %v", err)
	}
	_, err = f.exchange(t, keyID, next.ChallengeId, signP256(t, private)(next.Message))
	requireTeammateCode(t, "deactivated lead", err, connect.CodeUnauthenticated)
	if err = f.h.Users.UpdateUser(context.Background(), f.ownerID, map[string]any{"status": service.StatusActive}); err != nil {
		t.Fatal(err)
	}
	if err = f.h.Users.UpdateUser(context.Background(), f.agentID, map[string]any{"status": service.StatusDeactivated}); err != nil {
		t.Fatal(err)
	}
	next, err = f.challenge(t, keyID)
	if err != nil {
		t.Fatalf("CreateAgentMachineChallenge: %v", err)
	}
	_, err = f.exchange(t, keyID, next.ChallengeId, signP256(t, private)(next.Message))
	requireTeammateCode(t, "deactivated teammate", err, connect.CodeUnauthenticated)
	if got := teammateCounter(t, f.h, "identity_agent_exchanges_total", map[string]string{"key_kind": "teammate", "result": "refused"}); got < 6 {
		t.Fatalf("exchanges{teammate,refused} = %v", got)
	}
}

func TestTeammateKeys_RevocationIsImmediate(t *testing.T) {
	f := newTeammateFixture(t)
	private, public := p256Key(t)
	claim := f.claim("claim-revoke")
	keyID, err := f.register(t, claim, public)
	if err != nil {
		t.Fatalf("RegisterTeammateKey: %v", err)
	}
	pending, err := f.challenge(t, keyID)
	if err != nil {
		t.Fatalf("CreateAgentMachineChallenge: %v", err)
	}
	revoke := func(claimID string, reason identitypb.TeammateKeyRevocationReason) (*identitypb.RevokeTeammateKeyResponse, error) {
		resp, err := f.keys.RevokeTeammateKey(context.Background(), connect.NewRequest(&identitypb.RevokeTeammateKeyRequest{ClaimId: claimID, Reason: reason}))
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}
	before := time.Now()
	first, err := revoke(claim, identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_RELEASED)
	if err != nil || first.RevokedAt.AsTime().Before(before.Add(-time.Second)) || first.RevokedAt.AsTime().After(time.Now()) {
		t.Fatalf("RevokeTeammateKey = %+v, %v", first, err)
	}
	_, err = f.exchange(t, keyID, pending.ChallengeId, signP256(t, private)(pending.Message))
	requireTeammateCode(t, "challenge issued before revocation", err, connect.CodeUnauthenticated)
	_, err = f.challenge(t, keyID)
	requireTeammateCode(t, "challenge after revocation", err, connect.CodeUnauthenticated)
	second, err := revoke(claim, identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_REMOVED)
	if err != nil || !second.RevokedAt.AsTime().Equal(first.RevokedAt.AsTime()) {
		t.Fatalf("second RevokeTeammateKey = %+v, %v", second, err)
	}
	unknown, err := revoke(f.claim("never-registered"), identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_DRIFTED)
	if err != nil || unknown.RevokedAt != nil {
		t.Fatalf("RevokeTeammateKey(unknown) = %+v, %v", unknown, err)
	}
	_, err = revoke(claim, identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_UNSPECIFIED)
	requireTeammateCode(t, "unspecified reason", err, connect.CodeInvalidArgument)
	_, err = f.register(t, claim, public)
	requireTeammateCode(t, "re-register a revoked claim", err, connect.CodeFailedPrecondition)
	if got := teammateCounter(t, f.h, "identity_teammate_keys_revoked_total", map[string]string{"schedule": "immediate"}); got != 1 {
		t.Fatalf("revoked{immediate} = %v", got)
	}
}

func TestTeammateKeys_ExchangesStopAtTheDeadlineWithoutAnotherCall(t *testing.T) {
	f := newTeammateFixture(t)
	private, public := p256Key(t)
	claim := f.claim("claim-drain")
	keyID, err := f.register(t, claim, public)
	if err != nil {
		t.Fatalf("RegisterTeammateKey: %v", err)
	}
	_, err = f.revoke(claim, time.Now().Add(service.MaxTeammateKeyDrain+time.Minute))
	requireTeammateCode(t, "a deadline beyond the drain limit", err, connect.CodeInvalidArgument)

	deadline := time.Now().Add(3 * time.Second).Truncate(time.Millisecond)
	revoked, err := f.revoke(claim, deadline)
	if err != nil || !revoked.RevokedAt.AsTime().Equal(deadline) {
		t.Fatalf("RevokeTeammateKey(deadline) = %+v, %v", revoked, err)
	}
	later, err := f.revoke(claim, deadline.Add(time.Minute))
	if err != nil || !later.RevokedAt.AsTime().Equal(deadline) {
		t.Fatalf("a later deadline moved it: %+v, %v", later, err)
	}

	tokens := f.issue(t, keyID, signP256(t, private))
	claims := verifiedTeammateClaims(t, f.h, tokens.AccessToken)
	if claims.ExpiresAt > deadline.Unix() || int64(tokens.ExpiresIn) != claims.ExpiresAt-claims.IssuedAt {
		t.Fatalf("a token issued while draining expires at %d, after the deadline %d (expires_in %d)", claims.ExpiresAt, deadline.Unix(), tokens.ExpiresIn)
	}
	pending, err := f.challenge(t, keyID)
	if err != nil {
		t.Fatalf("CreateAgentMachineChallenge while draining: %v", err)
	}
	time.Sleep(time.Until(deadline) + 100*time.Millisecond)

	_, err = f.exchange(t, keyID, pending.ChallengeId, signP256(t, private)(pending.Message))
	requireTeammateCode(t, "an exchange after the deadline", err, connect.CodeUnauthenticated)
	_, err = f.challenge(t, keyID)
	requireTeammateCode(t, "a challenge after the deadline", err, connect.CodeUnauthenticated)
	if got := teammateCounter(t, f.h, "identity_teammate_keys_revoked_total", map[string]string{"schedule": "deadline"}); got != 1 {
		t.Fatalf("revoked{deadline} = %v", got)
	}
}

func TestTeammateKeys_ChallengesHaveAPerAddressLimit(t *testing.T) {
	const limit = 3
	f := newTeammateFixture(t, func(c *config.Config) { c.AgentMachineChallengePerIP = limit })
	_, public := p256Key(t)
	keyID, err := f.register(t, f.claim("claim-limit"), public)
	if err != nil {
		t.Fatalf("RegisterTeammateKey: %v", err)
	}
	for i := range limit {
		if _, err = f.challenge(t, keyID); err != nil {
			t.Fatalf("challenge %d within the limit: %v", i, err)
		}
	}
	_, err = f.challenge(t, keyID)
	requireTeammateCode(t, "a challenge beyond the per-address limit", err, connect.CodeUnavailable)
	_, err = f.challenge(t, "unknown-key")
	requireTeammateCode(t, "an unknown key beyond the per-address limit", err, connect.CodeUnavailable)
}

func TestTeammateKeys_DisabledByDefault(t *testing.T) {
	h := startTeammateHarness(t, false)
	manager := mintTeammateCredential(t, h, service.CredentialKindTeammateKeyManager, fmt.Sprintf("tk_off_%d", time.Now().UnixNano()))
	_, err := teammateKeyClient(h, manager).RegisterTeammateKey(context.Background(), connect.NewRequest(&identitypb.RegisterTeammateKeyRequest{ClaimId: "claim"}))
	requireTeammateCode(t, "unmounted TeammateKeyService", err, connect.CodeUnimplemented)
	_, err = h.Client.CreateAgentMachineChallenge(context.Background(), connect.NewRequest(&identitypb.CreateAgentMachineChallengeRequest{TeammateKeyId: "key", Operation: identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_EXCHANGE_AGENT}))
	requireTeammateCode(t, "teammate challenge while disabled", err, connect.CodeFailedPrecondition)
	_, err = h.Client.ExchangeAgentMachineCredential(context.Background(), connect.NewRequest(&identitypb.ExchangeAgentMachineCredentialRequest{TeammateKeyId: "key", Proof: &identitypb.AgentMachineProof{ChallengeId: "c", Signature: []byte{1}}}))
	requireTeammateCode(t, "teammate exchange while disabled", err, connect.CodeFailedPrecondition)
}

func teammateCounter(t *testing.T, h *teammateHarness, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := h.Metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			matched := 0
			for _, pair := range metric.GetLabel() {
				if labels[pair.GetName()] == pair.GetValue() {
					matched++
				}
			}
			if matched == len(labels) && len(metric.GetLabel()) == len(labels) {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}
