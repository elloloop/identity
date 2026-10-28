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
	agentID  string
	ownerID  string
	unique   string
	managers string
}

func startTeammateHarness(t *testing.T, enabled bool) *teammateHarness {
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

func newTeammateFixture(t *testing.T) *teammateFixture {
	t.Helper()
	h := startTeammateHarness(t, true)
	ctx := context.Background()
	unique := fmt.Sprintf("%d", time.Now().UnixNano())
	owner, err := h.Users.CreateUser(ctx, &service.User{Email: "owner-" + unique + "@example.test", Name: "Owner", Status: service.StatusActive, EmailVerified: true})
	if err != nil {
		t.Fatalf("CreateUser(owner): %v", err)
	}
	agent, err := h.Users.CreateUser(ctx, &service.User{Name: "Teammate", Kind: service.UserKindAgent, OwnerUserID: owner, Status: service.StatusActive})
	if err != nil {
		t.Fatalf("CreateUser(agent): %v", err)
	}
	manager := mintTeammateCredential(t, h, service.CredentialKindTeammateKeyManager, "tk_"+unique)
	return &teammateFixture{h: h, keys: teammateKeyClient(h, manager), agentID: agent, ownerID: owner, unique: unique, managers: manager}
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

func (f *teammateFixture) register(t *testing.T, claim string, public []byte, algorithm identitypb.KeyAlgorithm) (string, error) {
	t.Helper()
	resp, err := f.keys.RegisterTeammateKey(context.Background(), connect.NewRequest(&identitypb.RegisterTeammateKeyRequest{ClaimId: claim, TeammateId: f.agentID, CompanyId: "company-1", WorkstationId: "workstation-1", PublicKey: public, Algorithm: algorithm}))
	if err != nil {
		return "", err
	}
	return resp.Msg.KeyId, nil
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
	Actor         any      `json:"act"`
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
	keyID, err := f.register(t, claim, public, identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256)
	if err != nil || keyID == "" {
		t.Fatalf("RegisterTeammateKey: id=%q err=%v", keyID, err)
	}
	again, err := f.register(t, claim, public, identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256)
	if err != nil || again != keyID {
		t.Fatalf("idempotent RegisterTeammateKey: id=%q err=%v, want %q", again, err, keyID)
	}

	tokens := f.issue(t, keyID, signP256(t, private))
	if tokens.ExpiresIn != config.TeammateAccessSeconds || tokens.TokenType != "Bearer" || tokens.Scope != "" {
		t.Fatalf("exchange response = %+v", tokens)
	}
	claims := verifiedTeammateClaims(t, f.h, tokens.AccessToken)
	if claims.Sub != f.agentID || claims.Kind != service.UserKindAgent || claims.Issuer != teammateIssuer || claims.Project != f.h.ProjectID || len(claims.Audience) != 1 || claims.Audience[0] != teammateAudience || claims.ClaimID != claim || claims.WorkstationID != "workstation-1" || claims.CompanyID != "company-1" || claims.ExpiresAt-claims.IssuedAt != config.TeammateAccessSeconds || claims.Scope != nil || claims.Actor != nil {
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

func TestTeammateKeys_Ed25519Exchange(t *testing.T) {
	f := newTeammateFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := f.register(t, f.claim("claim-ed25519"), der, identitypb.KeyAlgorithm_KEY_ALGORITHM_ED25519)
	if err != nil {
		t.Fatalf("RegisterTeammateKey: %v", err)
	}
	tokens := f.issue(t, keyID, func(message []byte) []byte { return ed25519.Sign(private, message) })
	if claims := verifiedTeammateClaims(t, f.h, tokens.AccessToken); claims.Sub != f.agentID {
		t.Fatalf("sub = %q", claims.Sub)
	}
}

func TestTeammateKeys_RegistrationRefusals(t *testing.T) {
	f := newTeammateFixture(t)
	_, public := p256Key(t)
	_, other := p256Key(t)
	claim := f.claim("claim-a")
	if _, err := f.register(t, claim, public, identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256); err != nil {
		t.Fatalf("RegisterTeammateKey: %v", err)
	}
	_, err := f.register(t, claim, other, identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256)
	requireTeammateCode(t, "same claim, different key", err, connect.CodeFailedPrecondition)
	_, err = f.register(t, f.claim("claim-b"), public, identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256)
	requireTeammateCode(t, "same key, another claim", err, connect.CodeFailedPrecondition)
	_, err = f.register(t, f.claim("claim-c"), other, identitypb.KeyAlgorithm_KEY_ALGORITHM_ED25519)
	requireTeammateCode(t, "algorithm mismatch", err, connect.CodeInvalidArgument)
	_, err = f.register(t, f.claim("claim-c"), other, identitypb.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED)
	requireTeammateCode(t, "unspecified algorithm", err, connect.CodeInvalidArgument)
	_, err = f.register(t, f.claim("claim-c"), append([]byte{}, other[:len(other)-1]...), identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256)
	requireTeammateCode(t, "truncated key", err, connect.CodeInvalidArgument)

	_, err = f.keys.RegisterTeammateKey(context.Background(), connect.NewRequest(&identitypb.RegisterTeammateKeyRequest{ClaimId: f.claim("claim-human"), TeammateId: f.ownerID, CompanyId: "company-1", WorkstationId: "workstation-1", PublicKey: other, Algorithm: identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256}))
	requireTeammateCode(t, "a person as teammate", err, connect.CodeInvalidArgument)
	_, err = f.keys.RegisterTeammateKey(context.Background(), connect.NewRequest(&identitypb.RegisterTeammateKeyRequest{ClaimId: f.claim("claim-blank"), TeammateId: f.agentID, WorkstationId: "workstation-1", PublicKey: other, Algorithm: identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256}))
	requireTeammateCode(t, "blank company", err, connect.CodeInvalidArgument)

	directory := mintTeammateCredential(t, f.h, service.CredentialKindDirectoryReader, "dk_"+f.unique)
	for name, key := range map[string]string{"no credential": "", "malformed": "nodot", "wrong secret": "dk_" + f.unique + ".wrong", "directory key": directory} {
		_, err = teammateKeyClient(f.h, key).RegisterTeammateKey(context.Background(), connect.NewRequest(&identitypb.RegisterTeammateKeyRequest{ClaimId: f.claim("claim-d"), TeammateId: f.agentID, CompanyId: "company-1", WorkstationId: "workstation-1", PublicKey: other, Algorithm: identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256}))
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
	keyID, err := f.register(t, f.claim("claim-proof"), public, identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256)
	if err != nil {
		t.Fatalf("RegisterTeammateKey: %v", err)
	}
	challenge, err := f.challenge(t, keyID)
	if err != nil {
		t.Fatalf("CreateAgentMachineChallenge: %v", err)
	}
	_, err = f.exchange(t, keyID, challenge.ChallengeId, signP256(t, impostor)(challenge.Message))
	requireTeammateCode(t, "another key's signature", err, connect.CodeUnauthenticated)
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

	if err = f.h.Users.UpdateUser(context.Background(), f.agentID, map[string]any{"status": service.StatusDeactivated}); err != nil {
		t.Fatal(err)
	}
	next, err := f.challenge(t, keyID)
	if err != nil {
		t.Fatalf("CreateAgentMachineChallenge: %v", err)
	}
	_, err = f.exchange(t, keyID, next.ChallengeId, signP256(t, private)(next.Message))
	requireTeammateCode(t, "deactivated teammate", err, connect.CodeUnauthenticated)
	if got := teammateCounter(t, f.h, "identity_agent_exchanges_total", map[string]string{"key_kind": "teammate", "result": "refused"}); got < 4 {
		t.Fatalf("exchanges{teammate,refused} = %v", got)
	}
}

func TestTeammateKeys_RevocationIsImmediate(t *testing.T) {
	f := newTeammateFixture(t)
	private, public := p256Key(t)
	claim := f.claim("claim-revoke")
	keyID, err := f.register(t, claim, public, identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256)
	if err != nil {
		t.Fatalf("RegisterTeammateKey: %v", err)
	}
	pending, err := f.challenge(t, keyID)
	if err != nil {
		t.Fatalf("CreateAgentMachineChallenge: %v", err)
	}
	revoke := func(claimID string, reason identitypb.TeammateKeyRevocationReason) error {
		_, err := f.keys.RevokeTeammateKey(context.Background(), connect.NewRequest(&identitypb.RevokeTeammateKeyRequest{ClaimId: claimID, Reason: reason}))
		return err
	}
	if err = revoke(claim, identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_RELEASED); err != nil {
		t.Fatalf("RevokeTeammateKey: %v", err)
	}
	_, err = f.exchange(t, keyID, pending.ChallengeId, signP256(t, private)(pending.Message))
	requireTeammateCode(t, "challenge issued before revocation", err, connect.CodeUnauthenticated)
	_, err = f.challenge(t, keyID)
	requireTeammateCode(t, "challenge after revocation", err, connect.CodeUnauthenticated)
	if err = revoke(claim, identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_REMOVED); err != nil {
		t.Fatalf("second RevokeTeammateKey: %v", err)
	}
	if err = revoke(f.claim("never-registered"), identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_DRIFTED); err != nil {
		t.Fatalf("RevokeTeammateKey(unknown): %v", err)
	}
	requireTeammateCode(t, "unspecified reason", revoke(claim, identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_UNSPECIFIED), connect.CodeInvalidArgument)
	_, err = f.register(t, claim, public, identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256)
	requireTeammateCode(t, "re-register a revoked claim", err, connect.CodeFailedPrecondition)
	if got := teammateCounter(t, f.h, "identity_teammate_keys_revoked_total", nil); got != 1 {
		t.Fatalf("revoked = %v", got)
	}
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
