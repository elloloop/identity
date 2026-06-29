//go:build browsere2e

package browsere2e

import (
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"

	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/repo"
	"github.com/elloloop/identity/pkg/jwt/jwttest"
	"github.com/elloloop/identity/pkg/passkeys"
)

// passkeyDeviceName is the label the ceremony registers the virtual
// authenticator under, asserted nowhere but kept out of the JS as a literal.
const passkeyDeviceName = "Virtual Authenticator"

// passkeyStartServer boots the same real app handler + postgres testcontainer
// as the harness's startServer, but pins the listener to a known port FIRST so
// the WebAuthn relying-party Origin (and RP-ID) can be configured to match the
// page origin the browser will actually use.
//
// WebAuthn binds the ceremony to an exact origin: go-webauthn compares
// clientDataJSON.origin (scheme + host + PORT) against the RP's configured
// origins, and the browser requires the RP-ID to be a registrable suffix of the
// page host. The harness's fixed http://localhost (no port) cannot match a
// random httptest port, so this boot derives the origin from the bound port and
// serves on "localhost" (RP-ID "localhost" is a valid registrable suffix of
// localhost:<port>). Everything else mirrors startServer; the harness helpers
// (startPostgresContainer, newUIConfig, the fixture constants) are reused
// verbatim.
//
// Returns the base URL the browser navigates to (http://localhost:<port>/).
func passkeyStartServer(t *testing.T) string {
	t.Helper()

	// Container-boot budget, matching startServer's own context.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dsn := startPostgresContainer(ctx, t)

	// Bind the listener up front so the port — and therefore the WebAuthn
	// origin — is known before the relying-party instance is built.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	rpID := "localhost"
	origin := fmt.Sprintf("http://localhost:%d", port)

	projectID := "browsere2e"
	cfg := newUIConfig(true /* signup enabled */, projectID)
	// Keep the global config consistent with the relying party we build below;
	// the per-project override path is unused (no project config), so the global
	// passkeys instance is what every ceremony resolves to.
	cfg.PasskeyRPID = rpID
	cfg.PasskeyOrigin = origin
	// newUIConfig leaves this at zero, which would expire every passkey
	// challenge the instant it is stored (now + 0s). Give the browser real time
	// to run the create/get ceremony between Begin and Complete.
	cfg.PasskeyChallengeExpirySeconds = 300

	built, err := repo.Build(ctx, repo.Config{
		Driver:              repo.DriverPostgres,
		PostgresDSN:         dsn,
		PostgresMaxConns:    5,
		PostgresAutoMigrate: true,
		ProjectID:           cfg.DefaultProjectID,
	}, zap.NewNop())
	require.NoError(t, err)
	if closer, ok := built.Repository.(interface{ Close() }); ok {
		t.Cleanup(closer.Close)
	}

	_, err = built.ProjectStore.EnsureDefaultProject(
		ctx, cfg.DefaultProjectID, cfg.DefaultTenantID, "browsere2e",
	)
	require.NoError(t, err)

	signer := jwttest.NewSigner(t, "browsere2e-passkey-kid")

	// The relying party bound to the real serving origin. With no per-project
	// passkey override configured, AuthService.passkeysFor returns this global
	// instance for both the registration and the login ceremony, so the origin
	// the browser presents matches what the server validates.
	pkSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   rpID,
		RPName: cfg.PasskeyRPName,
		Origin: origin,
	})
	require.NoError(t, err)

	appBuilt, err := app.New(app.Deps{
		Config:             cfg,
		Logger:             zap.NewNop(),
		Signer:             signer,
		Repo:               built.Repository,
		DB:                 built.DB,
		Passkeys:           pkSvc,
		TOTPKey:            []byte(totpKey),
		TOTPRecoveryPepper: []byte(totpRecoveryPepper),
		ProjectResolver:    built.ProjectResolver(),
	})
	require.NoError(t, err)
	appBuilt.Start()
	t.Cleanup(appBuilt.Stop)

	srv := httptest.NewUnstartedServer(appBuilt.Handler)
	// Replace httptest's auto-bound listener with ours so the server serves on
	// the port the origin above was derived from.
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	return origin + "/"
}

// passkeyEnableVirtualAuthenticator turns on the CDP WebAuthn domain and adds a
// CTAP2 internal virtual authenticator that is backup-ELIGIBLE and
// backup-STATE-set. The backup flags are the whole point: PR #283 dropped the
// BE/BS flags at registration, so the login assertion (which an eligible
// authenticator always marks BE=1) no longer matched the stored credential and
// verification failed. Setting DefaultBackupEligibility/DefaultBackupState true
// reproduces a real platform passkey (e.g. iCloud Keychain) and exercises that
// replay path.
func passkeyEnableVirtualAuthenticator(t *testing.T, ctx context.Context) {
	t.Helper()
	opts := &webauthn.VirtualAuthenticatorOptions{
		Protocol:                    webauthn.AuthenticatorProtocolCtap2,
		Transport:                   webauthn.AuthenticatorTransportInternal,
		HasResidentKey:              true,
		HasUserVerification:         true,
		AutomaticPresenceSimulation: true,
		IsUserVerified:              true,
		DefaultBackupEligibility:    true,
		DefaultBackupState:          true,
	}
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		if err := webauthn.Enable().Do(ctx); err != nil {
			return fmt.Errorf("webauthn.Enable: %w", err)
		}
		if _, err := webauthn.AddVirtualAuthenticator(opts).Do(ctx); err != nil {
			return fmt.Errorf("AddVirtualAuthenticator: %w", err)
		}
		return nil
	}))
	require.NoError(t, err, "enable + add backup-eligible virtual authenticator")
}

// passkeyCeremonyResult is the shape the injected JS resolves to. Exactly one of
// (Error) / (AccessToken,...) is populated.
type passkeyCeremonyResult struct {
	Stage        string `json:"stage"`
	Error        string `json:"error"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	UserEmail    string `json:"userEmail"`
}

// passkeyCeremonyJS runs the entire register→login round-trip from the page's
// own origin: PasswordSignup → BeginPasskeyRegistration → navigator.credentials
// .create → CompletePasskeyRegistration → BeginPasskeyLogin → navigator
// .credentials.get → CompletePasskeyLogin. It returns a result object so a
// server-side rejection surfaces as a readable failure with its stage instead
// of a bare timeout.
//
// The WebAuthn options the server emits carry base64url strings (challenge,
// user.id, credential ids); navigator.credentials needs ArrayBuffers, and the
// attestation/assertion must be re-serialized to the standard WebAuthn base64url
// JSON the go-webauthn parser expects. Both conversions live here.
func passkeyCeremonyJS(email, password string) string {
	return fmt.Sprintf(`
(async () => {
  const result = {stage: 'start'};
  const EMAIL = %q, PASSWORD = %q, DEVICE = %q;

  function b64urlToBuf(s) {
    s = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length %% 4) s += '=';
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }
  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  async function rpc(method, body, token) {
    const headers = {'Content-Type': 'application/json'};
    if (token) headers['Authorization'] = 'Bearer ' + token;
    const r = await fetch('/identity.v1.IdentityService/' + method, {
      method: 'POST', headers, body: JSON.stringify(body),
    });
    let j = {};
    try { j = await r.json(); } catch (e) {}
    return {ok: r.ok, status: r.status, body: j};
  }

  try {
    // 1. Create an authenticated user.
    result.stage = 'signup';
    const su = await rpc('PasswordSignup', {email: EMAIL, password: PASSWORD});
    if (!su.ok) { result.error = 'signup ' + su.status + ':' + JSON.stringify(su.body); return result; }
    const token = su.body.accessToken || su.body.access_token;
    if (!token) { result.error = 'no signup token:' + JSON.stringify(su.body); return result; }

    // 2. Begin registration (authenticated) and run the create ceremony.
    result.stage = 'beginRegistration';
    const br = await rpc('BeginPasskeyRegistration', {deviceName: DEVICE}, token);
    if (!br.ok) { result.error = 'beginRegistration ' + br.status + ':' + JSON.stringify(br.body); return result; }
    const regChallengeId = br.body.challengeId || br.body.challenge_id;
    const creation = JSON.parse(br.body.optionsJson || br.body.options_json);
    const cpk = creation.publicKey;
    cpk.challenge = b64urlToBuf(cpk.challenge);
    cpk.user.id = b64urlToBuf(cpk.user.id);
    if (Array.isArray(cpk.excludeCredentials)) {
      cpk.excludeCredentials.forEach(c => { c.id = b64urlToBuf(c.id); });
    }
    result.stage = 'credentials.create';
    const att = await navigator.credentials.create({publicKey: cpk});
    const attJSON = JSON.stringify({
      id: att.id,
      rawId: bufToB64url(att.rawId),
      type: att.type,
      response: {
        attestationObject: bufToB64url(att.response.attestationObject),
        clientDataJSON: bufToB64url(att.response.clientDataJSON),
      },
    });

    // 3. Complete registration — stores the credential incl. backup flags.
    result.stage = 'completeRegistration';
    const cr = await rpc('CompletePasskeyRegistration',
      {challengeId: regChallengeId, credentialJson: attJSON, deviceName: DEVICE}, token);
    if (!cr.ok) { result.error = 'completeRegistration ' + cr.status + ':' + JSON.stringify(cr.body); return result; }

    // 4. Begin login (scoped to the email) and run the get ceremony.
    result.stage = 'beginLogin';
    const bl = await rpc('BeginPasskeyLogin', {email: EMAIL});
    if (!bl.ok) { result.error = 'beginLogin ' + bl.status + ':' + JSON.stringify(bl.body); return result; }
    const loginChallengeId = bl.body.challengeId || bl.body.challenge_id;
    const request = JSON.parse(bl.body.optionsJson || bl.body.options_json);
    const rpk = request.publicKey;
    rpk.challenge = b64urlToBuf(rpk.challenge);
    if (Array.isArray(rpk.allowCredentials)) {
      rpk.allowCredentials.forEach(c => { c.id = b64urlToBuf(c.id); });
    }
    result.stage = 'credentials.get';
    const asn = await navigator.credentials.get({publicKey: rpk});
    const asnJSON = JSON.stringify({
      id: asn.id,
      rawId: bufToB64url(asn.rawId),
      type: asn.type,
      response: {
        authenticatorData: bufToB64url(asn.response.authenticatorData),
        clientDataJSON: bufToB64url(asn.response.clientDataJSON),
        signature: bufToB64url(asn.response.signature),
        userHandle: asn.response.userHandle ? bufToB64url(asn.response.userHandle) : null,
      },
    });

    // 5. Complete login — verifies user-handle + replays backup flags.
    result.stage = 'completeLogin';
    const cl = await rpc('CompletePasskeyLogin', {challengeId: loginChallengeId, credentialJson: asnJSON});
    if (!cl.ok) { result.error = 'completeLogin ' + cl.status + ':' + JSON.stringify(cl.body); return result; }

    result.stage = 'done';
    result.accessToken = cl.body.accessToken || cl.body.access_token || '';
    result.refreshToken = cl.body.refreshToken || cl.body.refresh_token || '';
    result.userEmail = (cl.body.user && cl.body.user.email) || '';
    return result;
  } catch (e) {
    result.error = 'exception@' + result.stage + ':' + (e && e.message ? e.message : String(e));
    return result;
  }
})()
`, email, password, passkeyDeviceName)
}

// TestBrowser_Passkey_RegisterThenLogin_VirtualAuthenticator drives a real
// WebAuthn register→login round-trip through a Chrome virtual authenticator and
// asserts the login issues tokens. It is the regression test for PR #283: a
// successful CompletePasskeyLogin proves both that the assertion's user handle
// matched the real user id (not a placeholder) and that the backup-eligibility
// / backup-state flags survived registration and replayed at login — the
// virtual authenticator is configured backup-eligible specifically to exercise
// that flag path.
func TestBrowser_Passkey_RegisterThenLogin_VirtualAuthenticator(t *testing.T) {
	// Skip before the (slow, Docker-dependent) container boot when no browser is
	// present, matching the harness's skip pattern.
	requireChrome(t)

	baseURL := passkeyStartServer(t)
	ctx := newBrowser(t)

	// The virtual authenticator must exist before the page calls
	// navigator.credentials.create/get.
	passkeyEnableVirtualAuthenticator(t, ctx)

	email := uniqueEmail("passkey")
	const password = "Sup3rSecret!pw"

	require.NoError(t, chromedp.Run(ctx, chromedp.Navigate(baseURL)))

	var result passkeyCeremonyResult
	err := chromedp.Run(ctx,
		chromedp.Evaluate(passkeyCeremonyJS(email, password), &result,
			func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
				return p.WithAwaitPromise(true)
			}),
	)
	require.NoError(t, err, "evaluate passkey ceremony")
	require.Empty(t, result.Error,
		"passkey ceremony failed at stage %q: %s", result.Stage, result.Error)

	require.Equal(t, "done", result.Stage)
	require.NotEmpty(t, result.AccessToken,
		"CompletePasskeyLogin must return an access token — proves the full "+
			"register→login round-trip incl. user-handle check and backup-flag replay")
	require.NotEmpty(t, result.RefreshToken,
		"CompletePasskeyLogin must return a refresh token")
	require.Equal(t, email, result.UserEmail,
		"the passkey login must resolve to the registering user")
}
