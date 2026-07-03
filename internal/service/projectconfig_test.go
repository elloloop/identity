package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProjectConfig_Empty_ReturnsZero(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "   ", "\n\t"} {
		cfg, err := ParseProjectConfig(in)
		require.NoError(t, err)
		assert.Empty(t, cfg.CORS.AllowedOrigins)
	}
}

func TestParseProjectConfig_CORSOrigins(t *testing.T) {
	t.Parallel()

	cfg, err := ParseProjectConfig(`{"cors":{"allowed_origins":["https://a.example.com","http://localhost:3000"]}}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://a.example.com", "http://localhost:3000"}, cfg.CORS.AllowedOrigins)
}

func TestParseProjectConfig_LoginDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := ParseProjectConfig(`{"login":{"allowed_methods":"email_otp,password","require_2fa":true}}`)
	require.NoError(t, err)
	assert.Equal(t, "email_otp,password", cfg.Login.AllowedMethods)
	assert.True(t, cfg.Login.Require2FA)
}

func TestParseProjectConfig_LoginDefaults_OmittedIsZero(t *testing.T) {
	t.Parallel()

	// An older config (CORS only) leaves the login default zero = no restriction.
	cfg, err := ParseProjectConfig(`{"cors":{"allowed_origins":["https://a.example.com"]}}`)
	require.NoError(t, err)
	assert.Empty(t, cfg.Login.AllowedMethods)
	assert.False(t, cfg.Login.Require2FA)
}

func TestParseProjectConfig_UnknownKeysTolerated(t *testing.T) {
	t.Parallel()

	cfg, err := ParseProjectConfig(`{"future_knob":42,"cors":{"allowed_origins":["https://a.example.com"]}}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://a.example.com"}, cfg.CORS.AllowedOrigins)
}

func TestParseProjectConfig_Malformed_Errors(t *testing.T) {
	t.Parallel()

	_, err := ParseProjectConfig(`{"cors": `)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse project config")
}

func TestParseProjectConfig_Branding(t *testing.T) {
	t.Parallel()

	cfg, err := ParseProjectConfig(`{"branding":{
		"product_name":"Glassa Kids",
		"email_from":"no-reply@kids.example.com",
		"email_from_name":"Glassa Kids",
		"logo_url":"https://kids.example.com/logo.png",
		"primary_color":"#1a73e8",
		"support_email":"help@kids.example.com"
	}}`)
	require.NoError(t, err)
	assert.Equal(t, "Glassa Kids", cfg.Branding.ProductName)
	assert.Equal(t, "no-reply@kids.example.com", cfg.Branding.EmailFrom)
	assert.Equal(t, "Glassa Kids", cfg.Branding.EmailFromName)
	assert.Equal(t, "https://kids.example.com/logo.png", cfg.Branding.LogoURL)
	assert.Equal(t, "#1a73e8", cfg.Branding.PrimaryColor)
	assert.Equal(t, "help@kids.example.com", cfg.Branding.SupportEmail)
}

func TestParseProjectConfig_Passkey(t *testing.T) {
	t.Parallel()

	cfg, err := ParseProjectConfig(`{"passkey":{
		"rp_id":"kids.example.com",
		"rp_name":"Glassa Kids",
		"origin":"https://kids.example.com"
	}}`)
	require.NoError(t, err)
	assert.Equal(t, "kids.example.com", cfg.Passkey.RPID)
	assert.Equal(t, "Glassa Kids", cfg.Passkey.RPName)
	assert.Equal(t, "https://kids.example.com", cfg.Passkey.Origin)
}

func TestParseProjectConfig_InvalidBrandingOrPasskey_Rejected(t *testing.T) {
	t.Parallel()

	for name, blob := range map[string]string{
		"bad email_from":    `{"branding":{"email_from":"not-an-address"}}`,
		"bad support_email": `{"branding":{"support_email":"nope"}}`,
		"non-https logo":    `{"branding":{"logo_url":"http://insecure.example.com/l.png"}}`,
		"rp_id with scheme": `{"passkey":{"rp_id":"https://kids.example.com"}}`,
		"rp_id with port":   `{"passkey":{"rp_id":"kids.example.com:443"}}`,
		"bad origin":        `{"passkey":{"origin":"kids.example.com"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseProjectConfig(blob)
			require.Error(t, err, "expected %s to be rejected", name)
		})
	}
}

func TestParseProjectConfig_EmptyBlocksValid(t *testing.T) {
	t.Parallel()

	// Every branding/passkey field is optional: an empty block is valid and
	// means "fall back to the global default".
	cfg, err := ParseProjectConfig(`{"branding":{},"passkey":{}}`)
	require.NoError(t, err)
	assert.Empty(t, cfg.Branding.ProductName)
	assert.Empty(t, cfg.Passkey.RPID)
}

func TestParseProjectConfig_OAuth_Present(t *testing.T) {
	t.Parallel()

	cfg, err := ParseProjectConfig(`{"oauth":{
		"google":{"client_id":"g","client_secret_enc":"enc-g","issuer":"https://accounts.google.com"},
		"microsoft":{"client_id":"m","client_secret_enc":"enc-m","tenant_id":"11111111-1111-1111-1111-111111111111"},
		"apple":{"client_id":"a","team_id":"team","key_id":"kid","private_key_enc":"enc-pk"},
		"oidc":{"client_id":"o","client_secret_enc":"enc-o","issuer":"https://issuer.example","scopes":"openid email"}
	}}`)
	require.NoError(t, err)
	require.NotNil(t, cfg.OAuth.Google)
	assert.Equal(t, "g", cfg.OAuth.Google.ClientID)
	assert.Equal(t, "enc-g", cfg.OAuth.Google.ClientSecretEnc)
	require.NotNil(t, cfg.OAuth.Microsoft)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", cfg.OAuth.Microsoft.TenantID)
	require.NotNil(t, cfg.OAuth.Apple)
	assert.Equal(t, "enc-pk", cfg.OAuth.Apple.PrivateKeyEnc)
	require.NotNil(t, cfg.OAuth.OIDC)
	assert.Equal(t, "openid email", cfg.OAuth.OIDC.Scopes)
	assert.True(t, cfg.OAuth.hasAny())
}

func TestParseProjectConfig_OAuth_Absent(t *testing.T) {
	t.Parallel()

	cfg, err := ParseProjectConfig(`{"cors":{"allowed_origins":["https://a.example.com"]}}`)
	require.NoError(t, err)
	assert.Nil(t, cfg.OAuth.Google)
	assert.False(t, cfg.OAuth.hasAny())
}

func TestParseProjectConfig_OAuth_PartialGoogleRejected(t *testing.T) {
	t.Parallel()

	// A configured google block missing its secret must fail the write.
	_, err := ParseProjectConfig(`{"oauth":{"google":{"client_id":"g"}}}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oauth.google requires")
}

func TestParseProjectConfig_OAuth_PartialAppleRejected(t *testing.T) {
	t.Parallel()

	_, err := ParseProjectConfig(`{"oauth":{"apple":{"client_id":"a","team_id":"team"}}}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oauth.apple requires")
}

func TestParseProjectConfig_OAuth_OIDCRequiresIssuer(t *testing.T) {
	t.Parallel()

	_, err := ParseProjectConfig(`{"oauth":{"oidc":{"client_id":"o","client_secret_enc":"enc"}}}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oauth.oidc requires issuer")
}

func TestParseProjectConfig_OAuth_GoogleBadURLRejected(t *testing.T) {
	t.Parallel()

	_, err := ParseProjectConfig(`{"oauth":{"google":{"client_id":"g","client_secret_enc":"enc","token_url":"ftp://nope"}}}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oauth.google.token_url")
}

func TestParseProjectConfig_OAuth_NativeAudiences_Present(t *testing.T) {
	t.Parallel()

	// A provider block may carry hosted credentials AND native audiences, or
	// either alone. Here Google has both, Microsoft has both (+tenant/issuer),
	// Apple is native-only.
	cfg, err := ParseProjectConfig(`{"oauth":{
		"google":{"client_id":"g","client_secret_enc":"enc-g","native_audiences":["web.g","ios.g"]},
		"microsoft":{"client_id":"m","client_secret_enc":"enc-m","tenant_id":"11111111-1111-1111-1111-111111111111","issuer_format":"https://login.microsoftonline.com/%s/v2.0","native_audiences":["ms.app"]},
		"apple":{"native_audiences":["com.a.app","com.a.web"]}
	}}`)
	require.NoError(t, err)
	require.NotNil(t, cfg.OAuth.Google)
	assert.Equal(t, []string{"web.g", "ios.g"}, cfg.OAuth.Google.NativeAudiences)
	require.NotNil(t, cfg.OAuth.Microsoft)
	assert.Equal(t, []string{"ms.app"}, cfg.OAuth.Microsoft.NativeAudiences)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", cfg.OAuth.Microsoft.TenantID)
	require.NotNil(t, cfg.OAuth.Apple)
	assert.Equal(t, []string{"com.a.app", "com.a.web"}, cfg.OAuth.Apple.NativeAudiences)

	// The accessor returns the right list per provider.
	assert.Equal(t, []string{"web.g", "ios.g"}, cfg.OAuth.nativeAudiences("google"))
	assert.Equal(t, []string{"ms.app"}, cfg.OAuth.nativeAudiences("microsoft"))
	assert.Equal(t, []string{"com.a.app", "com.a.web"}, cfg.OAuth.nativeAudiences("apple"))
}

func TestParseProjectConfig_OAuth_NativeAudiences_Absent(t *testing.T) {
	t.Parallel()

	// Hosted-only blocks (no native_audiences) yield nil for the native accessor.
	cfg, err := ParseProjectConfig(`{"oauth":{
		"google":{"client_id":"g","client_secret_enc":"enc-g"},
		"apple":{"client_id":"a","team_id":"team","key_id":"kid","private_key_enc":"enc-pk"}
	}}`)
	require.NoError(t, err)
	assert.Nil(t, cfg.OAuth.nativeAudiences("google"))
	assert.Nil(t, cfg.OAuth.nativeAudiences("apple"))
	assert.Nil(t, cfg.OAuth.nativeAudiences("microsoft")) // provider absent entirely
}

func TestParseProjectConfig_OAuth_MicrosoftAllowedTenants_Present(t *testing.T) {
	t.Parallel()

	cfg, err := ParseProjectConfig(`{"oauth":{
		"microsoft":{"client_id":"m","client_secret_enc":"enc-m","allowed_tenants":["11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222"]}
	}}`)
	require.NoError(t, err)
	require.NotNil(t, cfg.OAuth.Microsoft)
	assert.Equal(t,
		[]string{"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"},
		cfg.OAuth.Microsoft.AllowedTenants)
}

func TestParseProjectConfig_OAuth_MicrosoftAllowedTenants_Invalid(t *testing.T) {
	t.Parallel()

	// Only a directory GUID is a valid entry. A verified-domain form
	// ("contoso.onmicrosoft.com") is a config error — a token's `tid` is always a
	// GUID, so a domain entry would silently never match. So are non-GUID junk,
	// embedded whitespace, and empty. Every one must be rejected at parse time.
	for _, bad := range []string{"contoso.onmicrosoft.com", "example.co", "not a tenant", "common", "-", ""} {
		blob := `{"oauth":{"microsoft":{"client_id":"m","client_secret_enc":"enc-m","allowed_tenants":["` + bad + `"]}}}`
		_, err := ParseProjectConfig(blob)
		require.Error(t, err, "entry %q must be rejected", bad)
		assert.Contains(t, err.Error(), "allowed_tenants")
	}
}

func TestParseProjectConfig_OAuth_NativeOnlyBlocks_Valid(t *testing.T) {
	t.Parallel()

	// A native-only block (native_audiences, no hosted credentials) is valid for
	// each provider — a project may enable native login without the hosted flow.
	for name, blob := range map[string]string{
		"google":    `{"oauth":{"google":{"native_audiences":["web.g"]}}}`,
		"microsoft": `{"oauth":{"microsoft":{"native_audiences":["ms.app"]}}}`,
		"apple":     `{"oauth":{"apple":{"native_audiences":["com.a.app"]}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := ParseProjectConfig(blob)
			require.NoError(t, err)
			assert.Len(t, cfg.OAuth.nativeAudiences(name), 1)
		})
	}
}

func TestParseProjectConfig_OAuth_PartialMicrosoftHostedRejected(t *testing.T) {
	t.Parallel()

	// A Microsoft block with a hosted client_id but no secret AND no native
	// audiences is a half-filled hosted block — rejected.
	_, err := ParseProjectConfig(`{"oauth":{"microsoft":{"client_id":"m"}}}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oauth.microsoft requires")
}

func TestParseProjectConfig_OAuth_EmptyProviderBlockRejected(t *testing.T) {
	t.Parallel()

	// A wholly-empty provider block (neither hosted creds nor native audiences)
	// is a config error for each provider.
	for name, blob := range map[string]string{
		"google":    `{"oauth":{"google":{}}}`,
		"microsoft": `{"oauth":{"microsoft":{}}}`,
		"apple":     `{"oauth":{"apple":{}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseProjectConfig(blob)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "oauth."+name+" requires")
		})
	}
}
