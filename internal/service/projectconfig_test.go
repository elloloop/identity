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
		"microsoft":{"client_id":"m","client_secret_enc":"enc-m","tenant_id":"t"},
		"apple":{"client_id":"a","team_id":"team","key_id":"kid","private_key_enc":"enc-pk"},
		"oidc":{"client_id":"o","client_secret_enc":"enc-o","issuer":"https://issuer.example","scopes":"openid email"}
	}}`)
	require.NoError(t, err)
	require.NotNil(t, cfg.OAuth.Google)
	assert.Equal(t, "g", cfg.OAuth.Google.ClientID)
	assert.Equal(t, "enc-g", cfg.OAuth.Google.ClientSecretEnc)
	require.NotNil(t, cfg.OAuth.Microsoft)
	assert.Equal(t, "t", cfg.OAuth.Microsoft.TenantID)
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
