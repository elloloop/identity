package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/secretcrypto"
)

// This file adds the operator-authored write/read surface for a project's
// hosted/native OAuth providers — the authoring gap the per-project OAuth
// feature left open (an operator would otherwise have to hand-craft the
// AES-GCM ciphertext of each secret and splice it into config_json by hand).
//
// The operator sends PLAINTEXT secrets over the admin API (TLS); the service
// encrypts them with the configured GATEWAY_PROJECT_SECRETS_KEY (the same key
// the resolver decrypts with) and stores them in the project's config_json.
// Reads NEVER return secret material — they report presence via has_* flags.
//
// Every write is a JSON-level READ-MODIFY-WRITE that byte-preserves every key it
// does not touch. UpdateProjectConfig replaces the WHOLE blob, so the merge
// decodes BOTH the top level AND the "oauth" subtree into map[string]RawMessage
// and replaces (Set) or removes (Delete) exactly one provider key inside the
// oauth map — every other top-level key (branding/passkey/cors/login) and every
// other oauth key (a sibling provider, or an unknown key a newer binary wrote)
// survives verbatim, so a set/delete is never a lossy rewrite. Only the ONE
// provider being Set is decoded + validated at author time; Delete just removes
// a key, so a stale invalid neighbour never blocks an unrelated deletion.

// OAuth provider keys, mirroring the login `provider` argument callers pass.
const (
	oauthProviderGoogle    = "google"
	oauthProviderMicrosoft = "microsoft"
	oauthProviderApple     = "apple"
	oauthProviderOIDC      = "oidc"
)

// oauthProviderKeys is the canonical (sorted) set of configurable provider
// keys, used to enumerate a project's providers deterministically.
var oauthProviderKeys = []string{oauthProviderApple, oauthProviderGoogle, oauthProviderMicrosoft, oauthProviderOIDC}

// ProjectOAuthProviderInput is the operator-supplied authoring input for one of
// a project's OAuth providers. Secret fields (ClientSecret, ApplePrivateKey)
// are PLAINTEXT — the service encrypts them with the configured secrets key
// before storage. An EMPTY secret on a write keeps the currently-stored secret,
// so non-secret fields can be edited without re-sending it.
type ProjectOAuthProviderInput struct {
	Provider        string
	ClientID        string
	ClientSecret    string
	NativeAudiences []string

	GoogleAuthorizationURL string
	GoogleTokenURL         string
	GoogleJWKSURL          string
	GoogleIssuer           string

	MicrosoftTenantID     string
	MicrosoftIssuerFormat string

	AppleTeamID     string
	AppleKeyID      string
	ApplePrivateKey string

	OIDCIssuer       string
	OIDCDiscoveryURL string
	OIDCScopes       string
}

// ProjectOAuthProviderView is the REDACTED read view of one configured provider:
// every non-secret field plus HasClientSecret / HasPrivateKey in place of any
// secret material. No ciphertext or plaintext ever appears here.
type ProjectOAuthProviderView struct {
	Provider        string
	ClientID        string
	HasClientSecret bool
	NativeAudiences []string

	GoogleAuthorizationURL string
	GoogleTokenURL         string
	GoogleJWKSURL          string
	GoogleIssuer           string

	MicrosoftTenantID     string
	MicrosoftIssuerFormat string

	AppleTeamID   string
	AppleKeyID    string
	HasPrivateKey bool

	OIDCIssuer       string
	OIDCDiscoveryURL string
	OIDCScopes       string
}

// AdminSetProjectOAuthProvider sets (or rotates) one of a project's OAuth
// providers. It encrypts any plaintext secret in the input, merges the provider
// into the project's config_json without disturbing any other config key, and
// returns the stored provider config with secrets REDACTED. project_id and a
// known provider key are required. An unknown project surfaces ErrNotFound.
func (s *ControlPlaneAdminService) AdminSetProjectOAuthProvider(ctx context.Context, secret, projectID string, in *ProjectOAuthProviderInput) (*ProjectOAuthProviderView, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	if in == nil {
		return nil, fmt.Errorf("%w: missing config", ErrInvalidArgument)
	}
	provider, err := normalizeOAuthProvider(in.Provider)
	if err != nil {
		return nil, err
	}

	// The whole merge runs inside the optimistic-concurrency helper so a
	// concurrent write to a SIBLING provider can no longer clobber this one: on a
	// version conflict the helper re-reads fresh state and replays the merge.
	var view *ProjectOAuthProviderView
	if _, err := s.mutateProjectConfig(ctx, projectID, func(current string) (string, error) {
		top, oauthSub, err := decodeOAuthSubtree(current)
		if err != nil {
			return "", err
		}
		// Build the typed provider (encrypting any new secret, keeping the stored
		// one when the input secret is empty) and validate ONLY this provider.
		prov, err := s.buildProvider(provider, in, oauthSub[provider])
		if err != nil {
			return "", err
		}
		single := ProjectOAuthConfig{}
		assignProvider(&single, provider, prov)
		if err := single.validate(); err != nil {
			return "", fmt.Errorf("%w: %s", ErrInvalidArgument, err.Error())
		}
		raw, err := json.Marshal(prov)
		if err != nil {
			return "", fmt.Errorf("marshal oauth provider: %w", err)
		}
		oauthSub[provider] = raw
		view = providerView(provider, prov)
		return encodeOAuthSubtree(top, oauthSub)
	}); err != nil {
		return nil, err
	}

	s.audit.Log(ctx, audit.EventProjectOAuthProviderSet, audit.WithSuccess(true), audit.WithDetails(map[string]any{
		"project_id": projectID,
		"provider":   provider,
	}))
	return view, nil
}

// AdminDeleteProjectOAuthProvider removes one provider block from a project's
// config, leaving every other provider and every other config key intact
// (including keys this binary does not understand). It is idempotent — removing
// an absent provider is a no-op — and does NOT decode or validate the surviving
// providers, so a stale invalid neighbour never blocks the deletion. An unknown
// project surfaces ErrNotFound.
func (s *ControlPlaneAdminService) AdminDeleteProjectOAuthProvider(ctx context.Context, secret, projectID, provider string) error {
	if err := s.authorize(secret); err != nil {
		return err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	provider, err := normalizeOAuthProvider(provider)
	if err != nil {
		return err
	}

	if _, err := s.mutateProjectConfig(ctx, projectID, func(current string) (string, error) {
		top, oauthSub, err := decodeOAuthSubtree(current)
		if err != nil {
			return "", err
		}
		delete(oauthSub, provider)
		return encodeOAuthSubtree(top, oauthSub)
	}); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.EventProjectOAuthProviderRemoved, audit.WithSuccess(true), audit.WithDetails(map[string]any{
		"project_id": projectID,
		"provider":   provider,
	}))
	return nil
}

// AdminListProjectOAuthProviders lists a project's configured OAuth providers,
// ordered by provider key, with secrets REDACTED. Only the known provider keys
// are surfaced; an unknown key stored under "oauth" is preserved on write but
// not listed (its shape is unknown to this binary). An unknown project surfaces
// ErrNotFound.
func (s *ControlPlaneAdminService) AdminListProjectOAuthProviders(ctx context.Context, secret, projectID string) ([]*ProjectOAuthProviderView, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	stored, _, err := s.projects.GetProjectConfig(ctx, projectID)
	if err != nil {
		return nil, err
	}
	_, oauthSub, err := decodeOAuthSubtree(stored)
	if err != nil {
		return nil, err
	}
	out := make([]*ProjectOAuthProviderView, 0, len(oauthProviderKeys))
	for _, key := range oauthProviderKeys {
		raw, ok := oauthSub[key]
		if !ok || len(raw) == 0 {
			continue
		}
		prov, err := decodeProvider(key, raw)
		if err != nil {
			return nil, fmt.Errorf("%w: stored oauth.%s is malformed: %s", ErrInvalidArgument, key, err.Error())
		}
		out = append(out, providerView(key, prov))
	}
	return out, nil
}

// decodeOAuthSubtree decodes a stored config_json blob into its top-level object
// and its "oauth" subtree as raw-message maps, so every untouched key round-trips
// byte-for-byte. A blob that is not a JSON object, or whose "oauth" value is not
// an object, is an ErrInvalidArgument. It is pure — the read-modify-write helper
// owns the store I/O — so it can be replayed on a CAS retry.
func decodeOAuthSubtree(stored string) (top, oauthSub map[string]json.RawMessage, err error) {
	top = map[string]json.RawMessage{}
	if strings.TrimSpace(stored) != "" {
		if err := json.Unmarshal([]byte(stored), &top); err != nil {
			return nil, nil, fmt.Errorf("%w: stored project config is not a JSON object: %s", ErrInvalidArgument, err.Error())
		}
	}
	oauthSub = map[string]json.RawMessage{}
	if raw, ok := top["oauth"]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &oauthSub); err != nil {
			return nil, nil, fmt.Errorf("%w: stored oauth config is not a JSON object: %s", ErrInvalidArgument, err.Error())
		}
	}
	return top, oauthSub, nil
}

// encodeOAuthSubtree re-marshals the merged oauth subtree back into the
// top-level map (dropping the "oauth" key entirely when no key remains, so a
// project with no providers is not left with a dangling empty object) and
// returns the serialized blob. RawMessage values are emitted verbatim, so
// untouched providers and unknown keys are byte-preserved.
func encodeOAuthSubtree(top, oauthSub map[string]json.RawMessage) (string, error) {
	if len(oauthSub) > 0 {
		raw, err := json.Marshal(oauthSub)
		if err != nil {
			return "", fmt.Errorf("marshal oauth config: %w", err)
		}
		top["oauth"] = raw
	} else {
		delete(top, "oauth")
	}
	final, err := json.Marshal(top)
	if err != nil {
		return "", fmt.Errorf("marshal project config: %w", err)
	}
	return string(final), nil
}

// buildProvider builds the typed provider sub-struct from the input, encrypting
// any plaintext secret. An empty plaintext secret keeps the ciphertext already
// stored for that provider (decoded from existingRaw); every other field is
// fully replaced by the input, since a Set replaces the whole provider block.
func (s *ControlPlaneAdminService) buildProvider(provider string, in *ProjectOAuthProviderInput, existingRaw json.RawMessage) (any, error) {
	switch provider {
	case oauthProviderGoogle:
		keep := ""
		if len(existingRaw) > 0 {
			var g ProjectOAuthGoogle
			if json.Unmarshal(existingRaw, &g) == nil {
				keep = g.ClientSecretEnc
			}
		}
		enc, err := s.encryptOrKeep(in.ClientSecret, keep)
		if err != nil {
			return nil, err
		}
		return &ProjectOAuthGoogle{
			ClientID:         strings.TrimSpace(in.ClientID),
			ClientSecretEnc:  enc,
			AuthorizationURL: strings.TrimSpace(in.GoogleAuthorizationURL),
			TokenURL:         strings.TrimSpace(in.GoogleTokenURL),
			JWKSURL:          strings.TrimSpace(in.GoogleJWKSURL),
			Issuer:           strings.TrimSpace(in.GoogleIssuer),
			NativeAudiences:  normalizeAudiences(in.NativeAudiences),
		}, nil
	case oauthProviderMicrosoft:
		keep := ""
		if len(existingRaw) > 0 {
			var m ProjectOAuthMicrosoft
			if json.Unmarshal(existingRaw, &m) == nil {
				keep = m.ClientSecretEnc
			}
		}
		enc, err := s.encryptOrKeep(in.ClientSecret, keep)
		if err != nil {
			return nil, err
		}
		return &ProjectOAuthMicrosoft{
			ClientID:        strings.TrimSpace(in.ClientID),
			ClientSecretEnc: enc,
			TenantID:        strings.TrimSpace(in.MicrosoftTenantID),
			IssuerFormat:    strings.TrimSpace(in.MicrosoftIssuerFormat),
			NativeAudiences: normalizeAudiences(in.NativeAudiences),
		}, nil
	case oauthProviderApple:
		keep := ""
		if len(existingRaw) > 0 {
			var a ProjectOAuthApple
			if json.Unmarshal(existingRaw, &a) == nil {
				keep = a.PrivateKeyEnc
			}
		}
		enc, err := s.encryptOrKeep(in.ApplePrivateKey, keep)
		if err != nil {
			return nil, err
		}
		return &ProjectOAuthApple{
			ClientID:        strings.TrimSpace(in.ClientID),
			TeamID:          strings.TrimSpace(in.AppleTeamID),
			KeyID:           strings.TrimSpace(in.AppleKeyID),
			PrivateKeyEnc:   enc,
			NativeAudiences: normalizeAudiences(in.NativeAudiences),
		}, nil
	case oauthProviderOIDC:
		// The generic OIDC provider is hosted-only: it has no native-audience
		// allow-list, so accepting native_audiences here would silently drop
		// them. Reject rather than discard operator intent without signal.
		if len(normalizeAudiences(in.NativeAudiences)) > 0 {
			return nil, fmt.Errorf("%w: oauth.oidc does not support native_audiences; native login supports google, apple, microsoft", ErrInvalidArgument)
		}
		keep := ""
		if len(existingRaw) > 0 {
			var o ProjectOAuthOIDC
			if json.Unmarshal(existingRaw, &o) == nil {
				keep = o.ClientSecretEnc
			}
		}
		enc, err := s.encryptOrKeep(in.ClientSecret, keep)
		if err != nil {
			return nil, err
		}
		return &ProjectOAuthOIDC{
			ClientID:        strings.TrimSpace(in.ClientID),
			ClientSecretEnc: enc,
			Issuer:          strings.TrimSpace(in.OIDCIssuer),
			DiscoveryURL:    strings.TrimSpace(in.OIDCDiscoveryURL),
			Scopes:          strings.TrimSpace(in.OIDCScopes),
		}, nil
	}
	// Unreachable: provider is normalized to one of the four keys above.
	return nil, fmt.Errorf("%w: unknown oauth provider %q", ErrInvalidArgument, provider)
}

// decodeProvider unmarshals one provider's stored JSON into its typed struct,
// so a redacted view can be built for a list/read.
func decodeProvider(provider string, raw json.RawMessage) (any, error) {
	switch provider {
	case oauthProviderGoogle:
		var g ProjectOAuthGoogle
		if err := json.Unmarshal(raw, &g); err != nil {
			return nil, err
		}
		return &g, nil
	case oauthProviderMicrosoft:
		var m ProjectOAuthMicrosoft
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		return &m, nil
	case oauthProviderApple:
		var a ProjectOAuthApple
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
		return &a, nil
	case oauthProviderOIDC:
		var o ProjectOAuthOIDC
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		return &o, nil
	}
	return nil, fmt.Errorf("unknown oauth provider %q", provider)
}

// assignProvider installs a built typed provider onto a ProjectOAuthConfig, so
// the shared per-provider validation (ProjectOAuthConfig.validate) can run
// against exactly the one provider being set.
func assignProvider(cfg *ProjectOAuthConfig, provider string, prov any) {
	switch p := prov.(type) {
	case *ProjectOAuthGoogle:
		cfg.Google = p
	case *ProjectOAuthMicrosoft:
		cfg.Microsoft = p
	case *ProjectOAuthApple:
		cfg.Apple = p
	case *ProjectOAuthOIDC:
		cfg.OIDC = p
	}
}

// encryptOrKeep encrypts a plaintext secret for at-rest storage, or returns the
// existing ciphertext unchanged when the operator supplied no new secret (an
// empty plaintext means "keep whatever is stored"). Encrypting requires the
// configured secrets key; a write that carries a secret with no key configured
// is ErrProjectSecretsKeyMissing.
func (s *ControlPlaneAdminService) encryptOrKeep(plaintext, existingEnc string) (string, error) {
	if plaintext == "" {
		return existingEnc, nil
	}
	if len(s.secretsKey) == 0 {
		return "", ErrProjectSecretsKeyMissing
	}
	return secretcrypto.Encrypt(plaintext, s.secretsKey)
}

// providerView renders the redacted read view of a single typed provider.
func providerView(provider string, prov any) *ProjectOAuthProviderView {
	v := &ProjectOAuthProviderView{Provider: provider}
	switch p := prov.(type) {
	case *ProjectOAuthGoogle:
		v.ClientID = p.ClientID
		v.HasClientSecret = p.ClientSecretEnc != ""
		v.NativeAudiences = p.NativeAudiences
		v.GoogleAuthorizationURL = p.AuthorizationURL
		v.GoogleTokenURL = p.TokenURL
		v.GoogleJWKSURL = p.JWKSURL
		v.GoogleIssuer = p.Issuer
	case *ProjectOAuthMicrosoft:
		v.ClientID = p.ClientID
		v.HasClientSecret = p.ClientSecretEnc != ""
		v.NativeAudiences = p.NativeAudiences
		v.MicrosoftTenantID = p.TenantID
		v.MicrosoftIssuerFormat = p.IssuerFormat
	case *ProjectOAuthApple:
		v.ClientID = p.ClientID
		v.HasPrivateKey = p.PrivateKeyEnc != ""
		v.NativeAudiences = p.NativeAudiences
		v.AppleTeamID = p.TeamID
		v.AppleKeyID = p.KeyID
	case *ProjectOAuthOIDC:
		v.ClientID = p.ClientID
		v.HasClientSecret = p.ClientSecretEnc != ""
		v.OIDCIssuer = p.Issuer
		v.OIDCDiscoveryURL = p.DiscoveryURL
		v.OIDCScopes = p.Scopes
	}
	return v
}

// normalizeAudiences trims each native-audience entry and drops the empties,
// returning nil when nothing remains (so an all-blank list is stored as absent).
func normalizeAudiences(in []string) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeOAuthProvider lower-cases/trims a provider key and rejects any that
// is not one of the four configurable providers.
func normalizeOAuthProvider(provider string) (string, error) {
	switch k := strings.ToLower(strings.TrimSpace(provider)); k {
	case oauthProviderGoogle, oauthProviderMicrosoft, oauthProviderApple, oauthProviderOIDC:
		return k, nil
	default:
		return "", fmt.Errorf("%w: unknown oauth provider %q (want %q, %q, %q, or %q)",
			ErrInvalidArgument, provider, oauthProviderGoogle, oauthProviderMicrosoft, oauthProviderApple, oauthProviderOIDC)
	}
}
