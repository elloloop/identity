package service

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
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
//
// A host's own client for a provider (ADR-0019) lives one level down, under
// oauth.hosts.<host>.<provider>. It has its own Set and Delete calls, so a
// write meant for one host's client can never reach the base provider, and
// AdminListProjectOAuthProviders lists it beside the providers.

// OAuth provider keys, mirroring the login `provider` argument callers pass.
const (
	oauthProviderGoogle    = "google"
	oauthProviderMicrosoft = "microsoft"
	oauthProviderApple     = "apple"
	oauthProviderGitHub    = "github"
	oauthProviderOIDC      = "oidc"
)

// oauthProviderKeys is the canonical (sorted) set of configurable provider
// keys, used to enumerate a project's providers deterministically.
var oauthProviderKeys = []string{oauthProviderApple, oauthProviderGitHub, oauthProviderGoogle, oauthProviderMicrosoft, oauthProviderOIDC}

// isOAuthProviderKey reports whether key is one of the built-in provider keys.
func isOAuthProviderKey(key string) bool {
	return slices.Contains(oauthProviderKeys, key)
}

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

	MicrosoftTenantID       string
	MicrosoftIssuerFormat   string
	MicrosoftAllowedTenants []string

	AppleTeamID     string
	AppleKeyID      string
	ApplePrivateKey string

	GitHubAuthorizationURL string
	GitHubTokenURL         string
	GitHubUserURL          string
	GitHubUserMailURL      string

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

	MicrosoftTenantID       string
	MicrosoftIssuerFormat   string
	MicrosoftAllowedTenants []string

	AppleTeamID   string
	AppleKeyID    string
	HasPrivateKey bool

	GitHubAuthorizationURL string
	GitHubTokenURL         string
	GitHubUserURL          string
	GitHubUserMailURL      string

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
// project surfaces ErrNotFound. The provider's host clients (ADR-0019) stay
// stored and apply to whichever base the precedence then selects
// (ADR-0010/0011); with none they are inert, since an override never enables
// a provider. AdminDeleteProjectOAuthHostClient removes them.
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

// ProjectOAuthHostClientInput is the operator-supplied client one provider uses
// on one callback host (ADR-0019); every other setting is the base provider's.
// ClientSecret is PLAINTEXT, encrypted before storage, and an EMPTY one keeps
// the stored secret. Apple takes none: the base provider's key signs for the
// host's Services ID.
type ProjectOAuthHostClientInput struct {
	Provider     string
	CallbackHost string
	ClientID     string
	ClientSecret string
}

// ProjectOAuthHostClientView is the REDACTED read view of a host client:
// HasClientSecret in place of the secret.
type ProjectOAuthHostClientView struct {
	Provider        string
	CallbackHost    string
	ClientID        string
	HasClientSecret bool
}

// AdminSetProjectOAuthHostClient sets (or rotates) the client one of a
// project's providers uses on one callback host (ADR-0019). It encrypts any
// plaintext secret, merges the client into the project's config_json without
// disturbing the base provider or any other config key, and returns it with
// the secret REDACTED. project_id, a known provider key and a callback host
// are required. An unknown project surfaces ErrNotFound.
func (s *ControlPlaneAdminService) AdminSetProjectOAuthHostClient(ctx context.Context, secret, projectID string, in *ProjectOAuthHostClientInput) (*ProjectOAuthHostClientView, error) {
	if err := s.authorize(secret); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	if in == nil {
		return nil, fmt.Errorf("%w: missing client", ErrInvalidArgument)
	}
	provider, err := normalizeOAuthProvider(in.Provider)
	if err != nil {
		return nil, err
	}
	host, err := newCallbackHost(in.CallbackHost)
	if err != nil {
		return nil, err
	}
	if provider == oauthProviderApple && in.ClientSecret != "" {
		return nil, fmt.Errorf("%w: apple takes no client_secret on a callback host: the base provider's key signs for its client", ErrInvalidArgument)
	}

	var view *ProjectOAuthHostClientView
	if _, err := s.mutateProjectConfig(ctx, projectID, func(current string) (string, error) {
		top, oauthSub, err := decodeOAuthSubtree(current)
		if err != nil {
			return "", err
		}
		hosts, err := decodeHostClients(oauthSub)
		if err != nil {
			return "", err
		}
		var stored ProjectOAuthHostClient
		if raw, ok := hosts[host][provider]; ok {
			if err := json.Unmarshal(raw, &stored); err != nil {
				return "", fmt.Errorf("%w: stored oauth.hosts[%q].%s is malformed: %s", ErrInvalidArgument, host, provider, err.Error())
			}
		}
		enc, err := s.encryptOrKeep(in.ClientSecret, stored.ClientSecretEnc)
		if err != nil {
			return "", err
		}
		client := ProjectOAuthHostClient{ClientID: strings.TrimSpace(in.ClientID), ClientSecretEnc: enc}
		if err := client.validate(provider); err != nil {
			return "", fmt.Errorf("%w: oauth.hosts[%q].%s", ErrInvalidArgument, host, err.Error())
		}
		raw, err := json.Marshal(client)
		if err != nil {
			return "", fmt.Errorf("marshal oauth host client: %w", err)
		}
		if hosts[host] == nil {
			hosts[host] = map[string]json.RawMessage{}
		}
		hosts[host][provider] = raw
		if err := encodeHostClients(oauthSub, hosts); err != nil {
			return "", err
		}
		view = hostClientView(host, provider, client)
		return encodeOAuthSubtree(top, oauthSub)
	}); err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.EventProjectOAuthProviderSet, audit.WithSuccess(true), audit.WithDetails(hostClientAuditDetails(projectID, provider, host)))
	return view, nil
}

// AdminDeleteProjectOAuthHostClient removes the client one of a project's
// providers uses on one callback host, leaving the base provider, every other
// host client and every other config key intact. It is idempotent — removing
// an absent host client is a no-op. An unknown project surfaces ErrNotFound.
func (s *ControlPlaneAdminService) AdminDeleteProjectOAuthHostClient(ctx context.Context, secret, projectID, provider, callbackHost string) error {
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
	host, err := normalizeCallbackHost(callbackHost)
	if err != nil {
		return err
	}
	// No key holds U+0000 (a Postgres jsonb config cannot store one), and the
	// audit row naming it would be refused by the same jsonb cast.
	if strings.ContainsRune(host, 0) {
		return fmt.Errorf("%w: invalid callback_host %q", ErrInvalidArgument, callbackHost)
	}

	if _, err := s.mutateProjectConfig(ctx, projectID, func(current string) (string, error) {
		top, oauthSub, err := decodeOAuthSubtree(current)
		if err != nil {
			return "", err
		}
		hosts, err := decodeHostClients(oauthSub)
		if err != nil {
			return "", err
		}
		delete(hosts[host], provider)
		if err := encodeHostClients(oauthSub, hosts); err != nil {
			return "", err
		}
		return encodeOAuthSubtree(top, oauthSub)
	}); err != nil {
		return err
	}
	s.audit.Log(ctx, audit.EventProjectOAuthProviderRemoved, audit.WithSuccess(true), audit.WithDetails(hostClientAuditDetails(projectID, provider, host)))
	return nil
}

// hostClientAuditDetails names what a host-client write changed: the project,
// the provider and the callback host.
func hostClientAuditDetails(projectID, provider, host string) map[string]any {
	return map[string]any{"project_id": projectID, "provider": provider, "callback_host": host}
}

// normalizeCallbackHost validates the host a host client is keyed by and
// returns it in the form the resolver compares a redirect URI's host in
// (ADR-0019). A key is valid only if it comes back from this function
// unchanged, which is what parsing a stored config checks, so a host whose
// normalized form would normalize again to something else (a doubled
// trailing dot) is refused rather than stored in a form no parse accepts.
func normalizeCallbackHost(host string) (string, error) {
	h, err := normalizeHostname("callback_host", host)
	if err != nil {
		return "", err
	}
	if again, err := normalizeHostname("callback_host", h); err != nil || again != h {
		return "", fmt.Errorf("%w: invalid callback_host %q", ErrInvalidArgument, host)
	}
	return h, nil
}

// newCallbackHost is normalizeCallbackHost for a host client being written,
// which must also be a bare domain name (isBareDomainName: two or more LDH
// labels), an IDN in its punycode form. That catches a typo, a stray URL
// character, an empty label or a control character at the write, instead of
// storing a key that silently never applies. A stored config is held only to
// normalizeCallbackHost, so a key written under a wider rule never stops this
// binary loading the project, and the delete can always remove it.
func newCallbackHost(host string) (string, error) {
	h, err := normalizeCallbackHost(host)
	if err != nil {
		return "", err
	}
	if !isBareDomainName(h) {
		return "", fmt.Errorf("%w: invalid callback_host %q: %s", ErrInvalidArgument, host, callbackHostRule)
	}
	return h, nil
}

// callbackHostRule says, in an error, what a written callback host must be.
const callbackHostRule = "want a hostname of two or more labels of a-z, 0-9 and '-', none starting or ending " +
	"with '-', at most 63 characters each and 253 in all (an IDN in punycode)"

// checkNewHostKeys holds each oauth.hosts key that the config text next adds
// to the stored config text current to the rule a host client write is held
// to: a key must be what newCallbackHost would store. So a whole-config write
// cannot store a key the host client RPC would refuse. A key already stored
// is kept whatever rule it was written under, so writing back a config as
// read never fails on it, even when the stored config no longer parses (a
// whole-config write is how such a config is repaired).
func checkNewHostKeys(current, next string) error {
	stored := configHostKeys(current)
	for host := range configHostKeys(next) {
		if stored[host] {
			continue
		}
		if h, err := newCallbackHost(host); err != nil || h != host {
			return fmt.Errorf("%w: oauth.hosts key %q (under any letter case of oauth.hosts): %s",
				ErrInvalidArgument, host, callbackHostRule)
		}
	}
	return nil
}

// configHostKeys returns the oauth.hosts keys in a config's JSON text under
// every spelling of "oauth" and "hosts" that encoding/json reads as that
// field: it matches a field name case-insensitively and keeps the last
// duplicate, and a jsonb store reorders an object's keys, so which spelling
// a later parse reads need not be the one a parse of the written text read.
// Text that is not a JSON object, or a spelling whose value is not one, adds
// no key.
func configHostKeys(config string) map[string]bool {
	keys := map[string]bool{}
	for _, oauth := range foldedValues(json.RawMessage(config), "oauth") {
		for _, hosts := range foldedValues(oauth, "hosts") {
			var entries map[string]json.RawMessage
			if json.Unmarshal(hosts, &entries) != nil {
				continue
			}
			for host := range entries {
				keys[host] = true
			}
		}
	}
	return keys
}

// foldedValues returns the value, of any JSON type, of every key of the JSON
// object data that equals field under Unicode case folding, the match
// encoding/json uses for a field name. Data that is not a JSON object has
// none.
func foldedValues(data json.RawMessage, field string) []json.RawMessage {
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) != nil {
		return nil
	}
	var out []json.RawMessage
	for k, v := range obj {
		if strings.EqualFold(k, field) {
			out = append(out, v)
		}
	}
	return out
}

// decodeHostClients decodes the oauth subtree's "hosts" object into raw
// per-host, per-provider entries, so every entry a write does not touch
// round-trips byte-for-byte.
func decodeHostClients(oauthSub map[string]json.RawMessage) (map[string]map[string]json.RawMessage, error) {
	hosts := map[string]map[string]json.RawMessage{}
	if raw, ok := oauthSub["hosts"]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &hosts); err != nil {
			return nil, fmt.Errorf("%w: stored oauth.hosts is not an object of objects: %s", ErrInvalidArgument, err.Error())
		}
	}
	if hosts == nil { // a stored "hosts": null
		hosts = map[string]map[string]json.RawMessage{}
	}
	return hosts, nil
}

// encodeHostClients writes hosts back into the oauth subtree, dropping a host
// left with no client and the "hosts" key itself once no host remains.
func encodeHostClients(oauthSub map[string]json.RawMessage, hosts map[string]map[string]json.RawMessage) error {
	for host, clients := range hosts {
		if len(clients) == 0 {
			delete(hosts, host)
		}
	}
	if len(hosts) == 0 {
		delete(oauthSub, "hosts")
		return nil
	}
	raw, err := json.Marshal(hosts)
	if err != nil {
		return fmt.Errorf("marshal oauth hosts: %w", err)
	}
	oauthSub["hosts"] = raw
	return nil
}

// hostClientView renders the redacted read view of a host's client.
func hostClientView(host, provider string, client ProjectOAuthHostClient) *ProjectOAuthHostClientView {
	return &ProjectOAuthHostClientView{
		Provider:        provider,
		CallbackHost:    host,
		ClientID:        client.ClientID,
		HasClientSecret: client.ClientSecretEnc != "",
	}
}

// AdminListProjectOAuthProviders lists a project's configured OAuth providers,
// ordered by provider key, and its host clients, ordered by host and then
// provider key, all with secrets REDACTED. Only the known provider keys are
// surfaced; an unknown key stored under "oauth" is preserved on write but not
// listed (its shape is unknown to this binary). An unknown project surfaces
// ErrNotFound.
func (s *ControlPlaneAdminService) AdminListProjectOAuthProviders(ctx context.Context, secret, projectID string) (providers []*ProjectOAuthProviderView, hostClients []*ProjectOAuthHostClientView, err error) {
	if err := s.authorize(secret); err != nil {
		return nil, nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	stored, _, err := s.projects.GetProjectConfig(ctx, projectID)
	if err != nil {
		return nil, nil, err
	}
	_, oauthSub, err := decodeOAuthSubtree(stored)
	if err != nil {
		return nil, nil, err
	}
	providers = make([]*ProjectOAuthProviderView, 0, len(oauthProviderKeys))
	for _, key := range oauthProviderKeys {
		raw, ok := oauthSub[key]
		if !ok || len(raw) == 0 {
			continue
		}
		prov, err := decodeProvider(key, raw)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: stored oauth.%s is malformed: %s", ErrInvalidArgument, key, err.Error())
		}
		providers = append(providers, providerView(key, prov))
	}
	hosts, err := decodeHostClients(oauthSub)
	if err != nil {
		return nil, nil, err
	}
	hostClients = []*ProjectOAuthHostClientView{}
	for _, host := range slices.Sorted(maps.Keys(hosts)) {
		for _, key := range oauthProviderKeys {
			raw, ok := hosts[host][key]
			if !ok {
				continue
			}
			var client ProjectOAuthHostClient
			if err := json.Unmarshal(raw, &client); err != nil {
				return nil, nil, fmt.Errorf("%w: stored oauth.hosts[%q].%s is malformed: %s", ErrInvalidArgument, host, key, err.Error())
			}
			hostClients = append(hostClients, hostClientView(host, key, client))
		}
	}
	return providers, hostClients, nil
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
	if top == nil { // a stored null
		top = map[string]json.RawMessage{}
	}
	oauthSub = map[string]json.RawMessage{}
	if raw, ok := top["oauth"]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &oauthSub); err != nil {
			return nil, nil, fmt.Errorf("%w: stored oauth config is not a JSON object: %s", ErrInvalidArgument, err.Error())
		}
	}
	if oauthSub == nil { // a stored "oauth": null
		oauthSub = map[string]json.RawMessage{}
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
			NativeAudiences:  normalizeStringList(in.NativeAudiences),
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
			AllowedTenants:  normalizeStringList(in.MicrosoftAllowedTenants),
			NativeAudiences: normalizeStringList(in.NativeAudiences),
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
			NativeAudiences: normalizeStringList(in.NativeAudiences),
		}, nil
	case oauthProviderGitHub:
		// GitHub is hosted-only: GitHub OAuth issues no ID token, so there is no
		// native-audience allow-list. Accepting native_audiences here would
		// silently drop them — reject rather than discard operator intent.
		if len(normalizeStringList(in.NativeAudiences)) > 0 {
			return nil, fmt.Errorf("%w: oauth.github does not support native_audiences; native login supports google, apple, microsoft", ErrInvalidArgument)
		}
		keep := ""
		if len(existingRaw) > 0 {
			var g ProjectOAuthGitHub
			if json.Unmarshal(existingRaw, &g) == nil {
				keep = g.ClientSecretEnc
			}
		}
		enc, err := s.encryptOrKeep(in.ClientSecret, keep)
		if err != nil {
			return nil, err
		}
		return &ProjectOAuthGitHub{
			ClientID:         strings.TrimSpace(in.ClientID),
			ClientSecretEnc:  enc,
			AuthorizationURL: strings.TrimSpace(in.GitHubAuthorizationURL),
			TokenURL:         strings.TrimSpace(in.GitHubTokenURL),
			UserURL:          strings.TrimSpace(in.GitHubUserURL),
			UserMailURL:      strings.TrimSpace(in.GitHubUserMailURL),
		}, nil
	case oauthProviderOIDC:
		// The generic OIDC provider is hosted-only: it has no native-audience
		// allow-list, so accepting native_audiences here would silently drop
		// them. Reject rather than discard operator intent without signal.
		if len(normalizeStringList(in.NativeAudiences)) > 0 {
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
	// Unreachable: provider is normalized to one of the five keys above.
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
	case oauthProviderGitHub:
		var g ProjectOAuthGitHub
		if err := json.Unmarshal(raw, &g); err != nil {
			return nil, err
		}
		return &g, nil
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
	case *ProjectOAuthGitHub:
		cfg.GitHub = p
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
		v.MicrosoftAllowedTenants = p.AllowedTenants
	case *ProjectOAuthApple:
		v.ClientID = p.ClientID
		v.HasPrivateKey = p.PrivateKeyEnc != ""
		v.NativeAudiences = p.NativeAudiences
		v.AppleTeamID = p.TeamID
		v.AppleKeyID = p.KeyID
	case *ProjectOAuthGitHub:
		v.ClientID = p.ClientID
		v.HasClientSecret = p.ClientSecretEnc != ""
		v.GitHubAuthorizationURL = p.AuthorizationURL
		v.GitHubTokenURL = p.TokenURL
		v.GitHubUserURL = p.UserURL
		v.GitHubUserMailURL = p.UserMailURL
	case *ProjectOAuthOIDC:
		v.ClientID = p.ClientID
		v.HasClientSecret = p.ClientSecretEnc != ""
		v.OIDCIssuer = p.Issuer
		v.OIDCDiscoveryURL = p.DiscoveryURL
		v.OIDCScopes = p.Scopes
	}
	return v
}

// normalizeStringList trims each entry and drops the empties, returning nil when
// nothing remains (so an all-blank list is stored as absent). Shared by the
// native-audience and Microsoft allowed-tenant authoring paths.
func normalizeStringList(in []string) []string {
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
// is not one of the five configurable providers.
func normalizeOAuthProvider(provider string) (string, error) {
	if k := strings.ToLower(strings.TrimSpace(provider)); isOAuthProviderKey(k) {
		return k, nil
	}
	return "", fmt.Errorf("%w: unknown oauth provider %q (want %q, %q, %q, %q, or %q)",
		ErrInvalidArgument, provider, oauthProviderGoogle, oauthProviderMicrosoft, oauthProviderApple, oauthProviderGitHub, oauthProviderOIDC)
}
