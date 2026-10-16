package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/elloloop/identity/pkg/audit"
)

const (
	OAuthGrantAuthorizationCode = "authorization_code"
	OAuthGrantRefreshToken      = "refresh_token"
	OAuthClientNativePublic     = "native_public"
	maxOAuthRedirects           = 16
	maxOAuthResources           = 16
	maxOAuthScopes              = 64
	maxOAuthURIBytes            = 2048
	maxOAuthScopeBytes          = 128
	maxOAuthProductBytes        = 128
	maxOAuthClientNameBytes     = 200
	maxOAuthClientPage          = 100
	defaultOAuthClientPage      = 50
)

var ErrOAuthClientRevision = errors.New("OAuth client revision changed")

// OAuthResourceBounds are protocol bounds, not application permissions.
type OAuthResourceBounds struct {
	Resource string   `json:"resource"`
	Product  string   `json:"product,omitempty"`
	Scopes   []string `json:"scopes"`
}

type OAuthClientRegistration struct {
	Name         string                `json:"name"`
	RedirectURIs []string              `json:"redirect_uris"`
	Resources    []OAuthResourceBounds `json:"resources"`
	GrantTypes   []string              `json:"grant_types"`
	Disabled     bool                  `json:"disabled"`
}

// OAuthClient is a project-scoped registration. Every update advances Revision,
// including disable/re-enable. A future grant must retain its approved bounds
// and client revision; rereading this mutable registration never widens consent.
type OAuthClient struct {
	ID           string
	Kind         string
	Registration OAuthClientRegistration
	Revision     int64
	CreatedAt    int64
	UpdatedAt    int64
}

func (c *OAuthClient) Clone() *OAuthClient {
	if c == nil {
		return nil
	}
	out := *c
	out.Registration.RedirectURIs = slices.Clone(c.Registration.RedirectURIs)
	out.Registration.GrantTypes = slices.Clone(c.Registration.GrantTypes)
	out.Registration.Resources = slices.Clone(c.Registration.Resources)
	for i := range out.Registration.Resources {
		out.Registration.Resources[i].Scopes = slices.Clone(c.Registration.Resources[i].Scopes)
	}
	return &out
}

func invalidOAuthClient(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidArgument, reason)
}

func boundedOAuthStrings(values []string, limit int) bool {
	if len(values) == 0 || len(values) > limit {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func oauthURI(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > maxOAuthURIBytes || strings.ContainsAny(raw, "#*\\") || strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r > '~' }) {
		return nil, invalidOAuthClient("invalid absolute URI")
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.User != nil || strings.HasSuffix(u.Host, ":") {
		return nil, invalidOAuthClient("invalid absolute URI")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, invalidOAuthClient("invalid URI port")
		}
	}
	return u, nil
}

func oauthRedirect(raw string) (*url.URL, error) {
	u, err := oauthURI(raw)
	if err != nil {
		return nil, err
	}
	if u.Opaque != "" || u.Host == "" || u.Hostname() == "" || strings.HasSuffix(u.Host, ":") {
		return nil, invalidOAuthClient("redirect must be an HTTPS or literal-loopback HTTP URI")
	}
	if u.Scheme == "https" {
		return u, nil
	}
	if u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1") {
		return u, nil
	}
	return nil, invalidOAuthClient("redirect must be an HTTPS or literal-loopback HTTP URI")
}

func validOAuthScope(scope string) bool {
	if scope == "" || len(scope) > maxOAuthScopeBytes {
		return false
	}
	for _, r := range scope {
		// RFC 6749 scope-token excludes space, double quote and backslash.
		if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

func (r *OAuthClientRegistration) Validate() error {
	if r == nil {
		return invalidOAuthClient("registration is required")
	}
	if !validOAuthClientName(r.Name) {
		return invalidOAuthClient("client name is required and must be at most 200 bytes without control or format characters")
	}
	if !boundedOAuthStrings(r.RedirectURIs, maxOAuthRedirects) {
		return invalidOAuthClient("register 1 to 16 distinct redirects")
	}
	for _, redirect := range r.RedirectURIs {
		if _, err := oauthRedirect(redirect); err != nil {
			return err
		}
	}
	if len(r.Resources) == 0 || len(r.Resources) > maxOAuthResources {
		return invalidOAuthClient("register 1 to 16 resources")
	}
	seenResources := make(map[string]bool, len(r.Resources))
	for _, resource := range r.Resources {
		u, err := oauthURI(resource.Resource)
		if err != nil || (u.Scheme != "https" && u.Scheme != "urn") || (u.Scheme == "https" && (u.Hostname() == "" || u.Opaque != "")) || (u.Scheme == "urn" && u.Opaque == "") {
			return invalidOAuthClient("resource must be an absolute HTTPS URI or URN without a fragment")
		}
		if seenResources[resource.Resource] {
			return invalidOAuthClient("resource registrations must be distinct")
		}
		seenResources[resource.Resource] = true
		if resource.Product != "" && (resource.Product != normalizeProductSlug(resource.Product) || len(resource.Product) > maxOAuthProductBytes || strings.ContainsAny(resource.Product, " /?#\\") || strings.ContainsFunc(resource.Product, unicode.IsControl)) {
			return invalidOAuthClient("invalid resource product")
		}
		if !boundedOAuthStrings(resource.Scopes, maxOAuthScopes) {
			return invalidOAuthClient("register 1 to 64 distinct scopes per resource")
		}
		for _, scope := range resource.Scopes {
			if !validOAuthScope(scope) {
				return invalidOAuthClient("invalid OAuth scope token")
			}
		}
	}
	if !boundedOAuthStrings(r.GrantTypes, 2) || !slices.Contains(r.GrantTypes, OAuthGrantAuthorizationCode) {
		return invalidOAuthClient("authorization_code is required; refresh_token is optional")
	}
	for _, grant := range r.GrantTypes {
		if grant != OAuthGrantAuthorizationCode && grant != OAuthGrantRefreshToken {
			return invalidOAuthClient("unsupported grant type")
		}
	}
	return nil
}

func validOAuthClientName(name string) bool {
	return utf8.ValidString(name) && strings.TrimSpace(name) != "" && len(name) <= maxOAuthClientNameBytes &&
		!strings.ContainsFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

// ValidateOAuthRequest checks registration bounds only. It does not authenticate
// a public client, approve consent, check PKCE or issue any credential.
func (c *OAuthClient) ValidateOAuthRequest(redirect, resource string, scopes []string, grant string) error {
	if c == nil || c.Kind != OAuthClientNativePublic || c.Revision <= 0 || c.Registration.Disabled {
		return ErrPermissionDenied
	}
	if err := c.Registration.Validate(); err != nil {
		return err
	}
	if !slices.Contains(c.Registration.GrantTypes, grant) {
		return ErrPermissionDenied
	}
	candidate, err := oauthRedirect(redirect)
	if err != nil {
		return err
	}
	matched := false
	for _, registered := range c.Registration.RedirectURIs {
		if redirect == registered {
			matched = true
			break
		}
		if candidate.Scheme != "http" {
			continue
		}
		u, _ := oauthRedirect(registered)
		// Native loopback redirects may vary only their port (RFC 8252).
		// Keep the remaining raw components exact; do not normalize paths,
		// encodings, query order, IPv4/IPv6 spelling or a trailing question mark.
		if u.Scheme == "http" && u.Hostname() == candidate.Hostname() {
			u.Host = candidate.Host
			if u.String() == redirect {
				matched = true
				break
			}
		}
	}
	if !matched || !boundedOAuthStrings(scopes, maxOAuthScopes) {
		return ErrPermissionDenied
	}
	for _, bound := range c.Registration.Resources {
		if bound.Resource != resource {
			continue
		}
		for _, scope := range scopes {
			if !slices.Contains(bound.Scopes, scope) {
				return ErrPermissionDenied
			}
		}
		return nil
	}
	return ErrPermissionDenied
}

func (s *AuthService) oauthClientAdmin(ctx context.Context, caller string) error {
	if caller == "" {
		return ErrUnauthenticated
	}
	u, err := s.repo(ctx).GetUser(ctx, caller)
	if err != nil {
		return err
	}
	if !isEligibleAgentOwner(u) || u.Role != RoleAdmin {
		return ErrPermissionDenied
	}
	return nil
}

func (s *AuthService) CreateOAuthClient(ctx context.Context, caller string, registration *OAuthClientRegistration) (*OAuthClient, error) {
	if err := s.oauthClientAdmin(ctx, caller); err != nil {
		return nil, err
	}
	if err := registration.Validate(); err != nil {
		return nil, err
	}
	now := s.nowMs()
	client := (&OAuthClient{ID: rand.Text(), Kind: OAuthClientNativePublic, Registration: *registration, Revision: 1, CreatedAt: now, UpdatedAt: now}).Clone()
	if err := s.repo(ctx).CreateOAuthClient(ctx, client); err != nil {
		return nil, err
	}
	s.audit.Log(ctx, audit.EventOAuthClientCreated, audit.WithActor(caller), audit.WithTarget(client.ID), audit.WithSuccess(true))
	return client, nil
}

func (s *AuthService) GetOAuthClient(ctx context.Context, caller, id string) (*OAuthClient, error) {
	if err := s.oauthClientAdmin(ctx, caller); err != nil {
		return nil, err
	}
	if id == "" {
		return nil, invalidOAuthClient("client_id is required")
	}
	client, err := s.repo(ctx).GetOAuthClient(ctx, id)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, ErrNotFound
	}
	return client, nil
}

func (s *AuthService) UpdateOAuthClient(ctx context.Context, caller, id string, expectedRevision int64, registration *OAuthClientRegistration) (*OAuthClient, error) {
	if err := s.oauthClientAdmin(ctx, caller); err != nil {
		return nil, err
	}
	if id == "" || expectedRevision <= 0 || expectedRevision == math.MaxInt64 {
		return nil, invalidOAuthClient("client_id and a valid expected_revision are required")
	}
	if err := registration.Validate(); err != nil {
		return nil, err
	}
	updated, err := s.repo(ctx).UpdateOAuthClient(ctx, id, expectedRevision, registration, s.nowMs())
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, ErrOAuthClientRevision
	}
	s.audit.Log(ctx, audit.EventOAuthClientUpdated, audit.WithActor(caller), audit.WithTarget(id), audit.WithSuccess(true))
	return updated, nil
}

func (s *AuthService) ListOAuthClients(ctx context.Context, caller, afterID string, limit int) ([]*OAuthClient, error) {
	if err := s.oauthClientAdmin(ctx, caller); err != nil {
		return nil, err
	}
	if limit == 0 {
		limit = defaultOAuthClientPage
	}
	if err := ValidateOAuthClientPage(afterID, limit); err != nil {
		return nil, err
	}
	return s.repo(ctx).ListOAuthClients(ctx, afterID, limit)
}

func validOAuthClientID(id string) bool {
	return id != "" && len(id) <= 128 && !strings.ContainsFunc(id, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_'
	})
}

func ValidateNewOAuthClient(client *OAuthClient) error {
	if client == nil || !validOAuthClientID(client.ID) || client.Kind != OAuthClientNativePublic || client.Revision != 1 || client.CreatedAt <= 0 || client.CreatedAt != client.UpdatedAt {
		return invalidOAuthClient("invalid initial client record")
	}
	return client.Registration.Validate()
}

func ValidateOAuthClientUpdate(id string, expected int64, registration *OAuthClientRegistration, atMs int64) error {
	if !validOAuthClientID(id) || expected <= 0 || expected == math.MaxInt64 || atMs <= 0 {
		return invalidOAuthClient("invalid client update")
	}
	return registration.Validate()
}

func ValidateOAuthClientPage(afterID string, limit int) error {
	if (afterID != "" && !validOAuthClientID(afterID)) || limit <= 0 || limit > maxOAuthClientPage {
		return invalidOAuthClient("invalid client page")
	}
	return nil
}
