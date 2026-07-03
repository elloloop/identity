// Package samlidp implements the SAML 2.0 Identity Provider (IdP) core:
// IdP-metadata generation, AuthnRequest parsing, and the issuance of
// XML-DSig-signed SAML assertions/responses for a registered Service
// Provider (SP).
//
// The package is deliberately transport-agnostic and persistence-agnostic.
// It exposes a narrow Issuer interface (MetadataProvider + AssertionIssuer)
// plus a no-op default so the rest of the server can hold exactly one
// Issuer for the process lifetime and call it without nil checks. The HTTP
// surface (SSO POST/Redirect bindings, SLO) and the SP-connection store
// are wired separately; this package owns only the SAML protocol logic and
// the signing.
//
// Signing uses an RSA private key + X.509 certificate supplied at
// construction (GATEWAY_SAML_*). Assertions are signed with RSA-SHA256 and
// SHA-256 digests per the SAML 2.0 / xmldsig-core profiles that modern SPs
// (Okta, Azure AD, Google Workspace) accept.
package samlidp

import (
	"context"
	"errors"
	"time"
)

// ProviderName identifies the active Issuer implementation. It is the value
// reported by Issuer.Name and is used for observability/logging only.
const (
	// ProviderNoop is the disabled-IdP implementation name.
	ProviderNoop = "noop"
	// ProviderRSA is the real RSA-signing IdP implementation name.
	ProviderRSA = "rsa"
)

// ErrDisabled is returned by the no-op Issuer for every issuance call: a
// deployment that leaves the SAML IdP disabled has no signing key, so it
// cannot mint assertions. Callers (the HTTP surface) map this to a 404 so a
// disabled IdP is indistinguishable from one that was never mounted.
var ErrDisabled = errors.New("samlidp: identity provider is disabled")

// ErrInvalidAuthnRequest indicates the inbound SAML AuthnRequest could not
// be parsed, was malformed, or named a destination/issuer the IdP will not
// serve. The HTTP surface maps this to a 400.
var ErrInvalidAuthnRequest = errors.New("samlidp: invalid AuthnRequest")

// ErrUnknownServiceProvider indicates the AuthnRequest's Issuer
// (SP entityID) does not match the SP this issuance is scoped to. The HTTP
// surface resolves the SP connection from its store before calling Issue;
// this guards a mismatch.
var ErrUnknownServiceProvider = errors.New("samlidp: unknown service provider")

// ServiceProvider is the relying-party configuration the IdP needs to mint
// an assertion: who the SP is (EntityID), where the signed Response is
// POSTed (ACSURL), and the audience the assertion is restricted to
// (defaults to EntityID when empty). It mirrors the persisted
// SP-connection record but carries only the fields the protocol logic
// needs, keeping this package free of any store dependency.
type ServiceProvider struct {
	// EntityID is the SP's SAML entityID (the Issuer it puts on its
	// AuthnRequest and the default Audience of the assertion).
	EntityID string
	// ACSURL is the SP Assertion Consumer Service endpoint the signed
	// SAML Response is delivered to (HTTP-POST binding). Required.
	ACSURL string
	// Audience overrides the AudienceRestriction value. Empty means use
	// EntityID.
	Audience string
	// NameIDFormat overrides the assertion Subject NameID Format. Empty
	// means urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress.
	NameIDFormat string
}

// Subject is the authenticated end user the assertion attests. NameID is
// the primary identifier delivered to the SP (typically the email);
// Attributes are optional SAML attribute statements (e.g. "email",
// "displayName") the SP may consume.
type Subject struct {
	// NameID is the Subject identifier (required). For the default
	// emailAddress format this is the user's email.
	NameID string
	// Attributes are extra single-valued SAML attributes keyed by name.
	Attributes map[string]string
}

// AuthnRequestInfo is the parsed, validated subset of an inbound SAML
// AuthnRequest the IdP echoes into its Response (InResponseTo) and uses to
// pick the redirect target.
type AuthnRequestInfo struct {
	// ID is the AuthnRequest @ID, echoed as Response @InResponseTo.
	ID string
	// Issuer is the SP entityID that sent the request.
	Issuer string
	// ACSURL is the AssertionConsumerServiceURL the SP requested, if any.
	// Empty falls back to the registered SP's ACSURL.
	ACSURL string
	// RelayState is the opaque value the SP supplied; the IdP echoes it
	// back unmodified on completion. Carried alongside (not inside) the
	// request envelope.
	RelayState string
}

// Response is the result of a successful issuance: the SAML Response XML
// (already signed) plus the ACS URL it must be POSTed to and the RelayState
// to echo. The HTTP surface base64-encodes SAMLResponse and renders the
// auto-submitting POST form.
type Response struct {
	// XML is the complete, signed <samlp:Response> document (UTF-8).
	XML []byte
	// ACSURL is where XML must be delivered (HTTP-POST binding).
	ACSURL string
	// RelayState echoes the SP-supplied RelayState (may be empty).
	RelayState string
}

// MetadataProvider exposes the IdP's SAML metadata so an SP can be
// configured to trust this IdP.
type MetadataProvider interface {
	// EntityID returns the IdP's SAML entityID (its metadata URL by
	// convention).
	EntityID() string
	// Metadata returns the IdP EntityDescriptor XML advertising the SSO
	// endpoint(s) and the signing certificate.
	Metadata() ([]byte, error)
}

// AssertionIssuer mints signed SAML Responses.
type AssertionIssuer interface {
	// ParseAuthnRequest decodes a SAML AuthnRequest (the already
	// base64/inflate-decoded XML bytes) and returns its echoed subset.
	// relayState is the transport-level RelayState to carry through.
	ParseAuthnRequest(raw []byte, relayState string) (AuthnRequestInfo, error)
	// Issue mints a signed SAML Response asserting subject for sp, echoing
	// req. It returns ErrUnknownServiceProvider when req.Issuer disagrees
	// with sp.EntityID.
	Issue(ctx context.Context, sp ServiceProvider, subject Subject, req AuthnRequestInfo) (Response, error)
}

// Issuer is the single capability the server holds: an IdP that both
// advertises metadata and mints assertions.
type Issuer interface {
	MetadataProvider
	AssertionIssuer
	// Name reports the active implementation (ProviderNoop | ProviderRSA).
	Name() string
	// Enabled reports whether real issuance is possible. The no-op Issuer
	// returns false; the HTTP surface mounts nothing when false.
	Enabled() bool
}

// now is overridable in tests for deterministic IssueInstant/NotOnOrAfter.
var now = time.Now
