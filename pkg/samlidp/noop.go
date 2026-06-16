package samlidp

import "context"

// NoopIssuer is the disabled-IdP implementation. It advertises no metadata
// and refuses every issuance with ErrDisabled. It is wired whenever the
// SAML IdP is disabled (the default) so the server can hold a non-nil
// Issuer without the HTTP surface needing a nil check; that surface mounts
// nothing while Enabled reports false.
type NoopIssuer struct{}

// NewNoopIssuer returns a NoopIssuer.
func NewNoopIssuer() NoopIssuer { return NoopIssuer{} }

// Name implements Issuer.
func (NoopIssuer) Name() string { return ProviderNoop }

// Enabled implements Issuer; the no-op IdP is never enabled.
func (NoopIssuer) Enabled() bool { return false }

// EntityID implements MetadataProvider; the disabled IdP has no entityID.
func (NoopIssuer) EntityID() string { return "" }

// Metadata implements MetadataProvider; it returns ErrDisabled.
func (NoopIssuer) Metadata() ([]byte, error) { return nil, ErrDisabled }

// ParseAuthnRequest implements AssertionIssuer; it returns ErrDisabled.
func (NoopIssuer) ParseAuthnRequest([]byte, string) (AuthnRequestInfo, error) {
	return AuthnRequestInfo{}, ErrDisabled
}

// Issue implements AssertionIssuer; it returns ErrDisabled.
func (NoopIssuer) Issue(context.Context, ServiceProvider, Subject, AuthnRequestInfo) (Response, error) {
	return Response{}, ErrDisabled
}
