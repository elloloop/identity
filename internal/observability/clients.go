package observability

import (
	"context"

	"go.opentelemetry.io/otel/attribute"

	"github.com/elloloop/identity/pkg/email"
	"github.com/elloloop/identity/pkg/idv"
	"github.com/elloloop/identity/pkg/oauth"
)

// TracedIDVProvider wraps an idv.Provider with client-kind spans so
// outbound BeginVerification / GetVerification calls show up in a
// distributed trace.
type TracedIDVProvider struct {
	inner idv.Provider
}

// WrapIDVProvider returns p wrapped in client-kind spans. Returns nil
// when p is nil so callers can construct optional providers without
// special-casing.
func WrapIDVProvider(p idv.Provider) idv.Provider {
	if p == nil {
		return nil
	}
	return &TracedIDVProvider{inner: p}
}

func (t *TracedIDVProvider) Name() string { return t.inner.Name() }

func (t *TracedIDVProvider) BeginVerification(ctx context.Context, req idv.Request) (*idv.Session, error) {
	ctx, end := StartClient(ctx, "idv.BeginVerification",
		attribute.String("idv.provider", t.inner.Name()),
	)
	s, err := t.inner.BeginVerification(ctx, req)
	end(err)
	return s, err
}

func (t *TracedIDVProvider) GetVerification(ctx context.Context, providerSessionID string) (*idv.StatusResult, error) {
	ctx, end := StartClient(ctx, "idv.GetVerification",
		attribute.String("idv.provider", t.inner.Name()),
	)
	r, err := t.inner.GetVerification(ctx, providerSessionID)
	end(err)
	return r, err
}

// TracedExchanger wraps oauth.Exchanger with a client-kind span for
// the outbound token-endpoint POST. When the inner value also
// satisfies oauth.Authorizer (the production Google / Microsoft /
// GitHub implementations do), the wrapper exposes the same surface
// so the service-layer's `exchanger.(oauth.Authorizer)` assertion
// keeps working.
type TracedExchanger struct {
	provider string
	inner    oauth.Exchanger
}

// tracedExchangerWithAuthorizer extends TracedExchanger when the
// inner Exchanger also implements Authorizer. The service layer
// type-asserts on Authorizer to drive BeginOAuthLogin; we preserve
// that by returning this richer type when applicable.
type tracedExchangerWithAuthorizer struct {
	TracedExchanger
	authorizer oauth.Authorizer
}

// WrapOAuthExchanger returns e wrapped in client-kind spans tagged
// with the supplied provider name. When e additionally satisfies
// oauth.Authorizer the returned value does too.
func WrapOAuthExchanger(provider string, e oauth.Exchanger) oauth.Exchanger {
	if e == nil {
		return nil
	}
	base := TracedExchanger{provider: provider, inner: e}
	if a, ok := e.(oauth.Authorizer); ok {
		return &tracedExchangerWithAuthorizer{TracedExchanger: base, authorizer: a}
	}
	return &base
}

func (t *TracedExchanger) Exchange(ctx context.Context, code, redirectURI string) (*oauth.Identity, error) {
	ctx, end := StartClient(ctx, "oauth.Exchange",
		attribute.String("oauth.provider", t.provider),
	)
	id, err := t.inner.Exchange(ctx, code, redirectURI)
	end(err)
	return id, err
}

func (t *tracedExchangerWithAuthorizer) AuthorizationURL(ctx context.Context, redirectURI, state, codeChallenge string) (string, error) {
	ctx, end := StartClient(ctx, "oauth.AuthorizationURL",
		attribute.String("oauth.provider", t.provider),
	)
	url, err := t.authorizer.AuthorizationURL(ctx, redirectURI, state, codeChallenge)
	end(err)
	return url, err
}

// TracedMailer wraps an email.Transport with client-kind spans. The
// span is tagged with subject but not the recipient — addresses are
// PII and we already redact them in the existing email logger.
type TracedMailer struct {
	inner email.Transport
}

// WrapMailer returns t wrapped in client-kind spans for Send.
func WrapMailer(t email.Transport) email.Transport {
	if t == nil {
		return nil
	}
	return &TracedMailer{inner: t}
}

func (m *TracedMailer) Send(ctx context.Context, msg email.Message) error {
	ctx, end := StartClient(ctx, "email.Send",
		attribute.String("email.subject", msg.Subject),
	)
	err := m.inner.Send(ctx, msg)
	end(err)
	return err
}
