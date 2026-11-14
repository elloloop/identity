package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/elloloop/identity/internal/origin"
)

// publicAddress is one configured value that says where this service, or a
// page it serves or hands people to, is reached: a URL, a bare host name or
// the token issuer.
type publicAddress struct {
	env, value string
}

// publicAddresses lists every public URL, host and issuer the config names,
// each under the variable it came from. Values that name other parties (an
// OAuth provider's endpoints, a webhook's receiver, the mail server, the
// token audience) are not the deployment's own address and are left out.
func (c *Config) publicAddresses() []publicAddress {
	var out []publicAddress
	add := func(env string, values ...string) {
		for _, v := range values {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, publicAddress{env: env, value: v})
			}
		}
	}
	add("GATEWAY_JWT_ISSUER", c.JWTIssuer)
	add("GATEWAY_APP_BASE_URL", c.AppBaseURL)
	add("GATEWAY_EMAIL_LINK_BASE_URL", c.EmailLinkBaseURL)
	add("GATEWAY_TENANT_INVITATION_PAGE_URL", c.TenantInvitationPageURL)
	add("GATEWAY_QR_LOGIN_BASE_URL", c.QRLoginBaseURL)
	add("GATEWAY_PASSKEY_RP_ID", c.PasskeyRPID)
	add("GATEWAY_PASSKEY_ORIGIN", c.PasskeyOrigin)
	for _, host := range c.PasskeyRelyingPartyHosts() {
		party, _ := c.PasskeyRelyingPartyForHost(host)
		add("GATEWAY_PASSKEY_RELYING_PARTIES", party.Host, party.RPID)
		add("GATEWAY_PASSKEY_RELYING_PARTIES", party.Origins...)
	}
	add("GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS", c.DefaultProjectAuthDomainList()...)
	add("GATEWAY_COOKIE_DOMAIN", c.CookieDomain)
	add("GATEWAY_ALLOWED_ORIGINS", strings.Split(c.AllowedOrigins, ",")...)
	add("GATEWAY_OAUTH_ALLOWED_RETURN_URLS", strings.Split(c.OAuthAllowedReturnURLs, ",")...)
	add("GATEWAY_SAML_ENTITY_ID", c.SAMLEntityID)
	add("GATEWAY_SAML_SSO_URL", c.SAMLSSOURL)
	add("GATEWAY_SAML_SLO_URL", c.SAMLSLOURL)
	return out
}

// validatePhoneCodeCapture keeps local_capture to a deployment that is
// plainly local. Capture mails a phone code to the account's own address, so
// the phone is never proved; that is harmless on a developer's machine and an
// account-verification bypass anywhere else. Being chosen by name is not
// enough, since a copied environment file carries the name along: every
// public URL, host and issuer the config names must also be a loopback host.
// It runs after ValidatePasskeyRelyingParties, whose parsed entries it reads.
func (c *Config) validatePhoneCodeCapture() error {
	var chosen []string
	if c.CapturesSMS() {
		chosen = append(chosen, "GATEWAY_SMS_PROVIDER="+SMSProviderLocalCapture)
	}
	if c.CapturesTemplateMessages() {
		chosen = append(chosen, "GATEWAY_TEMPLATEMSG_PROVIDER="+TemplateMessageProviderLocalCapture)
	}
	if len(chosen) == 0 {
		return nil
	}
	for _, a := range c.publicAddresses() {
		if !namesLoopbackHost(a.value) {
			return fmt.Errorf(
				"config: %s mails phone codes to the account instead of the phone and runs only on a local deployment, "+
					"but %s names %q, which is not a loopback host (localhost, *.localhost, 127.0.0.0/8 or [::1])",
				strings.Join(chosen, " and "), a.env, origin.Redact(a.value),
			)
		}
	}
	return nil
}

// namesLoopbackHost reports whether value, a URL or a bare host (with an
// optional port, or a cookie domain's leading dot), names a loopback host. A
// value that names no host at all, such as an issuer that is not a URL, is
// not one.
func namesLoopbackHost(value string) bool {
	host := value
	if strings.Contains(value, "://") {
		u, err := url.Parse(value)
		if err != nil {
			return false
		}
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(value); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(host), "."), ".")
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return isLoopbackHost(host) || strings.HasSuffix(host, ".localhost")
}
