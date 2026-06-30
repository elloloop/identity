package config

import "testing"

func baseSAMLConfig() *Config {
	c := Load()
	c.RevocationMode = RevocationModeTTL
	return c
}

func TestValidateSAML_DisabledIsAlwaysValid(t *testing.T) {
	c := baseSAMLConfig()
	c.SAMLIDPEnabled = false
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled SAML must validate: %v", err)
	}
}

func TestValidateSAML_EnabledRequiresEntityAndSSO(t *testing.T) {
	c := baseSAMLConfig()
	c.SAMLIDPEnabled = true
	c.SAMLSigningKey = "key"
	c.SAMLSigningCert = "cert"
	if err := c.Validate(); err == nil {
		t.Fatal("enabled SAML without entityID/SSO must fail")
	}
}

func TestValidateSAML_EnabledRequiresSigningMaterial(t *testing.T) {
	c := baseSAMLConfig()
	c.SAMLIDPEnabled = true
	c.SAMLEntityID = "https://idp/meta"
	c.SAMLSSOURL = "https://idp/sso"
	if err := c.Validate(); err == nil {
		t.Fatal("enabled SAML without signing key/cert must fail")
	}
}

func TestValidateSAML_EnabledHappyPath(t *testing.T) {
	c := baseSAMLConfig()
	c.SAMLIDPEnabled = true
	c.SAMLEntityID = "https://idp/meta"
	c.SAMLSSOURL = "https://idp/sso"
	c.SAMLSigningKey = "-----BEGIN-----"
	c.SAMLSigningCert = "-----BEGIN-----"
	if err := c.Validate(); err != nil {
		t.Fatalf("complete SAML config must validate: %v", err)
	}
}
