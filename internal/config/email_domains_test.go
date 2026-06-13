package config

import (
	"reflect"
	"testing"
)

func TestDefaultProjectAuthDomainList(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"auth.appa.com", []string{"auth.appa.com"}},
		{"auth.appA.com, Login.appB.com ,", []string{"auth.appa.com", "login.appb.com"}},
		{"a.com,a.com,b.com", []string{"a.com", "b.com"}}, // de-duped, order kept
	}
	for _, tc := range cases {
		c := &Config{DefaultProjectAuthDomains: tc.in}
		if got := c.DefaultProjectAuthDomainList(); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("DefaultProjectAuthDomainList(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestIsPublicEmailDomain_BuiltIn(t *testing.T) {
	t.Parallel()
	c := &Config{}

	publics := []string{
		"gmail.com", "googlemail.com",
		"outlook.com", "hotmail.co.uk", "live.com", "msn.com",
		"yahoo.com", "yahoo.co.uk", "ymail.com",
		"icloud.com", "me.com", "mac.com",
		"aol.com", "proton.me", "protonmail.com",
		"gmx.de", "mail.com", "zoho.com",
		"yandex.ru", "mail.ru", "qq.com", "163.com",
		"naver.com", "web.de", "libero.it", "orange.fr",
		"comcast.net", "rediffmail.com",
	}
	for _, d := range publics {
		if !c.IsPublicEmailDomain(d) {
			t.Errorf("IsPublicEmailDomain(%q) = false, want true", d)
		}
	}

	corporate := []string{"acme.com", "stripe.com", "elloloop.com", "example.io", "a.co"}
	for _, d := range corporate {
		if c.IsPublicEmailDomain(d) {
			t.Errorf("IsPublicEmailDomain(%q) = true, want false (corporate domain)", d)
		}
	}
}

func TestIsPublicEmailDomain_AcceptsFullAddress(t *testing.T) {
	t.Parallel()
	c := &Config{}

	if !c.IsPublicEmailDomain("alice@gmail.com") {
		t.Error("full address under a public domain must be public")
	}
	if c.IsPublicEmailDomain("alice@acme.com") {
		t.Error("full address under a corporate domain must not be public")
	}
	// Plus-addressed and dotted local parts do not affect the domain check.
	if !c.IsPublicEmailDomain("a.b.c+tag@yahoo.com") {
		t.Error("local-part shape must not affect the domain classification")
	}
}

func TestIsPublicEmailDomain_Normalisation(t *testing.T) {
	t.Parallel()
	c := &Config{}

	// Case, surrounding whitespace, and a trailing FQDN dot all normalise.
	for _, in := range []string{"GMAIL.COM", "  Gmail.Com  ", "gmail.com.", "ALICE@GMAIL.COM"} {
		if !c.IsPublicEmailDomain(in) {
			t.Errorf("IsPublicEmailDomain(%q) = false, want true after normalisation", in)
		}
	}
}

func TestIsPublicEmailDomain_EnvExtension(t *testing.T) {
	t.Parallel()
	// Extras are canonicalised: mixed case + surrounding spaces still match.
	c := &Config{PublicEmailDomains: "consumer.example, Foo.TEST ,bar.example"}

	for _, d := range []string{"x@consumer.example", "foo.test", "bar.example"} {
		if !c.IsPublicEmailDomain(d) {
			t.Errorf("IsPublicEmailDomain(%q) = false, want true via GATEWAY_PUBLIC_EMAIL_DOMAINS", d)
		}
	}
	// A domain not in the built-in set nor the extras is still corporate.
	if c.IsPublicEmailDomain("notlisted.example") {
		t.Error("a domain absent from built-ins and extras must not be public")
	}
}

func TestIsPublicEmailDomain_Empty(t *testing.T) {
	t.Parallel()
	c := &Config{}

	for _, in := range []string{"", "   ", "@", "alice@", "@gmail.com"} {
		// "@gmail.com" → domain "gmail.com" IS public; the rest are empty.
		want := in == "@gmail.com"
		if got := c.IsPublicEmailDomain(in); got != want {
			t.Errorf("IsPublicEmailDomain(%q) = %v, want %v", in, got, want)
		}
	}
}
