package samlidp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Metadata implements MetadataProvider. It emits a minimal, SP-consumable
// IdP EntityDescriptor: the IdP identity (entityID), the signing
// KeyDescriptor (certificate), and the supported NameID format.
//
// It deliberately does NOT advertise SingleSignOnService or
// SingleLogoutService endpoints. This slice mounts only /saml/metadata; the
// SSO (HTTP-POST/Redirect) and SLO binding handlers are a later slice.
// Publishing those Location URLs now would point an importing SP at routes
// that return 404. The endpoints are added here once their handlers exist
// (the issuer already carries the configured ssoURL/sloURL for that slice).
//
// Every dynamic value is XML-escaped via escape; attribute values are never
// emitted with fmt %q (see escape's documentation for why).
func (i *RSAIssuer) Metadata() ([]byte, error) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	fmt.Fprintf(&b, `<md:EntityDescriptor xmlns:md="%s" entityID="%s">`, escape(nsMetadata), escape(i.entityID))
	fmt.Fprintf(&b, `<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="%s">`, escape(nsProtocol))
	// Signing certificate.
	fmt.Fprintf(&b, `<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="%s"><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`, escape(nsDSig), i.certBase64())
	fmt.Fprintf(&b, `<md:NameIDFormat>%s</md:NameIDFormat>`, escape(nameIDFormatEmail))
	b.WriteString(`</md:IDPSSODescriptor></md:EntityDescriptor>`)
	return []byte(b.String()), nil
}

// Issue implements AssertionIssuer. It builds an enveloped-signature SAML
// assertion (signed with RSA-SHA256 over a SHA-256 digest) wrapped in a
// SAML Response addressed to the SP's ACS URL.
func (i *RSAIssuer) Issue(_ context.Context, sp ServiceProvider, subject Subject, req AuthnRequestInfo) (Response, error) {
	if strings.TrimSpace(sp.EntityID) == "" || strings.TrimSpace(sp.ACSURL) == "" {
		return Response{}, fmt.Errorf("%w: SP EntityID and ACSURL are required", ErrUnknownServiceProvider)
	}
	if strings.TrimSpace(subject.NameID) == "" {
		return Response{}, errors.New("samlidp: subject NameID is required")
	}
	if req.Issuer != "" && req.Issuer != sp.EntityID {
		return Response{}, fmt.Errorf("%w: request issuer %q != %q", ErrUnknownServiceProvider, req.Issuer, sp.EntityID)
	}

	acs := sp.ACSURL
	if req.ACSURL != "" {
		// The SP-requested ACS URL only takes effect when it matches the
		// registered ACS URL; otherwise we fall back to the trusted
		// registered value to prevent open-redirect of the assertion.
		if req.ACSURL == sp.ACSURL {
			acs = req.ACSURL
		}
	}

	audience := sp.Audience
	if audience == "" {
		audience = sp.EntityID
	}
	nameIDFormat := sp.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = nameIDFormatEmail
	}

	issued := now().UTC()
	notOnOrAfter := issued.Add(assertionValiditySeconds * time.Second)

	assertionID := "_" + randID()
	responseID := "_" + randID()

	assertion := i.buildAssertion(assertionParams{
		id:           assertionID,
		issueInstant: issued,
		notOnOrAfter: notOnOrAfter,
		audience:     audience,
		acsURL:       acs,
		inResponseTo: req.ID,
		nameID:       subject.NameID,
		nameIDFormat: nameIDFormat,
		attributes:   subject.Attributes,
	})

	signed, err := i.signAssertion(assertionID, assertion)
	if err != nil {
		return Response{}, err
	}

	respXML := i.buildResponse(responseID, issued, acs, req.ID, signed)
	return Response{XML: []byte(respXML), ACSURL: acs, RelayState: req.RelayState}, nil
}

type assertionParams struct {
	id           string
	issueInstant time.Time
	notOnOrAfter time.Time
	audience     string
	acsURL       string
	inResponseTo string
	nameID       string
	nameIDFormat string
	attributes   map[string]string
}

// buildAssertion serializes the unsigned <saml:Assertion> with a stable,
// fixed byte layout (single fixed prefixes, no extra whitespace). Every
// attribute value AND element-content value is XML-escaped via escape — we
// never emit XML attributes with fmt %q, which is Go-literal quoting (it
// renders " as \" so the quote still closes the attribute) and would let an
// attacker-controlled value (e.g. the echoed AuthnRequest @ID in
// InResponseTo, or an attribute name/value) inject forged, well-formed
// <saml:Attribute> elements into the *signed* assertion.
//
// TODO(saml-sso-binding): the SignedInfo declares the exclusive-C14N
// transform (algExcC14N) but the digest is computed over these raw
// serialized bytes, not a true exc-c14n canonicalization. The fixed,
// whitespace-free layout makes that digest stable, but real exc-c14n (or a
// vetted XML-DSig library) MUST replace this before the SSO POST/Redirect
// binding lands and assertions are consumed by arbitrary SPs.
func (i *RSAIssuer) buildAssertion(p assertionParams) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<saml:Assertion xmlns:saml="%s" ID="%s" IssueInstant="%s" Version="2.0">`,
		escape(nsAssertion), escape(p.id), escape(samlTime(p.issueInstant)))
	fmt.Fprintf(&b, `<saml:Issuer>%s</saml:Issuer>`, escape(i.entityID))
	// Subject.
	b.WriteString(`<saml:Subject>`)
	fmt.Fprintf(&b, `<saml:NameID Format="%s">%s</saml:NameID>`, escape(p.nameIDFormat), escape(p.nameID))
	b.WriteString(`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`)
	fmt.Fprintf(&b, `<saml:SubjectConfirmationData InResponseTo="%s" NotOnOrAfter="%s" Recipient="%s"/>`,
		escape(p.inResponseTo), escape(samlTime(p.notOnOrAfter)), escape(p.acsURL))
	b.WriteString(`</saml:SubjectConfirmation></saml:Subject>`)
	// Conditions.
	fmt.Fprintf(&b, `<saml:Conditions NotBefore="%s" NotOnOrAfter="%s">`,
		escape(samlTime(p.issueInstant)), escape(samlTime(p.notOnOrAfter)))
	fmt.Fprintf(&b, `<saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>`, escape(p.audience))
	b.WriteString(`</saml:Conditions>`)
	// AuthnStatement.
	fmt.Fprintf(&b, `<saml:AuthnStatement AuthnInstant="%s">`, escape(samlTime(p.issueInstant)))
	fmt.Fprintf(&b, `<saml:AuthnContext><saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef></saml:AuthnContext>`, escape(authnContextPassword))
	b.WriteString(`</saml:AuthnStatement>`)
	// Attributes.
	if len(p.attributes) > 0 {
		b.WriteString(`<saml:AttributeStatement>`)
		for _, name := range sortedKeys(p.attributes) {
			fmt.Fprintf(&b, `<saml:Attribute Name="%s" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>`,
				escape(name), escape(p.attributes[name]))
		}
		b.WriteString(`</saml:AttributeStatement>`)
	}
	b.WriteString(`</saml:Assertion>`)
	return b.String()
}

// signAssertion computes the enveloped XML-DSig signature over the
// assertion and returns the assertion with the <ds:Signature> inserted
// immediately after the <saml:Issuer> element (the position xmldsig
// schema-validation requires for SAML assertions).
func (i *RSAIssuer) signAssertion(assertionID, assertion string) (string, error) {
	digest := sha256.Sum256([]byte(assertion))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	signedInfo := fmt.Sprintf(
		`<ds:SignedInfo xmlns:ds="%s"><ds:CanonicalizationMethod Algorithm="%s"/><ds:SignatureMethod Algorithm="%s"/><ds:Reference URI="#%s"><ds:Transforms><ds:Transform Algorithm="%s"/><ds:Transform Algorithm="%s"/></ds:Transforms><ds:DigestMethod Algorithm="%s"/><ds:DigestValue>%s</ds:DigestValue></ds:Reference></ds:SignedInfo>`,
		escape(nsDSig), escape(algExcC14N), escape(algRSASHA256), escape(assertionID), escape(algEnvelopeSig), escape(algExcC14N), escape(algSHA256), digestB64,
	)

	siDigest := sha256.Sum256([]byte(signedInfo))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, siDigest[:])
	if err != nil {
		return "", fmt.Errorf("samlidp: sign assertion: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	signature := fmt.Sprintf(
		`<ds:Signature xmlns:ds="%s">%s<ds:SignatureValue>%s</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>`,
		escape(nsDSig), signedInfo, sigB64, i.certBase64(),
	)

	// Insert the signature right after the closing </saml:Issuer> tag.
	marker := `</saml:Issuer>`
	idx := strings.Index(assertion, marker)
	if idx < 0 {
		return "", errors.New("samlidp: assertion missing Issuer element")
	}
	insertAt := idx + len(marker)
	return assertion[:insertAt] + signature + assertion[insertAt:], nil
}

func (i *RSAIssuer) buildResponse(responseID string, issued time.Time, acs, inResponseTo, signedAssertion string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	fmt.Fprintf(&b, `<samlp:Response xmlns:samlp="%s" xmlns:saml="%s" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s">`,
		escape(nsProtocol), escape(nsAssertion), escape(responseID), escape(samlTime(issued)), escape(acs), escape(inResponseTo))
	fmt.Fprintf(&b, `<saml:Issuer>%s</saml:Issuer>`, escape(i.entityID))
	fmt.Fprintf(&b, `<samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status>`, escape(statusSuccess))
	b.WriteString(signedAssertion)
	b.WriteString(`</samlp:Response>`)
	return b.String()
}
