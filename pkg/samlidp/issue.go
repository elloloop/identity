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

// Metadata implements MetadataProvider. It emits a minimal but
// SP-consumable IdP EntityDescriptor: the signing KeyDescriptor plus
// SingleSignOnService endpoints (HTTP-POST and HTTP-Redirect) and, when
// configured, a SingleLogoutService endpoint.
func (i *RSAIssuer) Metadata() ([]byte, error) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	fmt.Fprintf(&b, `<md:EntityDescriptor xmlns:md=%q entityID=%q>`, nsMetadata, i.entityID)
	fmt.Fprintf(&b, `<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration=%q>`, nsProtocol)
	// Signing certificate.
	fmt.Fprintf(&b, `<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds=%q><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`, nsDSig, i.certBase64())
	if i.sloURL != "" {
		fmt.Fprintf(&b, `<md:SingleLogoutService Binding=%q Location=%q/>`, bindingRedirect, i.sloURL)
		fmt.Fprintf(&b, `<md:SingleLogoutService Binding=%q Location=%q/>`, bindingPOST, i.sloURL)
	}
	fmt.Fprintf(&b, `<md:NameIDFormat>%s</md:NameIDFormat>`, nameIDFormatEmail)
	fmt.Fprintf(&b, `<md:SingleSignOnService Binding=%q Location=%q/>`, bindingRedirect, i.ssoURL)
	fmt.Fprintf(&b, `<md:SingleSignOnService Binding=%q Location=%q/>`, bindingPOST, i.ssoURL)
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
// already-canonical byte layout (single fixed prefixes, no extra
// whitespace) so the bytes we digest are exactly the bytes an SP
// re-canonicalizes under exclusive C14N.
func (i *RSAIssuer) buildAssertion(p assertionParams) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<saml:Assertion xmlns:saml=%q ID=%q IssueInstant=%q Version="2.0">`,
		nsAssertion, p.id, samlTime(p.issueInstant))
	fmt.Fprintf(&b, `<saml:Issuer>%s</saml:Issuer>`, escape(i.entityID))
	// Subject.
	b.WriteString(`<saml:Subject>`)
	fmt.Fprintf(&b, `<saml:NameID Format=%q>%s</saml:NameID>`, p.nameIDFormat, escape(p.nameID))
	b.WriteString(`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`)
	fmt.Fprintf(&b, `<saml:SubjectConfirmationData InResponseTo=%q NotOnOrAfter=%q Recipient=%q/>`,
		p.inResponseTo, samlTime(p.notOnOrAfter), p.acsURL)
	b.WriteString(`</saml:SubjectConfirmation></saml:Subject>`)
	// Conditions.
	fmt.Fprintf(&b, `<saml:Conditions NotBefore=%q NotOnOrAfter=%q>`,
		samlTime(p.issueInstant), samlTime(p.notOnOrAfter))
	fmt.Fprintf(&b, `<saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>`, escape(p.audience))
	b.WriteString(`</saml:Conditions>`)
	// AuthnStatement.
	fmt.Fprintf(&b, `<saml:AuthnStatement AuthnInstant=%q>`, samlTime(p.issueInstant))
	fmt.Fprintf(&b, `<saml:AuthnContext><saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef></saml:AuthnContext>`, authnContextPassword)
	b.WriteString(`</saml:AuthnStatement>`)
	// Attributes.
	if len(p.attributes) > 0 {
		b.WriteString(`<saml:AttributeStatement>`)
		for _, name := range sortedKeys(p.attributes) {
			fmt.Fprintf(&b, `<saml:Attribute Name=%q NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>`,
				name, escape(p.attributes[name]))
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
		`<ds:SignedInfo xmlns:ds=%q><ds:CanonicalizationMethod Algorithm=%q/><ds:SignatureMethod Algorithm=%q/><ds:Reference URI="#%s"><ds:Transforms><ds:Transform Algorithm=%q/><ds:Transform Algorithm=%q/></ds:Transforms><ds:DigestMethod Algorithm=%q/><ds:DigestValue>%s</ds:DigestValue></ds:Reference></ds:SignedInfo>`,
		nsDSig, algExcC14N, algRSASHA256, assertionID, algEnvelopeSig, algExcC14N, algSHA256, digestB64,
	)

	siDigest := sha256.Sum256([]byte(signedInfo))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, siDigest[:])
	if err != nil {
		return "", fmt.Errorf("samlidp: sign assertion: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	signature := fmt.Sprintf(
		`<ds:Signature xmlns:ds=%q>%s<ds:SignatureValue>%s</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>`,
		nsDSig, signedInfo, sigB64, i.certBase64(),
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
	fmt.Fprintf(&b, `<samlp:Response xmlns:samlp=%q xmlns:saml=%q ID=%q Version="2.0" IssueInstant=%q Destination=%q InResponseTo=%q>`,
		nsProtocol, nsAssertion, responseID, samlTime(issued), acs, inResponseTo)
	fmt.Fprintf(&b, `<saml:Issuer>%s</saml:Issuer>`, escape(i.entityID))
	fmt.Fprintf(&b, `<samlp:Status><samlp:StatusCode Value=%q/></samlp:Status>`, statusSuccess)
	b.WriteString(signedAssertion)
	b.WriteString(`</samlp:Response>`)
	return b.String()
}
