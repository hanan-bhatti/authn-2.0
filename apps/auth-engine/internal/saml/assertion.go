/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/assertion.go
 * Tier: Business Logic Layer / Assertion Verification
 *
 * Description: Cryptographic and semantic verification of SAML 2.0 responses
 *              posted to the Assertion Consumer Service — XML-DSig signature
 *              validation against a connection's X.509 certificate, status,
 *              issuer, validity window and audience checks, and the single-use
 *              guard that stops a verified assertion being presented twice.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package saml

import (
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	// statusSuccess is the only Status.StatusCode.Value an assertion may be
	// consumed under. Every other code reports that the identity provider did
	// not authenticate the subject.
	statusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

	// clockSkewTolerance widens the Conditions window at both ends. Identity
	// provider and service provider clocks drift independently, so an assertion
	// is not rejected over sub-minute disagreement about the current time. Sixty
	// seconds is the tolerance conventionally granted; a wider window extends
	// how long a captured assertion stays replayable.
	clockSkewTolerance = 60 * time.Second

	// pemCertificateBlockType is the PEM block type an X.509 certificate is
	// carried in.
	pemCertificateBlockType = "CERTIFICATE"

	// responseElement, assertionElement, encryptedAssertionElement and
	// signatureElement are the local names this package matches on. Identity
	// providers vary the namespace prefix, so only the local name is compared.
	responseElement           = "Response"
	assertionElement          = "Assertion"
	encryptedAssertionElement = "EncryptedAssertion"
	signatureElement          = "Signature"
)

// samlDocument is a parsed but wholly untrusted SAML response, holding the
// elements a signature can be verified over alongside the fields decoded from
// them.
//
// Nothing read from this type may influence authentication until the relevant
// element has been through verifyAssertion.
type samlDocument struct {
	// root is the Response element as it arrived, the element a response-level
	// signature is verified over.
	root *etree.Element
	// assertion is the Assertion element as it arrived, the element an
	// assertion-level signature is verified over.
	assertion *etree.Element
	// rootSigned reports whether the Response carries an enveloped signature.
	rootSigned bool
	// assertionSigned reports whether the Assertion carries one.
	assertionSigned bool
	// decoded is the whole document decoded into Go values. It is used to read
	// the issuer that selects a connection, and the response status.
	decoded SAMLResponseXML
}

// issuer returns the identity provider the document claims to come from,
// preferring the response-level Issuer and falling back to the assertion's.
//
// The value is unauthenticated. It selects which connection's certificate the
// signature is checked against; verifyAssertion then re-checks the issuer of
// every signed element against that connection.
func (d *samlDocument) issuer() string {
	if issuer := strings.TrimSpace(d.decoded.Issuer); issuer != "" {
		return issuer
	}
	return strings.TrimSpace(d.decoded.Assertion.Issuer)
}

// verifiedAssertion is an assertion proven to have been signed by a configured
// identity provider, together with the connection whose certificate proved it.
type verifiedAssertion struct {
	// conn is the connection whose certificate verified the signature, and
	// whose organization the subject belongs to.
	conn *ent.SAMLConnection
	// assertion is decoded exclusively from the bytes the signature covers.
	assertion SAMLAssertion
	// expiresAt is the assertion's NotOnOrAfter, which bounds how long its ID
	// must be remembered to prevent replay.
	expiresAt time.Time
}

// parseSAMLDocument decodes a SAML response into its elements and Go values.
//
// Returns ErrInvalidAssertion when the payload is not XML, is not rooted at a
// Response, carries no Assertion, or carries an encrypted one, which this
// service provider does not advertise support for and cannot decrypt.
func parseSAMLDocument(xmlBytes []byte) (*samlDocument, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("%w: failed to parse XML: %v", ErrInvalidAssertion, err)
	}

	root := doc.Root()
	if root == nil || root.Tag != responseElement {
		return nil, fmt.Errorf("%w: document root is not a SAML Response", ErrInvalidAssertion)
	}

	if findChildElement(root, encryptedAssertionElement) != nil {
		return nil, fmt.Errorf("%w: encrypted assertions are not supported", ErrInvalidAssertion)
	}

	assertion := findChildElement(root, assertionElement)
	if assertion == nil {
		return nil, fmt.Errorf("%w: response carries no Assertion", ErrInvalidAssertion)
	}

	var decoded SAMLResponseXML
	if err := xml.Unmarshal(xmlBytes, &decoded); err != nil {
		return nil, fmt.Errorf("%w: failed to parse XML: %v", ErrInvalidAssertion, err)
	}

	return &samlDocument{
		root:            root,
		assertion:       assertion,
		rootSigned:      findChildElement(root, signatureElement) != nil,
		assertionSigned: findChildElement(assertion, signatureElement) != nil,
		decoded:         decoded,
	}, nil
}

// findChildElement returns the first direct child of el with the given local
// name, or nil when there is none.
//
// Only direct children are considered: the SAML schema places both the
// enveloped signature and the assertion directly under their parent, and a
// deeper match would let a crafted document present an element the signature
// does not cover as though it did.
func findChildElement(el *etree.Element, name string) *etree.Element {
	for _, child := range el.ChildElements() {
		if child.Tag == name {
			return child
		}
	}
	return nil
}

// verifyAssertion proves that doc was issued by the identity provider conn is
// configured for, and returns the assertion decoded from the signed bytes.
//
// Checks run in the order signature, status, issuer, validity window, audience,
// so that nothing beyond the certificate lookup is trusted before the signature
// holds. Every value returned is read from bytes the signature covers.
//
// Returns ErrSignatureFailed when no signature verifies against the
// connection's certificate, ErrAssertionExpired when the assertion is outside
// its Conditions window, ErrAudienceMismatch when an AudienceRestriction names
// a different service provider, ErrInvalidCert when the connection's stored
// certificate is unusable, and ErrInvalidAssertion for a malformed or
// unsuccessful response.
func verifyAssertion(doc *samlDocument, conn *ent.SAMLConnection, now time.Time, expectedAudience string) (*verifiedAssertion, error) {
	certificates, err := parseIdPCertificates(conn.IdpCertificate)
	if err != nil {
		return nil, err
	}

	validation := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certificates})

	// A signature on either element is accepted because identity providers
	// differ over which they sign, but each signature that is present must
	// verify: a document may not have a broken signature ignored because
	// another one holds.
	var signedResponse *SAMLResponseXML
	if doc.rootSigned {
		verified, err := validation.Validate(doc.root)
		if err != nil {
			return nil, fmt.Errorf("%w: Response signature: %v", ErrSignatureFailed, err)
		}
		var response SAMLResponseXML
		if err := decodeElement(verified, &response); err != nil {
			return nil, fmt.Errorf("%w: signed Response is unreadable: %v", ErrInvalidAssertion, err)
		}
		signedResponse = &response
	}

	var signedAssertion *SAMLAssertion
	if doc.assertionSigned {
		verified, err := validation.Validate(doc.assertion)
		if err != nil {
			return nil, fmt.Errorf("%w: Assertion signature: %v", ErrSignatureFailed, err)
		}
		var assertion SAMLAssertion
		if err := decodeElement(verified, &assertion); err != nil {
			return nil, fmt.Errorf("%w: signed Assertion is unreadable: %v", ErrInvalidAssertion, err)
		}
		signedAssertion = &assertion
	}

	if signedAssertion == nil {
		if signedResponse == nil {
			return nil, fmt.Errorf("%w: neither the Response nor the Assertion is signed", ErrSignatureFailed)
		}
		// A response-level signature covers the assertion nested inside it, so
		// the assertion carried by the verified response is equally proven.
		signedAssertion = &signedResponse.Assertion
	}

	// The status lives in the response envelope, which is unsigned when the
	// identity provider signs only the assertion. Reading it there is safe in
	// one direction only: a forged status can cause a rejection, never an
	// acceptance, and the subject is still authenticated by the signature.
	status := doc.decoded.Status.StatusCode.Value
	if signedResponse != nil {
		status = signedResponse.Status.StatusCode.Value
	}
	if status != statusSuccess {
		return nil, fmt.Errorf("%w: identity provider reported status %q", ErrInvalidAssertion, status)
	}

	if signedResponse != nil && strings.TrimSpace(signedResponse.Issuer) != conn.IdpEntityID {
		return nil, fmt.Errorf("%w: Response Issuer is not the configured identity provider", ErrInvalidAssertion)
	}
	if strings.TrimSpace(signedAssertion.Issuer) != conn.IdpEntityID {
		return nil, fmt.Errorf("%w: Assertion Issuer is not the configured identity provider", ErrInvalidAssertion)
	}

	expiresAt, err := checkConditions(signedAssertion.Conditions, now)
	if err != nil {
		return nil, err
	}

	if err := checkAudience(signedAssertion.Conditions, expectedAudience); err != nil {
		return nil, err
	}

	if strings.TrimSpace(signedAssertion.ID) == "" {
		return nil, fmt.Errorf("%w: Assertion carries no ID", ErrInvalidAssertion)
	}

	return &verifiedAssertion{
		conn:      conn,
		assertion: *signedAssertion,
		expiresAt: expiresAt,
	}, nil
}

// checkConditions enforces the assertion's validity window and returns the
// instant it stops being valid.
//
// NotOnOrAfter is required: an assertion with no expiry stays usable forever to
// anyone who captures it. NotBefore is enforced when present. Both bounds are
// widened by clockSkewTolerance.
//
// Returns ErrAssertionExpired when the window is absent, unparseable, or does
// not contain now.
func checkConditions(conditions SAMLConditions, now time.Time) (time.Time, error) {
	notOnOrAfter := strings.TrimSpace(conditions.NotOnOrAfter)
	if notOnOrAfter == "" {
		return time.Time{}, fmt.Errorf("%w: Conditions carries no NotOnOrAfter", ErrAssertionExpired)
	}

	expiresAt, err := time.Parse(time.RFC3339, notOnOrAfter)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: unparseable NotOnOrAfter %q", ErrAssertionExpired, notOnOrAfter)
	}
	if !now.Before(expiresAt.Add(clockSkewTolerance)) {
		return time.Time{}, fmt.Errorf("%w: assertion expired at %s", ErrAssertionExpired, notOnOrAfter)
	}

	if notBefore := strings.TrimSpace(conditions.NotBefore); notBefore != "" {
		startsAt, err := time.Parse(time.RFC3339, notBefore)
		if err != nil {
			return time.Time{}, fmt.Errorf("%w: unparseable NotBefore %q", ErrAssertionExpired, notBefore)
		}
		if now.Before(startsAt.Add(-clockSkewTolerance)) {
			return time.Time{}, fmt.Errorf("%w: assertion is not valid until %s", ErrAssertionExpired, notBefore)
		}
	}

	return expiresAt, nil
}

// checkAudience enforces that an assertion restricted to an audience names this
// service provider's entity ID for the organization the connection belongs to.
//
// An assertion carrying no AudienceRestriction is accepted, since the identity
// provider has not restricted where it may be presented.
//
// Returns ErrAudienceMismatch when restrictions are present and none matches.
func checkAudience(conditions SAMLConditions, expected string) error {
	if len(conditions.AudienceRestrictions) == 0 {
		return nil
	}

	for _, restriction := range conditions.AudienceRestrictions {
		for _, audience := range restriction.Audiences {
			if strings.TrimSpace(audience) == expected {
				return nil
			}
		}
	}

	return fmt.Errorf("%w: assertion is not addressed to %s", ErrAudienceMismatch, expected)
}

// parseIdPCertificates decodes every X.509 certificate in a connection's stored
// PEM blob, so that a provider mid-way through a key rotation can publish both.
//
// Returns ErrInvalidCert when the blob holds no certificate or one that does
// not parse.
func parseIdPCertificates(pemData string) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemCertificateBlockType {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: stored certificate does not parse: %v", ErrInvalidCert, err)
		}
		certificates = append(certificates, certificate)
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("%w: connection holds no PEM X.509 certificate", ErrInvalidCert)
	}

	return certificates, nil
}

// decodeElement unmarshals el into v.
//
// Callers pass the element returned by signature validation, which is
// reserialized from the exact bytes the digest was computed over, so the values
// decoded here are the ones the identity provider signed.
//
// Returns an error when the element cannot be serialized or does not fit v.
func decodeElement(el *etree.Element, v interface{}) error {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())

	serialized, err := doc.WriteToBytes()
	if err != nil {
		return err
	}

	return xml.Unmarshal(serialized, v)
}

// assertionReplayGuard remembers the IDs of assertions that have been consumed,
// so that a verified assertion captured in transit cannot be presented a second
// time before it expires.
//
// It holds state in this process only. A deployment running several instances,
// or one that restarts, admits a replay to an instance that has not seen the
// assertion; closing that requires storage shared across instances.
type assertionReplayGuard struct {
	// mu guards consumed.
	mu sync.Mutex
	// consumed maps an assertion key to the instant it stops being replayable,
	// after which the entry is dropped.
	consumed map[string]time.Time
}

// newAssertionReplayGuard constructs an empty guard.
func newAssertionReplayGuard() *assertionReplayGuard {
	return &assertionReplayGuard{consumed: make(map[string]time.Time)}
}

// consume records key as used until expiresAt and reports whether this is its
// first use. A false return means the assertion has already been consumed and
// must be rejected.
//
// Entries that have expired are dropped on each call, which bounds the map to
// the assertions still inside their validity window.
func (g *assertionReplayGuard) consume(key string, expiresAt, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	for consumedKey, consumedUntil := range g.consumed {
		if !now.Before(consumedUntil) {
			delete(g.consumed, consumedKey)
		}
	}

	if _, seen := g.consumed[key]; seen {
		return false
	}

	g.consumed[key] = expiresAt
	return true
}
