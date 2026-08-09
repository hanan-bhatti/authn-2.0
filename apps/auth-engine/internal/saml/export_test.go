/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/export_test.go
 * Tier: Business Logic Layer / Test Support
 *
 * Description: Narrow test-only access to unexported entity-ID and audience
 *              logic, so the external test package can assert that the entity ID
 *              published in metadata is exactly the one an assertion's audience
 *              is measured against.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package saml

// SPEntityIDForTest exposes a Service's entity-ID derivation.
func SPEntityIDForTest(s *Service, organizationID string) string {
	return s.spEntityID(organizationID)
}

// CheckAudienceForTest runs audience validation against a single-audience
// assertion, returning nil when expected is accepted.
func CheckAudienceForTest(audience, expected string) error {
	return checkAudience(SAMLConditions{
		AudienceRestrictions: []SAMLAudienceRestriction{{Audiences: []string{audience}}},
	}, expected)
}
