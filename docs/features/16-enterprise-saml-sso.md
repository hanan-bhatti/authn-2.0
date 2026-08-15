# Feature Specification: FR-16 Enterprise SAML 2.0 & Native SSO

## 1. Overview

**FR-16: Enterprise SAML 2.0 & Native SSO** provides corporate Single Sign-On capabilities for enterprise customers using Okta, Microsoft Azure AD / Entra ID, Ping Identity, Keycloak, or Auth0. It enables domain-based auto-routing, Just-In-Time (JIT) user provisioning, X.509 signature verification, SAML assertion processing, domain SSO enforcement policies, and real-time webhook events.

---

## 2. Architecture & Data Model

SAML configuration relies on the Ent ORM schema [`saml_connection.go`](../../apps/auth-engine/ent/schema/saml_connection.go):

- `id`: string (`saml_...`, unique, immutable)
- `organization_id`: string (owning organization)
- `idp_entity_id`: string (Issuer URI)
- `idp_sso_url`: string (Single Sign-On HTTP-POST / Redirect URL)
- `idp_certificate`: string (Public X.509 PEM certificate)
- `allowed_domains`: array of verified domains (e.g. `["siemens.com", "siemens.de"]`)
- `attribute_mapping`: JSON attribute map (`{"email": "attr_email"}`)
- `enforce_sso`: boolean (`true` disables password/social login for allowed domains)

---

## 3. Validation Bounds & Limits

| Attribute | Validation / Limit Bound |
| :--- | :--- |
| **IdP Entity ID** | Min 3, Max 500 characters. |
| **IdP SSO URL** | Valid HTTP/HTTPS URL format, Max 2048 characters. |
| **IdP Certificate** | Valid PEM formatted X.509 certificate block (must contain `CERTIFICATE`). Max 10,000 chars. |
| **Allowed Domains** | 1 to 20 domains per SAML connection. Domain regex validation. Domain conflict guard across tenant. |
| **Domain Lookup** | Real-time domain lookup endpoint `/v1/client/auth/domain-lookup`. |

---

## 4. API Endpoints

### Unauthenticated SAML Execution Endpoints
- `POST /v1/saml/acs` — Assertion Consumer Service (ACS) endpoint. Decodes SAMLResponse, verifies assertions, provisions user JIT, links to organization, and returns user/org payload.
- `GET /v1/saml/metadata/:orgId` — Service Provider (SP) XML Metadata document generator.

### Client Domain Lookup Endpoint (`/v1/client/auth/domain-lookup`)
*Requires Publishable Key `pk_...`*
- `POST /v1/client/auth/domain-lookup` — Checks if an email domain has an active SAML connection and whether `enforce_sso` is enabled.

### Organization SAML Configuration Endpoints (`/v1/client/organizations/:orgId/saml`)
*Requires Publishable Key `pk_...` and User Bearer JWT*
- `POST /v1/client/organizations/:orgId/saml` — Configure SAML 2.0 connection.
- `GET /v1/client/organizations/:orgId/saml` — Get SAML connection settings.
- `PATCH /v1/client/organizations/:orgId/saml` — Update SAML connection settings (IdP URL, Cert, Domains, `enforce_sso`).
- `DELETE /v1/client/organizations/:orgId/saml` — Delete SAML connection.

---

## 5. Webhooks & Audit Events

- `saml.connection_created`
- `saml.connection_updated`
- `saml.connection_deleted`
- `saml.login_success` (includes `user_id`, `email`, `domain`, `org_id`)
- `saml.login_failed`

---

## 6. Verification

Run automated Go tests:
```bash
go test -v ./internal/saml/...
```
