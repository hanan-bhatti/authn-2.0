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
- `environment`: enum `test` | `live`, defaulting to `live` (which environment the connection's users are provisioned into)

### Environment & JIT provisioning

An organization has at most one SAML connection, and that connection's `environment` decides which environment the people arriving through the identity provider belong to. A `test` connection provisions sandbox accounts; a `live` one provisions real accounts.

This is the one environment field in the schema that defaults to `live`. A connection exists only once an administrator has supplied a real identity provider's certificate and SSO URL, so the people arriving through it are that organization's actual employees.

The ACS endpoint is unauthenticated — there is no publishable or secret key on the request, so no middleware has established an environment, and the assertion itself carries none. The connection is therefore the only thing that can say, and `resolveOrProvisionSubject` narrows both its lookup and its create by it. Narrowing also makes the lookup single-valued by construction, which the write depends on: the unique index is on `(tenant, environment, email)`, so an unnarrowed query matching two rows would fall through to a create the index rejects, locking that subject out of SSO permanently rather than for one attempt.

**Trialling a provider.** Create the connection with `"environment": "test"`, sign in a few times, confirm the assertions map to the people you expect, then `PATCH` it to `"live"`. The promotion governs subsequent sign-ins and does not migrate the accounts already created: an employee who signed in during the trial keeps their test account and receives a separate live one on their next sign-in. Both the environment and any change to it are recorded on the `saml.connection_created` / `saml.connection_updated` audit rows.

### A live connection takes a live key

`environment` arriving in the request body does not make it a free choice. A connection in `live` is the record an organization's real employees authenticate through, so its certificate, its SSO URL and its existence are all live configuration. `callerMayWrite` refuses a test-scoped caller that creates a live connection, edits one, promotes a test one into live, or deletes one, with `403 Forbidden` and code `live_key_required`.

Because the schema default is `live`, a create that omits `environment` is the same request as one that names it — without this check a test credential could file a live connection by supplying nothing at all.

The guard sits in the service rather than on the route, because the decision needs the stored row and not just the credential: a test key may edit a connection that stays in `test`, and only reading the row says which case a `PATCH` is. Both the stored environment and the requested one are checked, for different reasons — the first stops a test key touching live SSO at all, the second stops it promoting a trial it does own.

The rule is one-directional. A live key may edit a connection still in `test`, which is what a promotion has to read before it writes. A symmetric rule would have made promotion impossible; a rule checking only the destination would have let a test key *demote* a live connection and break an organization's production SSO. Reads are ungated in both directions.

The caller's environment comes from the privacy context every auth middleware installs, so the rule applies identically to the `pk_` client tier and the `sk_` tenant tier. A caller with no scope at all, or a bypass, is exempt: provisioning, seeding and the retention sweeps address both environments at once, and every HTTP entry point installs a scope, so an absent one is not a request.

---

## 3. Validation Bounds & Limits

| Attribute | Validation / Limit Bound |
| :--- | :--- |
| **IdP Entity ID** | Min 3, Max 500 characters. |
| **IdP SSO URL** | Valid HTTP/HTTPS URL format, Max 2048 characters. |
| **IdP Certificate** | Valid PEM formatted X.509 certificate block (must contain `CERTIFICATE`). Max 10,000 chars. |
| **Allowed Domains** | 1 to 20 domains per SAML connection. Domain regex validation. Domain conflict guard across tenant. |
| **Environment** | `test` or `live`, case-insensitive and trimmed. Omitted on create means `live`. Anything else is rejected with `400`; a typo is never resolved into one of the two. A `live` target — named or defaulted — requires a live credential, else `403 live_key_required`. |
| **Domain Lookup** | Real-time domain lookup endpoint `/v1/client/auth/domain-lookup`. |

---

## 4. API Endpoints

### Unauthenticated SAML Execution Endpoints
- `POST /v1/saml/acs` — Assertion Consumer Service (ACS) endpoint. Decodes SAMLResponse, verifies assertions, provisions user JIT, links to organization, issues a session, and either redirects the browser to the `RelayState` destination with the access token in the URL fragment, or returns the token in the body when no registered destination was supplied. See [`docs/endpoints/cross-domain-resume.md`](../endpoints/cross-domain-resume.md).
- `GET /v1/saml/metadata/:orgId` — Service Provider (SP) XML Metadata document generator.

### Client Domain Lookup Endpoint (`/v1/client/auth/domain-lookup`)
*Requires Publishable Key `pk_...`*
- `POST /v1/client/auth/domain-lookup` — Checks if an email domain has an active SAML connection and whether `enforce_sso` is enabled.

### Organization SAML Configuration Endpoints (`/v1/client/organizations/:orgId/saml`)
*Requires Publishable Key `pk_...` and User Bearer JWT*
- `POST /v1/client/organizations/:orgId/saml` — Configure SAML 2.0 connection.
- `GET /v1/client/organizations/:orgId/saml` — Get SAML connection settings.
- `PATCH /v1/client/organizations/:orgId/saml` — Update SAML connection settings (IdP URL, Cert, Domains, `enforce_sso`, `environment`).
- `DELETE /v1/client/organizations/:orgId/saml` — Delete SAML connection.

---

## 5. Webhooks & Audit Events

- `saml.connection_created` (includes `environment`)
- `saml.connection_updated` (carries `environment_from` / `environment_to` when the connection was promoted or demoted)
- `saml.connection_deleted`
- `saml.login_success` (includes `user_id`, `email`, `domain`, `org_id`)
- `saml.login_failed`

---

## 6. Verification

Run automated Go tests:
```bash
go test -v ./internal/saml/...
```

`internal/saml/live_key_test.go` covers the credential rule directly: that a test-scoped caller can neither file a live connection, omit `environment` into one, edit one, promote its own trial nor delete one; that its own test connection is unaffected; that a live key promotes; and that a bypass or an unscoped context is exempt. `test/live_key_test.go` drives the same rule over HTTP, where the environment comes from the presented key rather than from a constructed context.
