# Domain Lookup & SSO Enforcement API (`POST /v1/client/auth/domain-lookup`)

> **Last Verified**: `2026-08-06` — 100% verified via live `curl` pentest suite against running server.

## Overview
The Domain Lookup endpoint allows login UIs to inspect an email domain (e.g. `user@acme.com`) prior to password entry to determine if Enterprise SAML Single Sign-On (SSO) is active or strictly enforced.

---

## Enumeration Safety & Security Controls
* **Enumeration Evasion**: Querying a domain that is NOT configured for SSO returns `{"has_sso": false, "enforce_sso": false}` (`200 OK`). It **never** reveals whether an organization exists, avoiding tenant enumeration vectors.
* **Rate Limiting**: Rate limited to prevent automated domain scanning attacks.
* **SSO Enforcement Guard**: When `enforce_sso: true`, standard email/password authentication endpoints (`POST /v1/client/auth/login`) reject password login attempts for domain-matched users with `403 Forbidden` (`SSO login is enforced for domain 'acme.com'`).

---

## Endpoint Specification

### Domain Lookup Request (`POST /v1/client/auth/domain-lookup`)
* **Headers**: `X-Authn-Publishable-Key: pk_test_...`
* **Request Body**:
```json
{
  "domain": "acme.com"
}
```

### Matched Domain Response (`200 OK`)
```json
{
  "has_sso": true,
  "enforce_sso": true,
  "org_id": "org_aac11dae-f5c",
  "org_name": "Acme Enterprise Corp",
  "idp_sso_url": "https://idp.acme.com/sso"
}
```

### Non-Existent / Non-SSO Domain Response (`200 OK`)
```json
{
  "has_sso": false,
  "enforce_sso": false
}
```
