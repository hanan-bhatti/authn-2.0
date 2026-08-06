# Endpoint Specification: `GET /.well-known/openid-configuration`

## Overview
* **Route**: `GET /.well-known/openid-configuration`
* **HTTP Method**: `GET` (also supports `HEAD`)
* **Purpose**: OpenID Connect 1.0 Provider Discovery Document (RFC 8414). Returns standard authorization server metadata, public endpoints, supported grant types, signing algorithms, scopes, and token claims.

---

## Authentication & Access Control
* **Authentication Required**: `None` (Public / Unauthenticated)
* **Security Headers Required**: None. Any passed `Authorization`, `X-Publishable-Key`, or `X-Secret-Key` headers are safely ignored.

---

## Request Parameters
* **Headers**: None
* **Query Parameters**: None
* **Request Body**: None

---

## Responses & Status Codes

### `200 OK` — Discovery Metadata Payload
Returned with `Cache-Control: public, max-age=3600` header to allow client SDKs and reverse proxies to cache discovery metadata.

```json
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/v1/oauth/authorize",
  "token_endpoint": "http://localhost:8080/v1/oauth/token",
  "userinfo_endpoint": "http://localhost:8080/v1/oauth/userinfo",
  "jwks_uri": "http://localhost:8080/v1/oauth/jwks",
  "response_types_supported": [
    "code"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256"
  ],
  "scopes_supported": [
    "openid",
    "profile",
    "email"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "none"
  ],
  "code_challenge_methods_supported": [
    "S256"
  ],
  "claims_supported": [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "email",
    "name",
    "tenant_id"
  ],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token"
  ]
}
```

### `405 Method Not Allowed` — Invalid HTTP Method
Returned when requesting with non-GET verbs (`POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`).

```json
{
  "error": {
    "code": 405,
    "message": "Method Not Allowed"
  }
}
```

---

## Rate Limiting Behavior
* **Exempt from Rate Limiting**: Registered at top-level `app.Get("/.well-known/openid-configuration")` before rate-limiting middleware to allow external OIDC client libraries (e.g. NextAuth, Passport.js, OIDC Client) to fetch metadata on boot without throttling.

---

## Design Notes & Security Compliance
* **Issuer Alignment**: The `issuer` field strictly prefers `ISSUER_URL` (`s.cfg.Issuer`) when configured in environment variables, guaranteeing exact string alignment with the `iss` claim in issued JWT ID Tokens per OIDC Discovery 1.0 Spec Section 3.
* **PKCE Enforcement**: Advertises `S256` only (`code_challenge_methods_supported: ["S256"]`). Requests sending `code_challenge_method=plain` are strictly rejected at `/v1/oauth/authorize` with `400 Bad Request`.
* **UserInfo Endpoint**: Full OIDC UserInfo endpoint is active at `/v1/oauth/userinfo`.

---

## Verification & Pentest History
* **Last Verified Date**: `2026-08-06`
* **Verification Method**: Manual live HTTP pentest + Automated Go Integration Test (`TestOIDCDiscoveryEndpoint`).
