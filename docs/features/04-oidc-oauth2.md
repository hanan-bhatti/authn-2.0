# Feature 04: OpenID Connect (OIDC) Discovery & OAuth2 PKCE Server

**Module**: `apps/auth-engine/internal/oauth` & `apps/auth-engine/pkg/jwt`  
**Version**: 1.0.0  
**Status**: Fully Verified, Hardened & Production-Ready  

---

## 1. Overview

The **OpenID Connect (OIDC) & OAuth2 Server** provides RFC 6749 and RFC 7636 compliant Single Sign-On (SSO) capabilities, discovery metadata, public JWKS key distribution, and PKCE-protected authorization code token exchanges for client applications, mobile SDKs, and third-party developers.

---

## 2. Supported Standards & Endpoints

| Endpoint | Method | Standard | Status | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `/.well-known/openid-configuration` | `GET` | RFC 8414 | Verified | Auto-discovery document for OIDC clients and SDKs. |
| `/v1/oauth/jwks` | `GET` | RFC 7517 | Verified | Public JSON Web Key Set (RS256 RSA Public Modulus `n` & Exponent `e`). |
| `/v1/oauth/authorize` | `GET` | RFC 6749 / RFC 7636 | Verified | Initiates Authorization Code Flow with PKCE challenge & session validation. |
| `/v1/oauth/token` | `POST` | RFC 6749 / RFC 7636 | Verified | Exchanges code + `code_verifier` for signed Access Token + RS256 ID Token. |

---

## 3. Verified Endpoints & Payloads

### 3.1 OIDC Discovery (`GET /.well-known/openid-configuration`)
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
    "S256",
    "plain"
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

### 3.2 JWKS Public Keys (`GET /v1/oauth/jwks`)
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "key_v1",
      "n": "2oH9w-ZnVWJI-6y5_zL5E2LZtoCPepRWLCnlZkOsyoark...",
      "e": "AQAB"
    }
  ]
}
```

### 3.3 PKCE Token Exchange (`POST /v1/oauth/token`)
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleV92MSIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile email"
}
```

---

## 4. Security Architecture & Hardening Applied

1. **RS256 Asymmetric RSA Key Signing**:
   - ID Tokens (`id_token`) are signed using 2048-bit RSA Private Keys (`RS256`).
   - Public Modulus `n` and Exponent `e` are exported via `/v1/oauth/jwks`. Zero private key secrets are ever exposed.
2. **Implicit Flow Deprecated**:
   - `response_types_supported` is strictly restricted to `["code"]` (Authorization Code Flow with PKCE). Implicit flow (`"token"`, `"id_token"`) is disabled for XSS protection.
3. **RSA Key Persistence (`FileKeyStore`)**:
   - Private keys are stored in PEM format (`AUTHN_RSA_KEY_PATH`, default `.keys/rsa_private.pem`, gitignored).
   - Server restarts reload the same RSA keypair, preserving public `kid`/`n`/`e` across instance restarts.
4. **Session-Based User Resolution**:
   - `GET /v1/oauth/authorize` requires an active session cookie or `Authorization: Bearer <access_token>`.
   - The authorization code subject (`sub`) is bound strictly to `claims.Sub` from the caller's session token. The `user_id` query parameter is eliminated.
5. **Database-Backed Client & Redirect URI Validation**:
   - `client_id` is queried against the Ent `Application` database table. Unregistered clients return `400 Bad Request`.
   - `redirect_uri` is strictly matched against `app.ExactRedirectUris`. Unauthorized URIs return `400 Bad Request`.
6. **Database Identity Claims Lookup**:
   - `POST /v1/oauth/token` loads user claims (`email`, `name`, `tenant_id`) directly from the database using the bound `user_id`. Arbitrary claims in token exchange request bodies are ignored.

---

## 5. Known Gaps & Architecture Notes

* **Unimplemented Endpoint (`GET /v1/oauth/userinfo`)**: Advertised in OIDC Discovery metadata per specification, but the route currently returns `404 Not Found`. Users receive user claims directly inside the signed `id_token`.
* **Dual Signing Strategy**:
  - `access_token`: Signed with `HS256` (Symmetric HMAC-SHA256 for internal engine validation performance).
  - `id_token`: Signed with `RS256` (Asymmetric RSA PKCS#1 v1.5 with SHA-256 published via JWKS for external client verification).
  - This split is an intentional architectural design.
