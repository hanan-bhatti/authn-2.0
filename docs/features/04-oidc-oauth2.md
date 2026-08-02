# Feature 04: OpenID Connect (OIDC) Discovery & OAuth2 PKCE Server

**Module**: `apps/auth-engine/internal/oauth` & `apps/auth-engine/pkg/jwt`  
**Version**: 1.0.0  
**Status**: Implemented, Production-Ready & Verified  

---

## 1. Overview

The **OpenID Connect (OIDC) & OAuth2 Server** provides RFC 6749 and RFC 7636 compliant Single Sign-On (SSO) capabilities, discovery metadata, public JWKS key distribution, and PKCE-protected authorization code token exchanges for client applications, mobile SDKs, and third-party developers.

---

## 2. Supported Standards & Endpoints

| Endpoint | Method | Standard | Purpose |
| :--- | :--- | :--- | :--- |
| `/.well-known/openid-configuration` | `GET` | RFC 8414 | Auto-discovery document for OIDC clients and SDKs. |
| `/v1/oauth/jwks` | `GET` | RFC 7517 | Public JSON Web Key Set for client-side JWT verification. |
| `/v1/oauth/authorize` | `GET` | RFC 6749 / RFC 7636 | Initiates Authorization Code Flow with PKCE challenge. |
| `/v1/oauth/token` | `POST` | RFC 6749 / RFC 7636 | Exchanges code + `code_verifier` for signed Access Token + ID Token. |

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
  "response_types_supported": ["code", "token", "id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["HS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "code_challenge_methods_supported": ["S256", "plain"],
  "claims_supported": ["iss", "sub", "aud", "exp", "iat", "email", "name", "tenant_id"],
  "grant_types_supported": ["authorization_code", "refresh_token"]
}
```

### 3.2 JWKS Public Keys (`GET /v1/oauth/jwks`)
```json
{
  "keys": [
    {
      "kty": "oct",
      "use": "sig",
      "alg": "HS256",
      "kid": "key_v1"
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
  "id_token": "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleV92MSIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile email"
}
```
