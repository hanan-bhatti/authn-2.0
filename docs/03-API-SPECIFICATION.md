# API Specification (Client & Admin REST/OIDC)

**Document Version**: 1.0.0  
**Date**: 2026-08-01  
**Status**: Approved Specification (Execution Ready)  
**Author**: Authn Core Team  

---

## 1. Overview & Authentication Headers

The **Authn Engine** exposes two distinct HTTP API surfaces:
1. **Public Client API (`/v1/client/*`)**: Used by web frontends (React, Vue, Next.js) and mobile clients (Android, iOS) via Publishable Client Keys (`pk_test_...` / `pk_live_...`).
2. **Admin Management API (`/v1/admin/*`)**: Used strictly by backend servers and the Developer Web Console via Secret Admin Keys (`sk_test_...` / `sk_live_...`) or Bearer tokens.
3. **OpenID Connect & OAuth 2.0 Standard Endpoints (`/oauth/*`, `/.well-known/*`)**: RFC-compliant OIDC authorization server endpoints.

### Authentication Headers & Client Types

| API Surface | Header | Format | Example |
| :--- | :--- | :--- | :--- |
| **Public Client API** | `X-Authn-Publishable-Key` | `pk_<env>_<hash>` | `X-Authn-Publishable-Key: pk_test_7f8a9b...` |
| **Client Device Type** | `X-Authn-Client-Type` | `web` (default) \| `native` | `X-Authn-Client-Type: native` |
| **Admin Management API** | `Authorization` | `Bearer sk_<env>_<hash>` | `Authorization: Bearer sk_live_3c2d1e...` |

*(Note: All API JSON request and response payloads use camelCase exclusively)*

---

## 2. Dual Token Delivery Model (Web vs Native Mobile)

To protect web clients against Cross-Site Scripting (XSS) token theft:
* **Web Browsers (`X-Authn-Client-Type: web` or omitted)**: 
  * Short-lived `accessToken` returned in JSON body.
  * Long-lived `refreshToken` is **NEVER returned in JSON**; it is set automatically via a `Set-Cookie: authn_refresh_token=...; HttpOnly; Secure; SameSite=Lax; Path=/` response header.
* **Native Mobile Apps (`X-Authn-Client-Type: native`)**: 
  * `refreshToken` is returned directly in the JSON response body so native Android/iOS apps can store it in Android KeyStore or iOS Secure Enclave.

---

## 3. Public Client API Endpoints (`/v1/client/*`)

All public client endpoints require `X-Authn-Publishable-Key` and enforce origin whitelisting against `allowed_cors_origins`.

### 3.1 Sign Up with Password
* **Endpoint**: `POST /v1/client/auth/signup`
* **Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "name": "Alex Smith"
}
```
* **Response (201 Created — Web Client)**:
```json
{
  "user": {
    "id": "usr_9a8b7c",
    "email": "user@example.com",
    "emailVerified": false,
    "name": "Alex Smith"
  },
  "session": {
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "expiresAt": 1722384000
  }
}
```
* **Response Headers (Web Client)**: `Set-Cookie: authn_refresh_token=raw_refresh_token_64chars...; HttpOnly; Secure; SameSite=Lax`

### 3.2 Sign In with Password
* **Endpoint**: `POST /v1/client/auth/login`
* **Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```
* **Response (200 OK — Standard Login)**:
```json
{
  "session": {
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "expiresAt": 1722384000
  }
}
```
* **Response (200 OK — Requires 2FA)**:
```json
{
  "requires2FA": true,
  "twoFactorToken": "tft_8f7e6d5c...",
  "methods": ["push", "totp", "passkey"],
  "matchNumber": 47
}
```
*(Note: `twoFactorToken` has a 120-second TTL and is cryptographically single-use)*

### 3.3 Real-Time WebSocket 2FA Approval Endpoint
* **Endpoint**: `GET /v1/client/ws/2fa?two_factor_token=tft_8f7e6d5c...`
* **Protocol**: WebSockets (WSS)
* **Behavior**: Holds real-time connection open for web browsers waiting for mobile push 2FA approval.
* **Server Broadcast Event (upon mobile approval)**:
```json
{
  "event": "2fa_approved",
  "exchangeToken": "ext_9f8e7d6c5b4a"
}
```
*(Note: `exchangeToken` has a 60-second TTL and is cryptographically single-use)*

### 3.4 2FA Token Exchange (Web Client Cookie Setting)
* **Endpoint**: `POST /v1/client/auth/2fa/exchange`
* **Request Body**:
```json
{
  "exchangeToken": "ext_9f8e7d6c5b4a"
}
```
* **Response (200 OK)**: Issues `accessToken` in JSON body and sets `authn_refresh_token` HttpOnly cookie. `exchangeToken` is deleted immediately upon exchange.

### 3.5 Verify 2FA (Mobile Push or Direct TOTP)
* **Endpoint**: `POST /v1/client/auth/2fa/verify`
* **Request Body**:
```json
{
  "challengeId": "chl_8f7e6d5c4b3a",
  "selectedNumber": 47,
  "signature": "3045022100..."
}
```
* **Response (200 OK)**: Validates 120s challenge TTL, signature, and selected number match. Triggers WebSocket broadcast to web browser.

### 3.6 Passwordless Magic Link Login
* **Endpoint**: `POST /v1/client/auth/magic-link`
* **Request Body**:
```json
{
  "email": "user@example.com"
}
```
* **Response (200 OK)**: Sends single-use 15-minute signed login URL to user's email.

### 3.7 Social Auth Initiate & Callback Flow
1. **Initiate Social Auth**: `GET /v1/client/auth/social/:provider?redirect_uri=...`
   * Generates a 32-byte cryptographically random `state` parameter and sets an `HttpOnly` state cookie (`authn_oauth_state`).
   * Redirects user to provider login (Google, Apple, GitHub, X, etc.).
2. **Social Auth Callback**: `GET /v1/client/auth/social/:provider/callback?code=...&state=...`
   * Validates `state` parameter against `authn_oauth_state` cookie (CSRF prevention).
   * Exchanges `code` for third-party tokens, encrypts tokens with KMS AES-256-GCM, upserts `User` and `Identity` records, and issues Authn session cookies/tokens.

### 3.8 Get Current User & Validate Session
* **Endpoint**: `GET /v1/client/user/me`
* **Headers**: `Authorization: Bearer <accessToken>`
* **Fail-Open Behavior**: If Redis cache is degraded, validates JWT locally using cached JWKS public key and appends response header `X-Authn-Degraded-Mode: true`.

### 3.9 Rate Limited Error Response (HTTP 429)
* **Status**: `429 Too Many Requests`
* **Response Headers**: `Retry-After: 60`
* **Response Body**:
```json
{
  "error": "rate_limit_exceeded",
  "message": "Too many requests. Please try again in 60 seconds.",
  "retryAfter": 60
}
```

---

## 4. OpenID Connect & OAuth 2.0 Endpoints

### 4.1 OpenID Discovery Document
* **Endpoint**: `GET /.well-known/openid-configuration`
* **Returns**: Standard OIDC discovery JSON metadata (issuer, authorization_endpoint, token_endpoint, jwks_uri).

### 4.2 Public JWKS Key Set
* **Endpoint**: `/.well-known/jwks.json`
* **Returns**: Active RS256/ES256 public keys used for stateless JWT signature verification. Includes 7-day overlapping grace period for rotated keys.

### 4.3 OAuth 2.0 Token Endpoint (Refresh & PKCE Exchange)
* **Endpoint**: `POST /oauth/token`
* **Grant Types**: `authorization_code` (with PKCE), `refresh_token`.
* **Outage Policy**: Fail-Closed (rate-limited to prevent refresh token brute forcing). Under the hood, `@authn/js` uses this exact endpoint with `grant_type=refresh_token` for seamless session renewal.

---

## 5. Admin Management API Endpoints (`/v1/admin/*`)

### 5.1 Create Application Key Pair
* **Endpoint**: `POST /v1/admin/applications/:appId/keys`
* **Request Body**:
```json
{
  "environment": "test",
  "type": "secret"
}
```
* **Response (201 Created — One-Time Secret Reveal)**:
```json
{
  "key": {
    "id": "key_1a2b3c",
    "prefix": "sk_test_",
    "rawSecretKey": "sk_test_9876543210fedcba...",
    "environment": "test"
  },
  "warning": "The rawSecretKey is returned exactly once and cannot be retrieved again. Please store it securely."
}
```

### 5.2 Admin User Impersonation ("Log in as User")
* **Endpoint**: `POST /v1/admin/users/:userId/impersonate`
* **Response (200 OK)**:
```json
{
  "impersonationSession": {
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "expiresAt": 1722387600
  }
}
```
*(Note: Access token carries `impersonatorId` claim and generates an audit log)*

### 5.3 List Tenant Users
* **Endpoint**: `GET /v1/admin/users?limit=50&cursor=usr_9a8b7c`
* **Response (200 OK — Cursor Pagination)**:
```json
{
  "users": [
    {
      "id": "usr_9a8b7c",
      "email": "user@example.com",
      "status": "active",
      "createdAt": "2026-07-30T10:00:00Z"
    }
  ],
  "nextCursor": "usr_1x2y3z",
  "hasMore": true
}
```
