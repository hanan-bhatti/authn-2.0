# API Specification (Client & Admin REST/OIDC)

**Document Version**: 2.0.0  
**Date**: 2026-08-05  
**Status**: Approved Specification (Production REST & OIDC Reference)  
**Author**: Authn Core Team  

---

## 1. Overview & Authentication Headers

The **Authn Engine** exposes three distinct HTTP API surfaces:
1. **Public Client API (`/v1/client/*`)**: Used by web frontends (React, Vue, Next.js) and mobile clients (Android, iOS) via Publishable Client Keys (`pk_test_...` / `pk_live_...`).
2. **Tenant Policy & Admin API (`/v1/tenant/*`, `/v1/admin/*`)**: Used by administrators and server environments via Secret Admin Keys (`sk_test_...` / `sk_live_...`) or Bearer tokens.
3. **OpenID Connect & OAuth 2.0 Standard Endpoints (`/v1/oauth/*`, `/.well-known/*`)**: RFC-compliant OIDC authorization server endpoints.

### Authentication Headers & Client Types

| API Surface | Header | Format | Example |
| :--- | :--- | :--- | :--- |
| **Public Client API** | `X-Authn-Publishable-Key` | `pk_<env>_<hash>` | `X-Authn-Publishable-Key: pk_test_7f8a9b...` |
| **Client Device Type** | `X-Authn-Client-Type` | `web` (default) \| `native` | `X-Authn-Client-Type: native` |
| **Admin Management API** | `Authorization` | `Bearer sk_<env>_<hash>` | `Authorization: Bearer sk_live_3c2d1e...` |

*(Note: All API JSON request and response payloads use camelCase/snake_case consistently per schema)*

---

## 2. Comprehensive Endpoint Index

### 2.1 System & Health
- `GET /v1/health` — Engine Liveness Probe (process liveness only; unauthenticated, exempt from rate-limiting)
- `GET /v1/ready` — Engine Readiness Probe (checks DB & Redis connectivity with 2s timeout; 200 ready / 503 not_ready)

### 2.2 OIDC Discovery & JWKS
- `GET /.well-known/openid-configuration` — OIDC Discovery Metadata
- `GET /v1/oauth/jwks` — Public RSA JWKS key set

### 2.3 OAuth 2.0 / OIDC Flow
- `GET /v1/oauth/authorize` — PKCE Authorization Code endpointhyyy4r21 DF
- `POST /v1/oauth/token` — Token exchange (`authorization_code`, `refresh_token`)

### 2.4 Core Client Authentication
- `POST /v1/client/signup` — User registration with email/password
- `POST /v1/client/login` — User authentication with Argon2id check
- `GET /v1/client/verify-email` — Single-use email verification link
- `POST /v1/client/resend-verification` — Resend email verification link

### 2.5 Session Management & Revocation (FR-8)
- `POST /v1/client/auth/refresh` — Rotate refresh token with 10s grace window & issue new JWT access token
- `GET /v1/client/sessions` — List active sessions for authenticated user with device parsing & `is_current` flag
- `POST /v1/client/sessions/revoke` — Revoke a specific session by ID
- `POST /v1/client/sessions/revoke-others` — Revoke all active user sessions except current
- `POST /v1/client/sessions/revoke-all` — Revoke all active user sessions
- `GET /v1/admin/users/:user_id/sessions` — Admin list user sessions
- `POST /v1/admin/users/:user_id/sessions/revoke-all` — Admin kill-switch to revoke all sessions for a user

### 2.6 Social Identity Providers (FR-7)
- `GET /v1/tenant/social-providers` — List all supported social providers, setup guides & status
- `GET /v1/tenant/social-providers/:provider` — Get setup guide & configuration for specific provider
- `PUT /v1/tenant/social-providers/:provider` — Configure provider client ID & encrypted secret with format validation
- `DELETE /v1/tenant/social-providers/:provider` — Remove provider configuration
- `GET /v1/client/auth/social/:provider/authorize` — Initiate social auth, generate 10-min CSRF state token & 302 redirect
- `GET /v1/client/auth/social/:provider/callback` — OAuth2 callback handler (exchanges code, finds/creates user, issues JWT)

### 2.7 Role-Based Access Control & Fine-Grained Permissions (FR-12)
- `GET /v1/tenant/roles` — List all roles for tenant with assigned permissions
- `POST /v1/tenant/roles` — Create custom role with validated permission strings & policy checks
- `PUT /v1/tenant/roles/:role_id/permissions` — Replace role permissions with audit logging
- `POST /v1/admin/users/:user_id/roles` — Assign role to user with audit trail
- `DELETE /v1/admin/users/:user_id/roles/:role_slug` — Revoke role from user with audit trail
- `GET /v1/client/user/permissions` — Retrieve accumulated roles & permissions for authenticated user

### 2.8 Smart Account Recovery & Guardians (FR-5)
- `POST /v1/client/account/guardians/invite` — Pre-enroll 1-5 guardians & issue zero-knowledge tokens
- `POST /v1/client/account/guardians/accept` — Accept guardian invitation
- `GET /v1/client/account/guardians` — List active guardians
- `DELETE /v1/client/account/guardians/:id` — Revoke guardian & trigger Re-Key/Re-Split
- `POST /v1/client/auth/recovery/initiate` — Initiate recovery & resolve dynamic methods
- `POST /v1/client/auth/recovery/proof/guardian` — Submit Shamir share proof ($k$-of-$N$)
- `POST /v1/client/auth/recovery/proof/phone-otp` — Submit phone OTP identity proof
- `POST /v1/client/auth/recovery/proof/email-otp` — Submit email OTP identity proof
- `POST /v1/client/auth/recovery/proof/old-password` — Submit old password proof
- `POST /v1/client/auth/recovery/proof/security-questions` — Submit security questions proof
- `POST /v1/client/auth/recovery/claim` — Execute final password reset & 2FA wipe with 15-min claim token
- `POST /v1/client/auth/recovery/cancel` — Cancel recovery via active authenticated session
- `POST /v1/client/auth/recovery/cancel/token` — Cancel recovery via public signed link token

### 2.9 Admin Tenant Policies & API Keys
- `GET /v1/tenant/password-policy` — Get tenant password policy
- `PUT /v1/tenant/password-policy` — Update tenant password complexity rules
- `GET /v1/tenant/security-policy` — Get tenant security policy
- `PUT /v1/tenant/security-policy` — Update tenant email verification & security policies
- `GET /v1/tenant/recovery-policy` — Get tenant recovery policy
- `PUT /v1/tenant/recovery-policy` — Update tenant recovery policy with 9 validation rules
- `POST /v1/admin/keys/` — Issue new publishable or secret API key
- `GET /v1/admin/keys/` — List API keys for application
- `POST /v1/admin/keys/:key_id/revoke` — Revoke API key

### 2.10 2FA Method Management & Verification (FR-4)
- `POST /v1/client/2fa/totp/enroll` — Generate secret & QR code URI for TOTP setup
- `POST /v1/client/2fa/totp/confirm` — Confirm TOTP setup with 6-digit code & activate
- `POST /v1/client/2fa/totp/verify` — Verify TOTP code during active session
- `POST /v1/client/2fa/totp/disable` — Disable TOTP 2FA (requires password confirmation)
- `POST /v1/client/2fa/webauthn/register/begin` — Initiate WebAuthn passkey registration options
- `POST /v1/client/2fa/webauthn/register/finish` — Finalize passkey registration with attestation
- `POST /v1/client/2fa/webauthn/login/begin` — Initiate WebAuthn passkey login options
- `POST /v1/client/2fa/webauthn/login/finish` — Finalize passkey login with assertion & issue JWT
- `GET /v1/client/2fa/webauthn/credentials` — List user's registered WebAuthn passkeys
- `DELETE /v1/client/2fa/webauthn/credentials/:id` — Delete a WebAuthn passkey (requires password)
- `POST /v1/client/2fa/sms/enroll` — Initiate SMS 2FA enrollment & send verification OTP
- `POST /v1/client/2fa/sms/confirm` — Confirm SMS 2FA with 6-digit OTP & activate
- `DELETE /v1/client/2fa/sms/disable` — Disable SMS 2FA (requires password)
- `POST /v1/client/auth/2fa/verify` — Unified login 2FA verification endpoint (`totp`, `webauthn`, `sms`, `backup_code`)

### 2.11 Outgoing Real-Time Event Webhooks (FR-13)
- `POST /v1/admin/webhooks/endpoints` — Register new webhook endpoint
- `GET /v1/admin/webhooks/endpoints` — List all webhook endpoints for tenant
- `GET /v1/admin/webhooks/endpoints/:id` — Get webhook endpoint details by ID
- `PUT /v1/admin/webhooks/endpoints/:id` — Update URL, description, or subscribed events
- `DELETE /v1/admin/webhooks/endpoints/:id` — Delete webhook endpoint and cascade delete delivery logs
- `POST /v1/admin/webhooks/endpoints/:id/ping` — Dispatch test ping webhook event
- `POST /v1/admin/webhooks/endpoints/:id/rotate-secret` — Rotate signing secret key
- `GET /v1/admin/webhooks/deliveries` — List webhook delivery audit logs

---

## 3. Endpoints & Edge Cases Detail

### 3.0 System Health & Readiness (`GET /v1/health` & `GET /v1/ready`)

#### `GET /v1/health` — Engine Liveness Probe
* **Description**: Returns engine liveness status and system timestamp.
* **Authentication**: Unauthenticated (Public).
* **Rate Limiting**: Exempt.
* **CORRECTION NOTICE [2026-08-05]**: *Previously, documentation implied `/v1/health` pinged database resources. `/v1/health` is strictly a shallow liveness probe (no DB/Redis ping) to prevent database outages from triggering container restart loops. For dependency health, call `/v1/ready`.*
* **Response (200 OK)**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-08-05T18:11:31Z"
}
```

#### `GET /v1/ready` — Engine Readiness Probe
* **Description**: Pings Database and Redis with a strict 2-second timeout per check.
* **Authentication**: Unauthenticated (Public).
* **Rate Limiting**: Exempt.
* **Response (200 OK — Ready)**:
```json
{
  "status": "ready",
  "checks": {
    "database": "ok",
    "redis": "ok"
  }
}
```
* **Response (503 Service Unavailable — Not Ready)**:
```json
{
  "status": "not_ready",
  "checks": {
    "database": "ok",
    "redis": "down"
  }
}
```

#### `GET /.well-known/openid-configuration` — OIDC Discovery Metadata
* **Description**: Returns standard OpenID Connect 1.0 discovery metadata payload.
* **Authentication**: Unauthenticated (Public).
* **Rate Limiting**: Exempt.
* **Headers Returned**: `Cache-Control: public, max-age=3600` (1-hour cache).
* **Issuer Alignment Fix [2026-08-05]**: *Prioritizes `ISSUER_URL` (`s.cfg.Issuer`) when configured to ensure the discovery document `issuer` matches the `iss` claim in ID tokens 100% of the time per OIDC Discovery 1.0 Spec Section 3.*
* **Known Limitation**: *Advertises `userinfo_endpoint` (`/v1/oauth/userinfo`), but that endpoint currently returns 404 (to be built in Endpoint 8).*
* **Response (200 OK)**:
```json
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/v1/oauth/authorize",
  "token_endpoint": "http://localhost:8080/v1/oauth/token",
  "userinfo_endpoint": "http://localhost:8080/v1/oauth/userinfo",
  "jwks_uri": "http://localhost:8080/v1/oauth/jwks",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "code_challenge_methods_supported": ["S256", "plain"],
  "claims_supported": ["iss", "sub", "aud", "exp", "iat", "email", "name", "tenant_id"],
  "grant_types_supported": ["authorization_code", "refresh_token"]
}
```

#### `GET /v1/oauth/jwks` — Public JWKS Key Set
* **Description**: Exposes public RSA key material (Modulus $N$, Exponent $E$) for JWT token verification.
* **Authentication**: Unauthenticated (Public).
* **Rate Limiting**: Exempt.
* **Headers Returned**: `Cache-Control: public, max-age=3600` (1-hour cache).
* **🔒 Security Audit**: Verified zero private key exponents (`d`, `p`, `q`, `dp`, `dq`, `qi`) in output.
* **Known Limitation**: *Currently exports 1 active RSA key. Multi-key rotation history array (30-day rotation with 7-day overlap) is a planned future enhancement.*
* **Response (200 OK)**:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "authn-rsa-key-1",
      "n": "u1P5z2...",
      "e": "AQAB"
    }
  ]
}
```

#### `GET /v1/saml/metadata/:orgId` — SP SAML Metadata Exporter
* **Description**: Returns Service Provider (SP) SAML 2.0 XML Metadata (`EntityDescriptor`) for an organization.
* **Authentication**: Unauthenticated (Public).
* **Rate Limiting**: Exempt.
* **Headers Returned**: `Content-Type: application/xml`, `Cache-Control: public, max-age=3600` (1-hour cache).
* **Database Validation**: Returns `404 Not Found` if `:orgId` does not exist or has no configured SAML connection.
* **Response (200 OK — Ready)**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="https://authn.com/saml/sp/org_acme" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8080/v1/saml/acs" index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>
```

### 3.1 Core Authentication (`POST /v1/client/signup`)

> **Last Verified**: `2026-08-06` — live `curl` against running server.
> See full endpoint doc: [`docs/endpoints/client-signup.md`](endpoints/client-signup.md)

- **Headers (Required)**: `X-Authn-Publishable-Key: pk_<env>_<hash>`, `Content-Type: application/json`
- **Headers (Optional)**: `X-Authn-Client-Type: web|native|mobile` (default: `web`)
- **Request**:
```json
{
  "email": "fresh.signup@authn.local",
  "password": "ValidPass123!",
  "name": "Fresh User"
}
```

#### `201 Created` — Successful Registration
Web client: refresh token in `Set-Cookie: authn_refresh_token; HttpOnly; SameSite=Lax; Path=/v1/client`.
Native/mobile client: refresh token in `refresh_token` JSON field.
```json
{
  "user": {
    "id": "usr_08e90da4-9e3",
    "email": "fresh.signup@authn.local",
    "email_verified": false,
    "name": "Fresh User",
    "status": "active",
    "created_at": "2026-08-06T00:26:27Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### `400 Bad Request` — Missing Fields / Email Format / Password Policy
```json
{ "error": "email and password are required" }
{ "error": "invalid email address format" }
{
  "error": "password does not meet policy requirements",
  "missing_criteria": ["min_length"]
}
```

#### `401 Unauthorized` — Missing Publishable Key
```json
{ "error": "missing publishable API key in X-Authn-Publishable-Key header" }
```

#### `405 Method Not Allowed` — Wrong HTTP Verb
```json
{ "error": { "code": 405, "message": "Method Not Allowed" } }
```

#### `409 Conflict` — Email Already Registered
Deliberate design choice matching standard B2C auth practice (Firebase, Clerk, Auth0). Not a security gap.
```json
{ "error": "user with this email already exists" }
```

#### `429 Too Many Requests` — Rate Limit
5 attempts / 900s window per IP + endpoint. Includes `Retry-After` header.
```json
{
  "error": "too many attempts, please try again later",
  "retry_after_seconds": 889
}
```

#### `POST /v1/client/login`

> **Last Verified**: `2026-08-06` — live `curl` against running server.
> See full endpoint doc: [`docs/endpoints/client-login.md`](endpoints/client-login.md)

- **Headers (Required)**: `X-Authn-Publishable-Key: pk_<env>_<hash>`, `Content-Type: application/json`
- **Headers (Optional)**: `X-Authn-Client-Type: web|native|mobile` (default: `web`)
- **Request**:
```json
{
  "email": "user.vanilla@authn.local",
  "password": "UserPass123!"
}
```

#### `200 OK` — Successful Authentication (Web Client)
Web client: refresh token in `Set-Cookie: authn_refresh_token; HttpOnly; SameSite=Lax; Path=/v1/client`.
Native/mobile client: refresh token in `refresh_token` JSON field.
```json
{
  "user": {
    "id": "usr_vanilla_007",
    "email": "user.vanilla@authn.local",
    "email_verified": true,
    "status": "active",
    "created_at": "2026-08-05T23:32:04Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### `200 OK` — 2FA / MFA Challenge Required
Access token and refresh token withheld until second factor verification is complete.
```json
{
  "user": {
    "id": "usr_totp_002",
    "email": "user.totp@authn.local",
    "email_verified": true,
    "status": "active",
    "created_at": "2026-08-05T23:32:03Z"
  },
  "mfa_required": true,
  "mfa_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "methods": ["totp"]
}
```

#### `401 Unauthorized` — Invalid Email or Password (Enumeration-Safe)
Constant-time CPU execution (~190ms) using `DummyArgon2idHash` when user not found.
```json
{ "error": "invalid email or password" }
```

#### `401 Unauthorized` — Missing Publishable Key
```json
{ "error": "missing publishable API key in X-Authn-Publishable-Key header" }
```

#### `429 Too Many Requests` — Rate Limit
5 attempts / 900s window per IP. Escalation backoff: 15m -> 1h -> 6h -> 24h.
```json
{
  "error": "too many attempts, please try again later",
  "retry_after_seconds": 889
}
```

#### `503 Service Unavailable` — Redis Outage (Fail-CLOSED)
```json
{ "error": "rate limit service unavailable" }
```

### 3.2 Email Verification (`GET /v1/client/verify-email` & `POST /v1/client/resend-verification`)


> **Last Verified**: `2026-08-06` — live `curl` + real token extracted from Mailpit SMTP catcher.
> See full endpoint doc: [`docs/endpoints/client-verify-email.md`](endpoints/client-verify-email.md)

#### Token Properties
* 32-byte `crypto/rand` → 64-char hex raw token. Only **SHA-256 hash** stored in DB.
* **24-hour expiry**. **Single-use**: token + expiry cleared from DB on first successful verification.

#### `GET /v1/client/verify-email?token=<raw_token>`
```json
// 200 OK — success
{
  "message": "email successfully verified",
  "email": "verify.test@authn.local",
  "email_verified": true
}
// 400 — missing token: {"error": "verification token query parameter is required"}
// 400 — invalid/expired/replayed: {"error": "invalid or revoked token"}
// 401 — missing pk_: {"error": "missing publishable API key in X-Authn-Publishable-Key header"}
// 405 — wrong verb (Allow: GET, HEAD): {"error": {"code": 405, "message": "Method Not Allowed"}}
```

#### `POST /v1/client/resend-verification`
Enumeration-safe — unknown emails, already-verified accounts, and valid unverified accounts all return identical `200`. Dedicated per-email rate limiting (default: 3 requests / 3600s window) configurable via `AUTHN_RESEND_RATELIMIT_*`.
```json
// Request body
{ "email": "user@example.com" }

// 200 OK (all cases — enumeration-safe)
{"message": "if an account exists with this email address, a verification link has been sent"}

// 400 — invalid email format: {"error": "invalid email address format"}
// 401 — missing pk_: {"error": "missing publishable API key in X-Authn-Publishable-Key header"}
// 405 — wrong verb (Allow: POST): {"error": {"code": 405, "message": "Method Not Allowed"}}
// 429 — per-email rate limit: {"error": "too many verification email requests for this address, please try again later", "retry_after_seconds": 900}
```

### 3.3 Refresh Token Rotation (`POST /v1/client/auth/refresh`)

> **Last Verified**: `2026-08-06` — live `curl` against running server.
> See full endpoint doc: [`docs/endpoints/client-auth-refresh.md`](endpoints/client-auth-refresh.md)

- **Description**: Exchanges a valid opaque refresh token for a new 15-minute Access Token JWT and a newly rotated 64-byte Refresh Token. Enforces a **10-second grace window** for handling concurrent browser requests, and **automatic compromise mitigation** (revoking user sessions according to tenant `SecurityPolicy.token_reuse_policy`: `"global_revoke"` vs `"session_revoke"`) if token reuse occurs after the 10-second grace window. Parses `refresh_token` from JSON body first, with fallback to `authn_refresh_token` HttpOnly cookie.
- **Headers**: `X-Authn-Publishable-Key: pk_<env>_<hash>`, `Content-Type: application/json`
- **Request**:
```json
{
  "refresh_token": "266cb73e6f9aecffa0dbd527c24baab0e9a4fe03864cedfdd34296aa4c698da2"
}
```
- **Response (200 OK — Rotation)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "512bbc00-1004-4607-9279-752897038b18a14100aa-cf80-4f3a-a18a-30f9176585bc",
  "token_type": "Bearer",
  "expires_in": 900,
  "session_id": "ses_1e12795c-48f"
}
```
- **Response (200 OK — Grace Period Concurrent Request)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "",
  "token_type": "Bearer",
  "expires_in": 900,
  "session_id": "ses_1e12795c-48f"
}
```
- **Error Codes**:
  - `400 Bad Request`: `{"error": "refresh_token required"}`
  - `401 Unauthorized` (`invalid_token`): `{"code": "invalid_token", "error": "invalid or expired refresh token"}`
  - `401 Unauthorized` (`session_expired`): `{"code": "session_expired", "error": "session expired"}`
  - `401 Unauthorized` (`session_revoked`): `{"code": "session_revoked", "error": "session revoked"}`
  - `401 Unauthorized` (`session_compromised`): `{"code": "session_compromised", "error": "session reuse detected; all sessions revoked for security"}` (triggers automatic account-wide session revocation)
  - `405 Method Not Allowed`: `{"error": {"code": 405, "message": "Method Not Allowed"}}`

### 3.4 Session Management (`GET /v1/client/sessions` & `/v1/client/sessions/revoke*`)

> **Last Verified**: `2026-08-06` — live `curl` against running server.
> See full endpoint doc: [`docs/endpoints/client-sessions.md`](endpoints/client-sessions.md)

- **Description**: Allows authenticated users to view active sessions with parsed device details (`browser`, `os`, `device`, `label`) and `is_current` flag, or revoke sessions. Strict IDOR ownership validation (`sess.UserID == caller.UserID`) rejects cross-user revocation with `403 Forbidden`.
  - `/revoke`: Revokes a specific session by ID (`{"session_id": "ses_..."}`). Returns `400` if missing, `404` if not found, `403` if IDOR attempt.
  - `/revoke-others`: Revokes all active sessions for the user except current.
  - `/revoke-all`: Revokes all active user sessions (logout all devices).
- **Headers**: `Authorization: Bearer <jwt>`, `X-Authn-Publishable-Key: pk_<env>_<hash>`
- **Response (200 OK)**:
```json
{
  "sessions": [
    {
      "id": "ses_67f048b7",
      "device": {
        "browser": "Chrome",
        "os": "macOS",
        "device": "Desktop",
        "label": "Chrome on macOS"
      },
      "ip_address": "192.168.1.100",
      "location": "London, UK",
      "last_active_at": "2026-08-05T02:00:51Z",
      "created_at": "2026-08-05T01:30:00Z",
      "is_current": true
    }
  ]
}
```

### 3.5 Social Identity Providers (`/v1/tenant/social-providers` & `/v1/client/auth/social/*`)

> **Last Verified**: `2026-08-06` — live `curl` against running server.
> See full endpoint doc: [`docs/endpoints/client-social-oauth.md`](endpoints/client-social-oauth.md)

- **Description**: Configure 8 supported social identity providers (`google`, `github`, `discord`, `microsoft`, `apple`, `facebook`, `x`, `linkedin`) and handle OAuth2 authorization code flows.
- **Admin Config (`PUT /v1/tenant/social-providers/:provider`)**:
```json
{
  "enabled": true,
  "client_id": "demo_google_client_id_123.apps.googleusercontent.com",
  "client_secret": "demo_google_secret_xyz"
}
```
- **Authorize Redirect (`GET /v1/client/auth/social/:provider/authorize`)**:
  - Generates a 32-byte random hex CSRF state token stored in Redis with 10-minute TTL, then returns 302 redirect to provider's authorization page.
- **Callback Handler (`GET /v1/client/auth/social/:provider/callback`)**:
  - Consumes single-use CSRF state token, exchanges code for provider tokens, retrieves user profile, handles Account Linking vs Signup vs Login, and issues JWT access token.
- **Edge Cases & Error Codes**:
  - `400 Bad Request`: Missing `redirect_uri`, missing `code`/`state`, or expired/invalid CSRF state token.
### 3.6 Passwordless Magic Links (`POST /v1/client/auth/magic-link` & `GET|POST /v1/client/auth/magic-link/verify`)

> **Last Verified**: `2026-08-06` — live `curl` & Mailpit API verification against running server.
> See full endpoint doc: [`docs/endpoints/client-magic-link.md`](endpoints/client-magic-link.md)

- **Description**: Passwordless login & auto-provisioning flow. Generates 32-byte cryptographically secure single-use tokens sent via email (15-minute TTL). Verification marks email verified, creates login session, issues JWT with `sid`, and clears token to prevent replay attacks.
- **Headers**: `X-Authn-Publishable-Key: pk_<env>_<hash>`, `Content-Type: application/json`
- **Request (`POST /v1/client/auth/magic-link`)**:
```json
{
  "email": "user.vanilla@authn.local",
  "name": "Vanilla User"
}
```
- **Response (200 OK — Sent)**:
```json
{
  "message": "a magic login link has been sent to your email address"
}
```
- **Verification (`POST /v1/client/auth/magic-link/verify`)**:
```json
{
  "token": "266f205526adbded53d5094095f4eb8b3da4969db13b1acc24be28e0088951f6"
}
```
- **Edge Cases & Error Codes**:
  - `400 Bad Request`: Invalid email format (`invalid email address format`), missing token, or expired/replayed token (`invalid or expired magic link token`).

### 3.7 Role-Based Access Control (`/v1/tenant/roles`, `/v1/admin/users/:id/roles`, `/v1/client/user/permissions`)

> **Last Verified**: `2026-08-06` — live `curl` injection attack suite against running server.
> See full endpoint doc: [`docs/endpoints/tenant-rbac.md`](endpoints/tenant-rbac.md)

- **Description**: Creates custom RBAC roles, validates permission strings (`resource:action`), enforces policy guards (preventing privilege escalation for viewer/support roles), logs audit events, and evaluates user permissions. Rejects SQLi/XSS payloads in permission strings with `422 Unprocessable Entity`.
- **Headers**: `X-Authn-Secret-Key: sk_<env>_<hash>` (Admin), `Authorization: Bearer <jwt>` (Client)
- **Request (`POST /v1/tenant/roles`)**:
```json
{
  "name": "Content Editor",
  "slug": "content_editor",
  "description": "Can create and edit blog posts",
  "permissions": ["posts:create", "posts:update"]
}
```
- **Response (201 Created)**:
```json
{
  "id": "rol_322dfcbc",
  "name": "Content Editor",
  "description": "Can create and edit blog posts",
  "is_system_role": false,
  "permissions": ["posts:create", "posts:update"],
  "created_at": "2026-08-05T05:49:42Z"
}
```
- **Edge Cases & Error Codes**:
  - `422 Unprocessable Entity` (`ErrInvalidPermissionFormat`): Malformed permission string (e.g. `banana-permission:write`).
  - `422 Unprocessable Entity` (`ErrRestrictedPermission`): Assigned permission is restricted for that role under active `RolePermissionPolicy` (e.g. assigning `*:write` to `viewer` role).
  - `409 Conflict` (`ErrRoleExists`): Role with same name already exists in tenant.

### 3.8 Smart Account Recovery (`/v1/client/auth/recovery/*`)

> **Last Verified**: `2026-08-06` — live `curl` attack suite against running server.
> See full endpoint doc: [`docs/endpoints/client-account-recovery.md`](endpoints/client-account-recovery.md)

- **Description**: Initiates account recovery, resolves identity-proof methods in priority order (Guardians, Old Password, Email/Phone OTP, Security Questions), executes timing-safe dummy Argon2id hashes for non-existent users (`200 OK`), restricts old password proof to trusted devices, and arms a 7-day origin IP blacklist upon owner cancellation.
- **Request (`POST /v1/client/auth/recovery/initiate`)**:
```json
{
  "email": "user.vanilla@authn.local"
}
```
- **Response (200 OK — Valid or Timing-Safe Non-Existent User)**:
```json
{
  "recovery_request_id": "req_3e2f8c17-a80",
  "status": "initiated",
  "is_trusted_device_origin": false,
  "available_methods": ["email_otp"],
  "cancellation_token": "539d51ae12546f05021de68590ff751235001293f7f47709d2b5d70b96c132bc"
}
```
- **Edge Cases & Error Codes**:
  - `403 Forbidden` (`origin_blacklisted`): Requesting IP, subnet, or device is blacklisted for 7 days following a security cancellation.
  - `400 Bad Request`: Missing email, untrusted device for old password proof (`old password proof is disallowed from unfamiliar device or network`), or invalid claim token.
  "is_trusted_device_origin": true,
  "available_methods": ["guardians", "email_otp", "old_password"],
  "cancellation_token": "a1b2c3d4e5f6..."
}
```
- **Identity Proof Submissions**:
  - `POST /v1/client/auth/recovery/proof/phone-otp`: Submit SMS/WhatsApp OTP code (`{"recovery_request_id": "req_...", "phone_number": "+15551234567", "otp_code": "123456"}`). Returns `200 OK` (`{"status": "proof_verified", "message": "Phone OTP verified successfully"}`).
  - `POST /v1/client/auth/recovery/proof/email-otp`: Submit Email OTP code (`{"recovery_request_id": "req_...", "email": "user@example.com", "otp_code": "123456"}`). Returns `200 OK` (`{"status": "proof_verified", "message": "Email OTP verified successfully"}`).
  - `POST /v1/client/auth/recovery/proof/guardian`: Submit Shamir share string (`{"recovery_request_id": "req_...", "share_payload": "..."}`). Returns `{"threshold_reached": true, "status": "proof_verified"}`.
  - `POST /v1/client/auth/recovery/proof/old-password`: Submit old password (`{"recovery_request_id": "req_...", "password": "..."}`). Returns `{"status": "proof_verified"}`.
- **Edge Cases & Error Codes**:
  - `400 Bad Request` (`no_recovery_methods_available`): No methods configured or available for account. Directs to support.
  - `403 Forbidden` (`ErrOriginBlacklisted`): Request origin (IP, subnet, or device fingerprint) is on the 7-day security blacklist following a recent cancellation.

### 3.9 B2B Organizations & Team Invitations (`/v1/client/organizations/*` & `/v1/tenant/organizations/*`)

> **Last Verified**: `2026-08-06` — live `curl` attack suite against running server.
> See full endpoint doc: [`docs/endpoints/client-organizations.md`](endpoints/client-organizations.md)

- **Description**: Manages B2B organization workspaces, member roles (`org_admin`, `editor`, `viewer`), and 32-byte cryptographic invitation tokens (7-day TTL). Enforces single-use token consumption and cascading cleanup of member/invitation records upon org deletion.
- **Request (`POST /v1/client/organizations`)**:
```json
{
  "name": "Acme Corporation",
  "slug": "acme-corp-101",
  "logo_url": "https://acme.local/logo.png"
}
```
- **Response (201 Created)**:
```json
{
  "id": "org_9038723e-062",
  "tenant_id": "tnt_default",
  "name": "Acme Corporation",
  "slug": "acme-corp-101",
  "logo_url": "https://acme.local/logo.png",
  "created_at": "2026-08-06T03:05:29.432Z"
}
```
- **Edge Cases & Error Codes**:
  - `400 Bad Request`: Invalid slug format (`organization slug must be 2-50 lowercase alphanumeric characters or hyphens`), duplicate slug in tenant (`organization slug already exists in this tenant`), or replayed invitation token (`invitation has already been accepted`).
  - `404 Not Found`: Organization or invitation token not found.

### 3.11 Admin User Impersonation (`/v1/admin/users/:id/impersonate`, `/v1/tenant/impersonation-policy`, `/v1/client/auth/impersonate/exit`)

> **Last Verified**: `2026-08-06` — live `curl` attack suite against running server.
> See full endpoint doc: [`docs/endpoints/tenant-impersonation.md`](endpoints/tenant-impersonation.md)

- **Description**: Allows support & tenant administrators to impersonate end users with configurable step-up re-authentication, support ticket tracking, user opt-in enforcement, and short-lived JWT issuance (`is_impersonated: true`).
- **Request (`POST /v1/admin/users/:user_id/impersonate`)**:
```json
{
  "reason": "Investigating billing ticket",
  "ticket_id": "SUPP-9921",
  "duration_minutes": 15
}
```
- **Response (200 OK)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "impersonated_user": {
    "id": "usr_vanilla_007",
    "email": "user.vanilla@authn.local",
    "status": "active"
  },
  "impersonator_id": "key_test_sk_demo123_v3"
}
```
- **Edge Cases & Error Codes**:
  - `400 Bad Request` (`admin_step_up_required`): Admin step-up re-authentication is required before impersonating.
  - `403 Forbidden` (`user_opt_in_required`): Target user has not granted support access permission (`support_access_enabled: false`).
  - `422 Unprocessable Entity`: Impersonation duration violates policy bounds (`must be between 1 and 60 minutes`).

### 3.12 Admin API Keys (`POST /v1/admin/keys/`, `GET /v1/admin/keys/`, `POST /v1/admin/keys/:id/revoke`)
- **Description**: Allows tenant administrators to issue publishable client keys (`pk_...`) or secret keys (`sk_...`) for server SDKs.
- **Request (`POST /v1/admin/keys/`)**:
```json
{
  "application_id": "app_test123",
  "key_type": "secret",
  "name": "Backend SDK Key"
}
```
- **Response (201 Created)**:
```json
{
  "id": "key_8a9b0c1d",
  "key": "sk_test_12345678901234567890123456789012",
  "key_type": "secret",
  "environment": "test",
  "created_at": "2026-08-05T05:00:00Z"
}
```
*(Note: Full secret key value is returned ONCE on creation and never stored in plaintext)*

### 3.8 2FA Method Management & Verification (`/v1/client/2fa/*` & `/v1/client/auth/2fa/verify`)
- **Description**: Comprehensive setup, verification, listing, and disabling for TOTP, WebAuthn Passkeys, SMS 2FA, and unified login challenge verification.
- **TOTP Setup (`POST /v1/client/2fa/totp/enroll` & `/confirm`)**:
  - `POST /v1/client/2fa/totp/enroll`: Generates RFC 6238 TOTP secret. Returns `{"secret": "JBSWY3DPEHPK3PXP", "uri": "otpauth://totp/Authn:user@example.com?secret=..."}`.
  - `POST /v1/client/2fa/totp/confirm`: Body `{"code": "123456"}`. Activates TOTP and returns single-use backup recovery codes.
- **WebAuthn / Passkeys (`/v1/client/2fa/webauthn/*`)**:
  - Registration: `POST /v1/client/2fa/webauthn/register/begin` returns WebAuthn creation options. `POST /v1/client/2fa/webauthn/register/finish` validates attestation response and stores credential public key.
  - Login: `POST /v1/client/2fa/webauthn/login/begin` returns assertion options. `POST /v1/client/2fa/webauthn/login/finish` validates signature assertion and issues JWT session.
  - List & Delete: `GET /v1/client/2fa/webauthn/credentials` lists registered passkeys; `DELETE /v1/client/2fa/webauthn/credentials/:id` deletes passkey requiring password confirmation.
- **SMS 2FA (`/v1/client/2fa/sms/*`)**:
  - `POST /v1/client/2fa/sms/enroll`: Body `{"phone_number": "+15551234567"}`. Sends 6-digit OTP via configured SMS driver.
  - `POST /v1/client/2fa/sms/confirm`: Body `{"code": "123456"}`. Activates SMS 2FA.
  - `DELETE /v1/client/2fa/sms/disable`: Body `{"password": "..."}`. Disables SMS 2FA requiring password confirmation.
- **Unified Login 2FA Verification (`POST /v1/client/auth/2fa/verify`)**:
  - **Request Body**:
```json
{
  "mfa_token": "mfa_8a9b0c1d2e",
  "method": "totp",
  "code": "123456"
}
```
  - **Supported `method` values**: `"totp"`, `"webauthn"`, `"sms"`, `"backup_code"`.
  - **Response (200 OK)**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1Ni...",
  "refresh_token": "ref_9a8b7c6d5e...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "usr_1a2b3c",
    "email": "user@example.com",
    "email_verified": false
  },
  "policy_warning": {
    "requires_email_verification": true
  }
}
```
- **Edge Cases & Error Codes**:
  - `400 Bad Request` (`invalid_code`): Code is expired or invalid.
  - `401 Unauthorized` (`mfa_token_expired`): 2FA login challenge token expired (5-minute TTL).
  - `403 Forbidden` (`password_confirmation_failed`): Incorrect password provided when disabling 2FA methods.

### 3.9 Outgoing Real-Time Event Webhooks (`/v1/admin/webhooks/*`)
- **Description**: Managing real-time outgoing HTTP webhook endpoints, secret rotation, delivery audit logs, and manual pings.
- **Request (`POST /v1/admin/webhooks/endpoints`)**:
```json
{
  "url": "https://webhook.site/test-handler",
  "description": "Production Events Webhook",
  "events": ["user.created", "session.revoked"]
}
```
- **Response (201 Created)**:
```json
{
  "id": "whe_cfde8b85-4b0",
  "url": "https://webhook.site/test-handler",
  "description": "Production Events Webhook",
  "secret": "whsec_f3578988dbffcec07b802a6f4c46de11206339ff7a4e0bac",
  "subscribed_events": ["user.created", "session.revoked"],
  "is_active": true,
  "failure_count": 0,
  "created_at": "2026-08-05T07:03:06+05:00"
}
```
- **Edge Cases & Error Codes**:
  - `422 Unprocessable Entity`: Invalid URL format (must be HTTPS or localhost in dev mode) or empty/invalid event types.
  - `404 Not Found`: Webhook Endpoint ID does not exist or belongs to another tenant.

### 3.10 Admin User Impersonation & Security Guard (`/v1/admin/users/:user_id/impersonate`, `/v1/client/auth/impersonate/exit`)
- **Description**: Initiating short-lived admin impersonation sessions with mandatory Sudo step-up auth, user notification emails, signed webhooks (`user.impersonated`), and read-only mutation guards.
- **Request (`POST /v1/admin/users/:user_id/impersonate`)**:
```json
{
  "reason": "Investigating customer invoice display issue #8841",
  "duration_minutes": 15,
  "verification_method": "password",
  "admin_password": "AdminSecret123!"
}
```
- **Response (200 OK)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "impersonated_user": {
    "id": "usr_target123",
    "email": "customer@example.com",
    "name": "Customer Name",
    "status": "active",
    "email_verified": true
  },
  "impersonator_id": "usr_admin99",
  "session_id": "ses_imp_178593849102"
}
```
- **Request (`POST /v1/client/auth/impersonate/exit`)**:
  - Header: `Authorization: Bearer {{impersonationToken}}`
- **Response (200 OK)**:
```json
{
  "message": "impersonation session exited successfully",
  "impersonated_id": "usr_target123",
  "impersonator_id": "usr_admin99"
}
```
- **Edge Cases & Error Codes**:
  - `400 Bad Request` (`admin_step_up_required`): Step-up authentication method (password/2FA) was omitted or required by tenant policy.
  - `401 Unauthorized` (`invalid_admin_password` / `invalid_admin_2fa_code`): Incorrect step-up credential provided.
  - `403 Forbidden` (`impersonation_hierarchy_violation`): Admin attempting to impersonate another administrative user (`tenant_admin`, `admin`, `super_admin`).
  - `403 Forbidden` (`user_opt_in_required`): Target user has not granted support access opt-in permission.
  - `403 Forbidden` (`insufficient_permissions`): Admin lacks `users:impersonate` RBAC permission.
  - `403 Forbidden` (`impersonation_read_only_restricted`): Impersonation session attempting destructive mutation on `/v1/client/user/password`, `/v1/client/2fa`, or `/v1/client/account`.
