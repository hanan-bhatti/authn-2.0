# API Specification (Client & Admin REST/OIDC)

**Document Version**: 2.0.0  
**Date**: 2026-08-04  
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

### 2.1 OIDC Discovery & JWKS
- `GET /.well-known/openid-configuration` — OIDC Discovery Metadata
- `GET /v1/oauth/jwks` — Public RSA JWKS key set

### 2.2 OAuth 2.0 / OIDC Flow
- `GET /v1/oauth/authorize` — PKCE Authorization Code endpoint
- `POST /v1/oauth/token` — Token exchange (`authorization_code`, `refresh_token`)

### 2.3 Core Client Authentication
- `POST /v1/client/signup` — User registration with email/password
- `POST /v1/client/login` — User authentication with Argon2id check
- `GET /v1/client/verify-email` — Single-use email verification link
- `POST /v1/client/resend-verification` — Resend email verification link

### 2.4 Passwordless Magic Links
- `POST /v1/client/auth/magic-link` — Request single-use 15-min login link
- `GET /v1/client/auth/magic-link/verify` — Verify magic link token via GET link
- `POST /v1/client/auth/magic-link/verify` — Verify magic link token via POST API

### 2.5 2FA - TOTP Authenticator
- `POST /v1/client/2fa/totp/enroll` — Generate TOTP QR code & secret
- `POST /v1/client/2fa/totp/confirm` — Confirm TOTP setup with initial code
- `POST /v1/client/2fa/totp/verify` (or `POST /v1/client/auth/2fa/verify`) — Validate TOTP challenge code
- `POST /v1/client/2fa/totp/disable` — Disable TOTP with step-up verification

### 2.6 2FA - SMS OTP
- `POST /v1/client/2fa/sms/enroll` — Register phone number for SMS 2FA
- `POST /v1/client/2fa/sms/confirm` — Confirm phone number with initial SMS code
- `DELETE /v1/client/2fa/sms/disable` — Disable SMS 2FA with step-up check

### 2.7 2FA - Backup Recovery Codes
- `POST /v1/client/2fa/recovery-codes/regenerate` — Generate 8 fresh backup recovery codes
- `GET /v1/client/2fa/recovery-codes/status` — Get remaining recovery codes count

### 2.8 2FA - WebAuthn / Passkeys (FIDO2)
- `POST /v1/client/2fa/webauthn/register/begin` — Initiate WebAuthn passkey registration
- `POST /v1/client/2fa/webauthn/register/finish` — Complete WebAuthn passkey registration
- `POST /v1/client/2fa/webauthn/login/begin` — Initiate WebAuthn passkey authentication
- `POST /v1/client/2fa/webauthn/login/finish` — Complete WebAuthn passkey authentication
- `GET /v1/client/2fa/webauthn/passkeys` — List user's registered passkeys
- `DELETE /v1/client/2fa/webauthn/passkeys/:id` — Delete registered passkey (preserves last 2FA method)

### 2.9 Smart Account Recovery & Guardians (FR-5)
- `POST /v1/client/account/guardians/invite` — Pre-enroll 1-5 guardians & issue zero-knowledge tokens
- `POST /v1/client/account/guardians/accept` — Accept guardian invitation
- `GET /v1/client/account/guardians` — List active guardians
- `DELETE /v1/client/account/guardians/:id` — Revoke guardian & trigger Re-Key/Re-Split
- `POST /v1/client/auth/recovery/initiate` — Initiate recovery & resolve dynamic methods
- `POST /v1/client/auth/recovery/proof/guardian` — Submit Shamir share proof ($k$-of-$N$)
- `POST /v1/client/auth/recovery/proof/old-password` — Submit old password proof
- `POST /v1/client/auth/recovery/proof/security-questions` — Submit security questions proof
- `POST /v1/client/auth/recovery/claim` — Execute final password reset & 2FA wipe with 15-min claim token
- `POST /v1/client/auth/recovery/cancel` — Cancel recovery via active authenticated session
- `POST /v1/client/auth/recovery/cancel/token` — Cancel recovery via public signed link token

### 2.11 Social Identity Providers (FR-7)
- `GET /v1/tenant/social-providers` — List all supported social providers, setup guides & status
- `GET /v1/tenant/social-providers/:provider` — Get setup guide & configuration for specific provider
- `PUT /v1/tenant/social-providers/:provider` — Configure provider client ID & encrypted secret with format validation
- `DELETE /v1/tenant/social-providers/:provider` — Remove provider configuration
### 2.12 Session Management & Revocation (FR-8)
- `POST /v1/client/auth/refresh` — Rotate refresh token with 10s grace window & issue new JWT access token
- `GET /v1/client/sessions` — List active sessions for authenticated user with device parsing & `is_current` flag
- `POST /v1/client/sessions/revoke` — Revoke a specific session by ID
- `POST /v1/client/sessions/revoke-others` — Revoke all active user sessions except current
- `POST /v1/client/sessions/revoke-all` — Revoke all active user sessions
- `GET /v1/admin/users/:user_id/sessions` — Admin list user sessions
- `POST /v1/admin/users/:user_id/sessions/revoke-all` — Admin kill-switch to revoke all sessions for a user

---

## 3. Endpoints & Edge Cases Detail

### 3.1 `POST /v1/client/auth/recovery/initiate`
- **Description**: Initiates account recovery and resolves identity-proof methods in priority order based on tenant `RecoveryPolicy`.
- **Request**:
```json
{
  "tenant_id": "tnt_demo",
  "environment": "test",
  "email": "user@example.com"
}
```
- **Response (200 OK)**:
```json
{
  "recovery_request_id": "req_8a9b0c1d2e",
  "status": "initiated",
  "is_trusted_device_origin": true,
  "available_methods": ["guardians", "email_otp", "old_password"],
  "cancellation_token": "a1b2c3d4e5f6..."
}
```
- **Edge Cases & Error Codes**:
  - `400 Bad Request` (`no_recovery_methods_available`): No methods configured or available for account. Directs to support.
  - `403 Forbidden` (`ErrOriginBlacklisted`): Request origin (IP, subnet, or device fingerprint) is on the 7-day security blacklist following a recent cancellation.
  - Non-existent user: Timing-safe dummy Argon2id calculation executed; returns generic `email_otp` response to prevent enumeration.

### 3.2 `POST /v1/client/auth/recovery/cancel` & `POST /v1/client/auth/recovery/cancel/token`
- **Authenticated Cancel Request (`/cancel`)**: Requires active session (`userID`, `sessionID`).
```json
{
  "recovery_request_id": "req_8a9b0c1d2e"
}
```
- **Signed Link Cancel Request (`/cancel/token`)**: Public unauthenticated endpoint.
```json
{
  "cancellation_token": "a1b2c3d4e5f6..."
}
```
- **Response (200 OK)**:
```json
{
  "status": "cancelled",
  "message": "Recovery request successfully cancelled. Originating request details blacklisted for 7 days. Account flagged for security review."
}
```
- **Actions Triggered**:
  1. Recovery request status $\to$ `CANCELLED`.
  2. 7-day blacklist record created for initiating IP, subnet, and client fingerprint.
  3. `User.SecurityReviewRequired` set to `true`.
  4. Active user sessions revoked (excluding current session for `/cancel`).

### 3.3 `PUT /v1/tenant/recovery-policy`
- **Description**: Updates tenant-wide account recovery policy.
- **Request**:
```json
{
  "guardians_enabled": true,
  "phone_otp_enabled": true,
  "email_otp_enabled": true,
  "old_password_enabled": true,
  "security_questions_enabled": true,
  "freeze_window_hours": 48,
  "claim_token_ttl_minutes": 15,
  "lockout_schedule": ["24h", "3d", "7d", "14d", "4w", "8w", "12w", "permanent"],
  "lockout_reset_days": 30,
  "trusted_device_window_days": 90,
  "ipv4_subnet_bits": 24,
  "ipv6_subnet_bits": 48,
  "max_proof_attempts_per_window": 5,
  "min_guardians": 1,
  "max_guardians": 5
}
```
- **Response (200 OK)**: Returns updated `RecoveryPolicy` JSON object.
- **Edge Cases & Error Codes**:
  - `400 Bad Request`: Fails if any of the 9 validation rules are violated (e.g. `freeze_window_hours` out of 24-168 bounds, non-monotonic lockout schedule, all method toggles set to false).

### 3.4 `GET /v1/tenant/social-providers` & `GET /v1/tenant/social-providers/:provider`
- **Description**: List configured and supported social identity providers with dynamic setup instructions (derived from `APP_BASE_URL` runtime configuration) and credentials format validation rules. Secrets are never exposed in API responses.
- **Headers**: `Authorization: Bearer sk_<env>_<hash>`
- **Response (200 OK)**:
```json
{
  "providers": [
    {
      "provider": "google",
      "enabled": true,
      "client_id": "123456789012-abc.apps.googleusercontent.com",
      "configured": true,
      "setup": {
        "callback_url": "http://localhost:8080/v1/client/auth/social/google/callback",
        "step_by_step": [
          "Go to console.cloud.google.com → APIs & Services → Credentials",
          "Click 'Create Credentials' → OAuth 2.0 Client ID",
          "Set Application type to 'Web application'",
          "Under 'Authorized redirect URIs' add: http://localhost:8080/v1/client/auth/social/google/callback",
          "Copy the Client ID and Client Secret into Authn"
        ],
        "console_url": "https://console.cloud.google.com/apis/credentials",
        "client_id_format": "must end with .apps.googleusercontent.com",
        "client_secret_format": "starts with GOCSPX- (newer apps) or alphanumeric"
      }
    }
  ]
}
```

### 3.5 `PUT /v1/tenant/social-providers/:provider`
- **Description**: Configures OAuth2/OIDC credentials for a social provider. Validates credentials format per provider rules and encrypts `client_secret` at rest with AES-256-GCM.
- **Headers**: `Authorization: Bearer sk_<env>_<hash>`
- **Request**:
```json
{
  "enabled": true,
  "client_id": "123456789012-abc.apps.googleusercontent.com",
  "client_secret": "GOCSPX-validsecret123"
}
```
- **Response (200 OK)**:
```json
{
  "message": "provider configured successfully",
  "provider": "google"
}
```
- **Edge Cases & Error Codes**:
  - `422 Unprocessable Entity`: Validation failure for provider format rules (e.g. Google client ID not ending with `.apps.googleusercontent.com`, Discord client ID not numeric, Microsoft client ID not UUID v4).

### 3.6 `GET /v1/client/auth/social/:provider/authorize`
- **Description**: Initiates social auth flow. Generates a 32-byte random hex CSRF state token stored with 10-minute TTL, then redirects (302 Found) to provider's OAuth authorization URL.
- **Headers**: `X-Authn-Publishable-Key: pk_<env>_<hash>`
- **Query Params**:
  - `redirect_uri` (required): Application's post-login redirect callback URL.
  - `post_callback_redirect` (optional): Deep link URL for mobile/web app post-login destination.
- **Response (302 Found)**: Redirects browser to provider's authorization page (e.g. `https://accounts.google.com/o/oauth2/v2/auth?...&state=...`).
- **Edge Cases**:
  - `400 Bad Request`: Provider not configured or missing `redirect_uri`.

### 3.8 `POST /v1/client/auth/refresh`
- **Description**: Exchanges a valid opaque refresh token for a new 15-minute Access Token JWT and a new 64-byte Refresh Token. Implements Refresh Token Rotation (RTR) with a 10-second grace window (`rotated_grace`) for handling concurrent parallel requests, and automatic compromise mitigation (revoking all sessions) if token reuse occurs after the 10-second grace window.
- **Headers**: `X-Authn-Publishable-Key: pk_<env>_<hash>`
- **Request**:
```json
{
  "refresh_token": "91c6044c-b80b-4897-9147-4a9a082c311c..."
}
```
*(Also reads `authn_refresh_token` HTTP-only cookie if body field is omitted)*
- **Response (200 OK)**:
```json
{
  "access_token": "eyJhbGciOi...",
  "refresh_token": "a1b2c3d4-...",
  "token_type": "Bearer",
  "expires_in": 900,
  "session_id": "ses_67f048b7"
}
```
- **Edge Cases & Error Codes**:
  - `401 Unauthorized` (`session_expired`): Session reached absolute TTL or idle timeout.
  - `401 Unauthorized` (`session_revoked`): Session was explicitly revoked.
  - `401 Unauthorized` (`session_compromised`): Token reuse detected outside 10s grace window. Triggers immediate revocation of all user sessions.

### 3.9 `GET /v1/client/sessions`
- **Description**: Returns all active non-expired sessions for the authenticated user with User-Agent device parsing (`browser`, `os`, `device`, `label`) and `is_current` boolean flag.
- **Headers**: `X-Authn-Publishable-Key: pk_<env>_<hash>`, `Authorization: Bearer <jwt>`
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

### 3.10 `POST /v1/client/sessions/revoke`, `/revoke-others`, `/revoke-all`
- **Description**: Allows authenticated users to manage their active login sessions.
  - `/revoke`: Revokes a specific session by ID (`{"session_id": "ses_..."}`).
  - `/revoke-others`: Revokes all active sessions for the user except current.
  - `/revoke-all`: Revokes all active sessions for the user (logs out all devices).
- **Headers**: `Authorization: Bearer <jwt>`
- **Response (200 OK)**:
```json
{
  "message": "all other sessions revoked",
  "count": 3
}
```

### 3.11 `GET /v1/admin/users/:user_id/sessions` & `POST /v1/admin/users/:user_id/sessions/revoke-all`
- **Description**: Administrative endpoints for security teams to inspect active user sessions or trigger an emergency kill-switch to revoke all sessions for a compromised account.
- **Headers**: `Authorization: Bearer sk_<env>_<hash>`
- **Response (200 OK)**:
```json
{
  "message": "all sessions revoked for user",
  "user_id": "usr_4d5a1533-735",
  "count": 4
}
```


