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

### 3.1 Core Authentication (`POST /v1/client/signup` & `POST /v1/client/login`)
- **Headers**: `X-Authn-Publishable-Key: pk_<env>_<hash>`, `X-Authn-Client-Type: native|web`
- **Request (`POST /v1/client/signup`)**:
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "name": "Alex Smith"
}
```
- **Response (200 OK or 201 Created)**:
```json
{
  "user": {
    "id": "usr_4d5a1533",
    "email": "user@example.com",
    "email_verified": false,
    "name": "Alex Smith",
    "status": "active"
  },
  "access_token": "eyJhbGciOi...",
  "refresh_token": "111d0dfc1a68..."
}
```
- **Edge Cases & Error Codes**:
  - `409 Conflict` (`email_exists`): Email already registered.
  - `400 Bad Request` (`password_policy_violation`): Password fails active tenant complexity rules.
  - `401 Unauthorized` (`invalid_credentials`): Incorrect email or password.

### 3.2 Refresh Token Rotation (`POST /v1/client/auth/refresh`)
- **Description**: Exchanges a valid opaque refresh token for a new 15-minute Access Token JWT and a new 64-byte Refresh Token. Implements Refresh Token Rotation (RTR) with a 10-second grace window (`rotated_grace`) for handling concurrent parallel requests, and automatic compromise mitigation (revoking all sessions) if token reuse occurs after the 10-second grace window.
- **Headers**: `X-Authn-Publishable-Key: pk_<env>_<hash>`
- **Request**:
```json
{
  "refresh_token": "91c6044c-b80b-4897-9147-4a9a082c311c..."
}
```
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

### 3.3 Session Management (`GET /v1/client/sessions` & `/v1/client/sessions/revoke*`)
- **Description**: Allows authenticated users to view active sessions with device details (`browser`, `os`, `device`, `label`) and `is_current` flag, or revoke sessions.
  - `/revoke`: Revokes a specific session by ID (`{"session_id": "ses_..."}`).
  - `/revoke-others`: Revokes all active sessions for the user except current.
  - `/revoke-all`: Revokes all active user sessions (logout all devices).
- **Headers**: `Authorization: Bearer <jwt>`
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

### 3.4 Social Identity Providers (`/v1/tenant/social-providers` & `/v1/client/auth/social/*`)
- **Description**: Configure social identity providers and handle OAuth2 authorization code flow.
- **Admin Config (`PUT /v1/tenant/social-providers/:provider`)**:
```json
{
  "enabled": true,
  "client_id": "123456789012-abc.apps.googleusercontent.com",
  "client_secret": "GOCSPX-validsecret123"
}
```
- **Authorize Redirect (`GET /v1/client/auth/social/:provider/authorize`)**:
  - Generates a 32-byte random hex CSRF state token stored with 10-minute TTL, then returns 302 redirect to provider's login page.
- **Callback Handler (`GET /v1/client/auth/social/:provider/callback`)**:
  - Consumes CSRF state token, exchanges code for provider tokens, retrieves user profile, handles Account Linking vs Signup vs Login, and issues JWT access token.
- **Edge Cases & Error Codes**:
  - `409 Conflict` (`email_exists_social_account`): Email exists as a password account. Prevents credential injection via signup. Directs user to login first then link provider.

### 3.5 Role-Based Access Control (`/v1/tenant/roles`, `/v1/admin/users/:id/roles`, `/v1/client/user/permissions`)
- **Description**: Creates custom RBAC roles, validates permission strings (`resource:action`), enforces policy guards, logs audit events, and returns user permissions.
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

### 3.6 Smart Account Recovery (`/v1/client/auth/recovery/*`)
- **Description**: Initiates account recovery and resolves identity-proof methods in priority order based on tenant `RecoveryPolicy`.
- **Request (`POST /v1/client/auth/recovery/initiate`)**:
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
- **Identity Proof Submissions**:
  - `POST /v1/client/auth/recovery/proof/phone-otp`: Submit SMS/WhatsApp OTP code (`{"recovery_request_id": "req_...", "phone_number": "+15551234567", "otp_code": "123456"}`). Returns `200 OK` (`{"status": "proof_verified", "message": "Phone OTP verified successfully"}`).
  - `POST /v1/client/auth/recovery/proof/email-otp`: Submit Email OTP code (`{"recovery_request_id": "req_...", "email": "user@example.com", "otp_code": "123456"}`). Returns `200 OK` (`{"status": "proof_verified", "message": "Email OTP verified successfully"}`).
  - `POST /v1/client/auth/recovery/proof/guardian`: Submit Shamir share string (`{"recovery_request_id": "req_...", "share_payload": "..."}`). Returns `{"threshold_reached": true, "status": "proof_verified"}`.
  - `POST /v1/client/auth/recovery/proof/old-password`: Submit old password (`{"recovery_request_id": "req_...", "password": "..."}`). Returns `{"status": "proof_verified"}`.
- **Edge Cases & Error Codes**:
  - `400 Bad Request` (`no_recovery_methods_available`): No methods configured or available for account. Directs to support.
  - `403 Forbidden` (`ErrOriginBlacklisted`): Request origin (IP, subnet, or device fingerprint) is on the 7-day security blacklist following a recent cancellation.

### 3.7 Admin API Keys (`POST /v1/admin/keys/`, `GET /v1/admin/keys/`, `POST /v1/admin/keys/:id/revoke`)
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
