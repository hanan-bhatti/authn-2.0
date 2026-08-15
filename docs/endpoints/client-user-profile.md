# Endpoint Specification: User Self-Service Profile & Account Settings (`/v1/client/user/*` & `/v1/oauth/userinfo`)

## Overview
* **Routes**:
  * `GET /v1/oauth/userinfo` — Standard OIDC UserInfo endpoint
  * `GET /v1/client/user/profile` — Fetch user profile & metadata
  * `PATCH /v1/client/user/profile` — Update display name, avatar, locale, and custom metadata
  * `POST /v1/client/user/password` — Change password with current password step-up re-authentication
  * `POST /v1/client/user/email` — Request primary email update (sends verification link)
  * `GET /v1/client/user/email/verify` — Verify primary email update callback
  * `GET /v1/client/user/recovery-email` — Get secondary recovery email status
  * `POST /v1/client/user/recovery-email` — Set secondary recovery email (sends verification link)
  * `GET /v1/client/user/recovery-email/verify` — Verify secondary recovery email callback
  * `DELETE /v1/client/user/recovery-email` — Delete secondary recovery email
  * `GET /v1/client/user/social-accounts` — List connected OAuth social identities
  * `DELETE /v1/client/user/social-accounts/:provider` — Unlink a social provider (enforces safety rule preventing unlinking the only login method)
  * `DELETE /v1/client/user/account` — Self-service GDPR account erasure (requires password step-up)
* **HTTP Methods**: `GET`, `PATCH`, `POST`, `DELETE`
* **Purpose**: Complete self-service user profile, password, recovery email, social account linking/unlinking, and account closure management.

---

## Authentication & Access Control
* **Protected Routes (`/v1/client/user/*`)**: Require `Authorization: Bearer <access_token>` (or `authn_access_token` cookie) AND `X-Authn-Publishable-Key: pk_<env>_<hash>`.
* **Public Callback Verification Routes (`/email/verify`, `/recovery-email/verify`)**: Require `X-Authn-Publishable-Key: pk_<env>_<hash>` and a valid single-use cryptographic token.

---

## Request & Response Examples

### 1. Standard OIDC UserInfo (`GET /v1/oauth/userinfo`)
```bash
$ curl -i -H "Authorization: Bearer <access_token>" http://localhost:8080/v1/oauth/userinfo
```
**Response (200 OK)**:
```json
{
  "sub": "usr_cae8e146-a3b",
  "email": "user@example.com",
  "email_verified": true,
  "name": "Alex Smith",
  "tenant_id": "tnt_00000000000000000000000000000001",
  "environment": "test",
  "updated_at": "2026-08-06T03:43:46Z"
}
```

### 2. Update Profile (`PATCH /v1/client/user/profile`)
```json
{
  "name": "Alex Smith",
  "avatar_url": "https://cdn.acme.local/avatars/user.png",
  "locale": "en-US",
  "metadata": {
    "theme": "dark",
    "notifications": true
  }
}
```
**Response (200 OK)**:
```json
{
  "id": "usr_cae8e146-a3b",
  "tenant_id": "tnt_00000000000000000000000000000001",
  "email": "user@example.com",
  "email_verified": true,
  "name": "Alex Smith",
  "avatar_url": "https://cdn.acme.local/avatars/user.png",
  "locale": "en-US",
  "metadata": {
    "notifications": true,
    "theme": "dark"
  },
  "created_at": "2026-08-06T03:43:46Z",
  "updated_at": "2026-08-06T03:43:46Z"
}
```

### 3. Set Secondary Recovery Email (`POST /v1/client/user/recovery-email`)
```json
{
  "recovery_email": "backup_user@example.com"
}
```
**Response (200 OK)**:
```json
{
  "message": "secondary recovery email verification link sent",
  "verification_token": "rec_013d370019a5850e33fc1ccaab48bacba9cb208950de9f76"
}
```

### 4. Verify Secondary Recovery Email (`GET /v1/client/user/recovery-email/verify?token=rec_...`)
**Response (200 OK)**:
```json
{
  "message": "secondary recovery email verified successfully"
}
```

---

## Security Audit & Verification Log

| Attack Vector / Test | Payload / Input | Response Status | Security Defense Execution |
| :--- | :--- | :--- | :--- |
| **Unauthenticated Request** | `GET /v1/client/user/profile` (No Bearer Token) | `401 Unauthorized` | Blocked by client auth middleware |
| **Password Change (Invalid Step-Up)** | `current_password: "WrongPassword"` | `401 Unauthorized` | Prevents unauthorized password resets |
| **Password Change (Weak Password)** | `new_password: "123"` | `400 Bad Request` | Enforces active tenant `PasswordPolicy` |
| **Primary Email Conflict** | `new_email: "existing_user@example.com"` | `409 Conflict` | Unique email constraint enforced per tenant |
| **Unlink Last Auth Method** | `DELETE /social-accounts/github` (No password set) | `403 Forbidden` | Prevents account lockouts |
| **GDPR Account Erasure** | `DELETE /v1/client/user/account` | `200 OK` | Cascading purge of sessions, memberships & identities |

*Last Verified*: `2026-08-06` — live `curl` attack suite against running server.
