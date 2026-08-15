# Feature 07: Passwordless Magic Links (FR-15)

**Module**: `apps/auth-engine/internal/auth`, `apps/auth-engine/internal/email`  
**Version**: 1.0.0  
**Status**: Implemented, Production-Ready & Verified  

---

## 1. Overview

The **Passwordless Magic Link Authentication Engine** enables frictionless sign-in and automatic account provisioning without requiring passwords (FR-15). It leverages the pluggable `EmailProvider` framework, HTML/Text email templates, 32-byte single-use SHA-256 token hashing, 15-minute token TTLs, and sliding-window rate limiting.

---

## 2. Key Architecture & Features

### 2.1 Auto-Signup / Frictionless Provisioning (Option A)
If a user requests a magic link for an email address that does not exist in the database, the Auth Engine automatically provisions a new user record (`usr_...`) with `email_verified = false` and sends the magic login link.

### 2.2 Implicit Email Verification & Single-Use Tokens
* **Security Storage**: The database stores only the **SHA-256 hash** (`magic_link_token`) and expiration (`magic_link_expires_at`). Raw tokens are never persisted.
* **Single-Use Replay Defense**: Validating the token immediately clears `magic_link_token` and `magic_link_expires_at` on the `User` entity, preventing replay attacks.
* **Implicit Verification**: Clicking a magic link automatically marks `email_verified = true` since accessing the email link proves inbox ownership.

---

## 3. Endpoints Reference

### 3.1 Request Magic Login Link
* **Endpoint**: `POST /v1/client/auth/magic-link`
* **Headers**: `X-Authn-Publishable-Key: pk_test_...`
* **Payload**:
```json
{
  "email": "user@example.com",
  "name": "Alex Smith",
  "tenant_id": "tnt_00000000000000000000000000000001",
  "environment": "test"
}
```
* **Response (200 OK)**:
```json
{
  "message": "a magic login link has been sent to your email address"
}
```

### 3.2 Verify Magic Link & Issue Session (Option A)
* **Endpoint**: `POST /v1/client/auth/magic-link/verify` or `GET /v1/client/auth/magic-link/verify?token=...`
* **Headers**: `X-Authn-Publishable-Key: pk_test_...`, `X-Authn-Client-Type: web` (or `native`/`mobile`)
* **Payload**:
```json
{
  "token": "1a05132219ac8b490616fd4963e660ab724dc09d2d1a5b8eeb68fc11ae0ba1a1"
}
```
* **Response (200 OK)**:
```json
{
  "user": {
    "id": "usr_d630ce0f-4fd",
    "email": "user@example.com",
    "email_verified": true,
    "name": "Alex Smith"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```
* **Cookie**: Sets `authn_refresh_token` (`HttpOnly`, `SameSite=Lax`, 30-day TTL) for `web` clients.

---

## 4. Replay Protection Behavior

Attempting to verify the same token a second time yields:
* **Response (400 Bad Request)**:
```json
{
  "error": "invalid or expired magic link token"
}
```
