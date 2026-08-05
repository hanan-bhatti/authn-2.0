# Endpoint Specification: `POST /v1/client/signup`

## Overview
* **Route**: `POST /v1/client/signup`
* **HTTP Method**: `POST`
* **Purpose**: User Registration Endpoint. Registers new user accounts with Argon2id password hashing, enforces tenant password complexity policies, issues initial JWT access tokens and HttpOnly refresh token cookies, and triggers email verification workflows.

---

## Authentication & Access Control
* **Authentication Required**: `X-Authn-Publishable-Key` (Public Client API Key)
* **Headers Required**:
  * `X-Authn-Publishable-Key: pk_<env>_<hash>` (e.g. `pk_test_demo12345678901234567890123456789012`)
  * `Content-Type: application/json`
  * `X-Authn-Client-Type: web|native|mobile` (Optional, defaults to `web`)

---

## Request Payload (`POST /v1/client/signup`)

```json
{
  "email": "fresh.signup@authn.local",
  "password": "ValidPass123!",
  "name": "Fresh User",
  "tenant_id": "tnt_default",
  "environment": "test"
}
```

### Request Fields
* `email` (string, required) — User email address. Must be a valid email format.
* `password` (string, required) — User password. Evaluated against active tenant password policies.
* `name` (string, optional) — Display name of user (max 255 characters).
* `tenant_id` (string, optional) — Target tenant identifier (defaults to `tnt_default`).
* `environment` (string, optional) — Application environment mode (defaults to `test`).

---

## Responses & Status Codes

### `201 Created` — Successful User Registration
Returned when user is successfully registered. For `web` client types, sets an `HttpOnly`, `SameSite=Lax` cookie `authn_refresh_token`.

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

### `400 Bad Request` — Password Policy Violation
Returned when password fails active tenant complexity rules.

```json
{
  "error": "password does not meet policy requirements",
  "missing_criteria": [
    "min_length"
  ]
}
```

### `401 Unauthorized` — Missing or Invalid Publishable Key
Returned when `X-Authn-Publishable-Key` header is missing or unrecognized.

```json
{
  "error": "missing publishable API key in X-Authn-Publishable-Key header"
}
```

### `409 Conflict` — User Email Already Registered
Returned when `email` is already registered in the target tenant.

```json
{
  "error": "user with this email already exists"
}
```

### `429 Too Many Requests` — Rate Limit Exceeded
Returned when request rate exceeds 5 attempts per 15-minute window per IP+endpoint sliding window.

```json
{
  "error": "too many attempts, please try again later",
  "retry_after_seconds": 889
}
```

### `503 Service Unavailable` — Fail-CLOSED Cache Outage Protection
Returned during Redis outages when rate limiting cannot be enforced. Prevents unthrottled registration attempts.

```json
{
  "error": "rate limit service unavailable"
}
```

---

## Rate Limiting & Outage Behavior
* **Sliding-Window Rate Limiter**: 5 attempts per 900s (15-minute) window per IP address + endpoint combination.
* **Fail-CLOSED Security Guard**: During Redis outages, this sensitive mutation endpoint **REJECTS** requests with `503 Service Unavailable` and `X-Authn-Degraded-Mode: true`. See [`docs/ARCHITECTURE-DEGRADED-MODE.md`](file:///home/hanan-bhatti/authn/docs/ARCHITECTURE-DEGRADED-MODE.md) for full outage architecture.

---

## Design Notes & Tradeoffs
* **User Enumeration Tradeoff**: Returning `409 Conflict` (`"user with this email already exists"`) is a deliberate design decision aligning with standard B2C/SaaS auth patterns (Firebase, Clerk, Auth0, Supabase) to enable seamless frontend signup UX.

---

## Verification & Pentest History
* **Last Verified Date**: `2026-08-06`
* **Verification Method**: Manual live `curl` pentest against running server (verified 201, 401, 409, 400, 429, and 503 raw responses).
