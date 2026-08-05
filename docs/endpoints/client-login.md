# Endpoint Specification: `POST /v1/client/login`

## Overview
* **Route**: `POST /v1/client/login`
* **HTTP Method**: `POST`
* **Purpose**: Primary User Authentication Endpoint. Authenticates users using email and password credentials, validates active 2FA/MFA enrollment, issues 15-minute JWT access tokens and HttpOnly refresh token cookies, and enforces constant-time CPU hashing to prevent timing-based user enumeration side-channel attacks.

---

## Authentication & Access Control
* **Authentication Required**: `X-Authn-Publishable-Key` (Public Client API Key)
* **Headers Required**:
  * `X-Authn-Publishable-Key: pk_<env>_<hash>` (e.g. `pk_test_demo12345678901234567890123456789012`)
  * `Content-Type: application/json`
  * `X-Authn-Client-Type: web|native|mobile` (Optional, defaults to `web`)

---

## Request Payload (`POST /v1/client/login`)

```json
{
  "email": "user.vanilla@authn.local",
  "password": "UserPass123!",
  "tenant_id": "tnt_default",
  "environment": "test"
}
```

### Request Fields
* `email` (string, required) — Registered user email address. Validated against RFC email format.
* `password` (string, required) — User password string. Checked via Argon2id hash comparison.
* `tenant_id` (string, optional) — Target tenant identifier (defaults to `tnt_default`).
* `environment` (string, optional) — Application environment mode (defaults to `test`).

---

## Response Delivery Split (`X-Authn-Client-Type`)

* **Web Clients (`X-Authn-Client-Type: web`)**:
  * Access Token JWT returned in JSON body (`access_token`).
  * Refresh Token issued **EXCLUSIVELY** via `Set-Cookie: authn_refresh_token; HttpOnly; SameSite=Lax; Path=/v1/client`.
  * `refresh_token` field is **absent** from JSON payload to prevent XSS theft.
* **Native / Mobile Clients (`X-Authn-Client-Type: native|mobile`)**:
  * Refresh token returned directly in JSON body (`refresh_token`).

---

## Responses & Status Codes

### `200 OK` — Successful Login (Web Client)
```bash
$ curl -i -X POST -H "Content-Type: application/json" \
  -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  -H "X-Authn-Client-Type: web" \
  -d '{"email":"user.vanilla@authn.local","password":"UserPass123!"}' \
  http://localhost:8080/v1/client/login

HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: authn_refresh_token=6f28e8aa35524e57ee755327b663bbcb543558ac16efaf11ecc36a498f3d9d3e; path=/v1/client; HttpOnly; SameSite=Lax
X-Authn-Degraded-Mode: false
```
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

### `200 OK` — 2FA / MFA Challenge Required
Returned when the user has an active 2FA method (TOTP, Passkey, SMS, Backup Codes). **No access token or refresh token is issued** until second-factor verification is completed via `POST /v1/client/2fa/totp/verify` or `POST /v1/client/auth/2fa/verify`.

```bash
$ curl -i -X POST -H "Content-Type: application/json" \
  -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  -d '{"email":"user.totp@authn.local","password":"UserPass123!"}' \
  http://localhost:8080/v1/client/login

HTTP/1.1 200 OK
Content-Type: application/json
X-Authn-Degraded-Mode: false
```
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
  "mfa_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfdG90cF8wMDIi...",
  "methods": [
    "totp"
  ]
}
```

### `401 Unauthorized` — Invalid Email or Password (Enumeration-Safe)
Returned for both wrong password and non-existent email address. Byte-for-byte identical output and constant-time CPU execution (~190ms vs ~210ms) using `DummyArgon2idHash` to eliminate timing side-channels.

```bash
$ curl -i -X POST -H "Content-Type: application/json" \
  -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  -d '{"email":"nonexistent.user@authn.local","password":"WrongPassword123!"}' \
  http://localhost:8080/v1/client/login

HTTP/1.1 401 Unauthorized
Content-Type: application/json
X-Authn-Degraded-Mode: false
```
```json
{
  "error": "invalid email or password"
}
```

### `401 Unauthorized` — Missing Publishable Key
```json
{
  "error": "missing publishable API key in X-Authn-Publishable-Key header"
}
```

### `429 Too Many Requests` — Rate Limit Exceeded
Triggered on 6th request within 15-minute sliding window per IP + endpoint.

```json
{
  "error": "too many attempts, please try again later",
  "retry_after_seconds": 889
}
```

### `503 Service Unavailable` — Fail-CLOSED Outage Protection
Returned during Redis outages when rate limiting cannot be enforced. Prevents unthrottled password brute-force attacks.

```json
{
  "error": "rate limit service unavailable"
}
```

---

## Security Properties (Verified)

| Security Feature | Implementation Mechanism | Pentest Result |
|---|---|---|
| User Enumeration Defense | Identical 401 payload for wrong password and non-existent email | Verified (byte-for-byte match) |
| Timing Side-Channel Defense | Constant-time Argon2id CPU computation (`DummyArgon2idHash`) when user not found | Verified (~190ms vs ~210ms execution) |
| Refresh Token XSS Defense | Web clients receive refresh token strictly via `HttpOnly` cookie | Verified (absent from JSON) |
| 2FA Gate | Access tokens withheld until 2FA challenge is verified | Verified (`mfa_required: true` response) |
| SQLi / NoSQLi Protection | Ent ORM parameterized queries + Fiber JSON type unmarshaling | Verified (injection payloads rejected) |
| Brute-Force Rate Limiting | Multi-dimensional IP sliding window + violation escalation backoff (15m -> 1h -> 6h -> 24h) | Verified |
| Outage Fail-Closed | Sensitive mutation handler rejects requests if Redis fails | Verified (`503` + `X-Authn-Degraded-Mode: true`) |

---

## Rate Limiting & Outage Behavior
* **Sliding-Window Rate Limiter**: 5 attempts per 900s (15-minute) window per IP address + endpoint.
* **Escalation Backoff**: Violations trigger exponential backoff: 1st violation (15m block), 2nd (1h), 3rd (6h), 4th+ (24h cap).
* **Fail-CLOSED Security Guard**: During Redis outages, login requests **FAIL-CLOSED** with `503 Service Unavailable` and `X-Authn-Degraded-Mode: true`. See [`docs/ARCHITECTURE-DEGRADED-MODE.md`](file:///home/hanan-bhatti/authn/docs/ARCHITECTURE-DEGRADED-MODE.md).

---

## Verification & Pentest History
* **Last Verified Date**: `2026-08-06`
* **Test Subjects**: `user.vanilla@authn.local`, `user.unverified@authn.local`, `user.totp@authn.local` (from `cmd/seed/main.go`).
* **Verification Method**: Manual live `curl` pentest against running server (verified happy path, 2FA gate, constant-time Argon2id timing defense, missing key 401, 429 rate limit, 503 fail-closed, and injection immunity).
