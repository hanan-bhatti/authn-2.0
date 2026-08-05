# Endpoint Specification: Passwordless Magic Links (`POST /v1/client/auth/magic-link` & `GET|POST /v1/client/auth/magic-link/verify`)

## Overview
* **Routes**:
  * `POST /v1/client/auth/magic-link` — Request a 15-minute single-use magic login link
  * `GET /v1/client/auth/magic-link/verify` — Verify magic link via browser redirect URL
  * `POST /v1/client/auth/magic-link/verify` — Verify magic link via JSON API payload
* **HTTP Methods**: `POST`, `GET`
* **Purpose**: Passwordless authentication flow. Generates cryptographically secure 32-byte random hex tokens, emails single-use magic links to users, auto-provisions new accounts if un-registered, marks email verified upon click, and neutralizes token replay attacks.

---

## Authentication & Access Control
* **Authentication Required**: `X-Authn-Publishable-Key` (Public Client API Key)
* **Headers Required**:
  * `X-Authn-Publishable-Key: pk_<env>_<hash>`
  * `Content-Type: application/json`

---

## Request Payloads

### 1. Send Magic Link (`POST /v1/client/auth/magic-link`)
```json
{
  "email": "user.vanilla@authn.local",
  "name": "Vanilla User"
}
```

### 2. Verify Magic Link (`POST /v1/client/auth/magic-link/verify`)
```json
{
  "token": "266f205526adbded53d5094095f4eb8b3da4969db13b1acc24be28e0088951f6"
}
```

---

## Responses & Status Codes

### `200 OK` — Magic Link Sent (`POST /v1/client/auth/magic-link`)
```json
{
  "message": "a magic login link has been sent to your email address"
}
```

### `200 OK` — Verification Success (`POST /v1/client/auth/magic-link/verify`)
```bash
$ curl -i -X POST -H "Content-Type: application/json" \
  -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  -d '{"token":"266f205526adbded53d5094095f4eb8b3da4969db13b1acc24be28e0088951f6"}' \
  http://localhost:8080/v1/client/auth/magic-link/verify

HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: authn_refresh_token=7863ce37ba9f...; Path=/; HttpOnly; SameSite=Lax
X-Authn-Degraded-Mode: false
```
```json
{
  "user": {
    "id": "usr_vanilla_007",
    "email": "user.vanilla@authn.local",
    "email_verified": true
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfdmFuaWxsYV8wMDciLCJzaWQiOiJzZXNfZmI5YjU0MDAtNWUxIiwiaWF0IjoxNzg1OTY1NzE3fQ..."
}
```

### `400 Bad Request` — Invalid Email Format
```json
{
  "error": "invalid email address format"
}
```

### `400 Bad Request` — Missing Token Parameter
```json
{
  "error": "token query parameter or body field is required"
}
```

### `400 Bad Request` — Invalid, Expired, or Replayed Token
```json
{
  "error": "invalid or expired magic link token"
}
```

---

## Pentest & Security Verification Log

| Test Case | Request | Observed Status | Defense Verification |
| :--- | :--- | :--- | :--- |
| **Unauthenticated Request** | `POST /auth/magic-link` (No PK) | `401 Unauthorized` | API key middleware validation |
| **Invalid Email** | `POST /auth/magic-link` (`email: "bad"`) | `400 Bad Request` | `invalid email address format` |
| **Send Magic Link** | `POST /auth/magic-link` (Valid Email) | `200 OK` | Rendered template sent via Mailpit (15m TTL) |
| **Auto-Provisioning** | Request for new email address | `200 OK` | New user created automatically |
| **Missing Token** | `POST /auth/magic-link/verify` (`{}`) | `400 Bad Request` | Required token check |
| **Garbage Token** | `POST /auth/magic-link/verify` (`fake`) | `400 Bad Request` | `invalid or expired magic link token` |
| **Valid Verification** | `POST /auth/magic-link/verify` (Real Token) | `200 OK` | Issues JWT with `sid`, sets HttpOnly cookie, marks email verified |
| **Replay Attack** | 2nd call with same magic link token | `400 Bad Request` | Single-use consumption cleared hash in DB |

*Last Verified*: `2026-08-06` — live `curl` & Mailpit API verification against running server.
