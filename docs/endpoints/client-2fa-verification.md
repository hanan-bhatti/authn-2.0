# Endpoint Specification: 2FA Verification & SMS/Passkey Challenge Routes

## Overview

These seven routes are registered in `internal/auth/handler.go` but were absent from
`docs/endpoints/` (audit finding D1). They cover the **verification** half of the 2FA
system — the enrollment half is documented in
[`mfa-enrollment-verification.md`](./mfa-enrollment-verification.md).

* **Routes**:
  * `POST /v1/client/auth/2fa/totp/verify` — Verify a TOTP/recovery code, completing login
  * `POST /v1/client/auth/2fa/verify` — Alias of the above, identical handler
  * `POST /v1/client/auth/2fa/sms/confirm` — Confirm an SMS 2FA enrollment with the delivered code
  * `DELETE /v1/client/auth/2fa/sms/disable` — Remove SMS 2FA (password re-verification required)
  * `POST /v1/client/auth/2fa/webauthn/login/begin` — Start a passkey login challenge
  * `POST /v1/client/auth/2fa/webauthn/login/finish` — Complete a passkey login challenge
* **Auth**: Publishable key (`pk_...`) on every route, via `RequirePublishableKey`.

---

## Authentication context — read this first

These routes do **not** all authenticate the same way, which is the single most
common integration mistake (audit finding D3).

| Route | Caller identity comes from |
|---|---|
| `POST /2fa/totp/verify` (with `mfa_token`) | The `mfa_token` returned by `/login` — **not** a bearer token |
| `POST /2fa/totp/verify` (without `mfa_token`) | `Authorization: Bearer <access_token>` |
| `POST /2fa/sms/confirm` | `Authorization: Bearer <access_token>` |
| `DELETE /2fa/sms/disable` | `Authorization: Bearer <access_token>` + password in body |
| `POST /2fa/webauthn/login/begin` | The `mfa_token` from `/login` |
| `POST /2fa/webauthn/login/finish` | The `mfa_token` from `/login` |

The `mfa_token` is a short-lived MFA **challenge** token. It is not an access token and
cannot be used against any other endpoint.

---

## The login → 2FA handshake

When `POST /v1/client/auth/login` succeeds against an account with an active second factor,
it returns `200 OK` with **no session**:

```json
{
  "user": { "id": "usr_...", "email": "user@example.com" },
  "mfa_required": true,
  "mfa_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "methods": ["totp", "sms", "webauthn", "recovery_code"]
}
```

A `200` here does **not** mean the user is signed in. Integrators must branch on
`mfa_required` before assuming `access_token` is present. `methods` lists the factors
this user actually has enrolled — use it to decide which verification route to call.

---

## 1. Verify TOTP / recovery code (`POST /v1/client/auth/2fa/totp/verify`)

Also registered as `POST /v1/client/auth/2fa/verify` — same handler, same contract.
Both names exist for backwards compatibility; prefer the `/2fa/totp/verify` form.

**Request**
```json
{
  "code": "123456",
  "mfa_token": "eyJhbGciOiJIUzI1NiIs...",
  "method": "totp"
}
```

| Field | Required | Notes |
|---|---|---|
| `code` | yes | 6-digit TOTP code, or a recovery code |
| `mfa_token` | no | Present in the login flow. Omit when verifying with a bearer token. |
| `method` | no | `totp` (default), `sms`, or `recovery_code` |

**Response (200 OK)** — issues the real session:
```json
{
  "user": { "id": "usr_...", "email": "user@example.com" },
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "e3b0c44298fc1c149afbf4c8996fb924..."
}
```

**Errors**

| Status | `code` | Cause |
|---|---|---|
| `400` | `missing_parameter` | `code` absent or blank |
| `400` | `validation_failed` | Invalid `client_type` |
| `401` | `invalid_mfa_code` | Wrong or expired code |
| `401` | `session_expired` | `mfa_token` expired — restart at `/login` |

---

## 2. Confirm SMS enrollment (`POST /v1/client/auth/2fa/sms/confirm`)

Completes the enrollment started by `POST /v1/client/auth/2fa/sms/enroll`.

**Request**
```json
{ "code": "482910" }
```

**Response (200 OK)**
```json
{ "message": "SMS two-factor authentication enabled" }
```

---

## 3. Disable SMS 2FA (`DELETE /v1/client/auth/2fa/sms/disable`)

Note the method: `DELETE`, not `POST`. Requires password re-verification, and is
blocked during an active impersonation session.

**Request**
```json
{ "password": "SuperSecret123!" }
```

**Response (200 OK)**
```json
{ "message": "SMS two-factor authentication disabled" }
```

**Errors**

| Status | `code` | Cause |
|---|---|---|
| `401` | `invalid_credentials` | Password re-verification failed |
| `403` | `impersonation_read_only_restricted` | Blocked during impersonation |

---

## 4. Passkey login begin (`POST /v1/client/auth/2fa/webauthn/login/begin`)

**Request**
```json
{ "mfa_token": "eyJhbGciOiJIUzI1NiIs..." }
```

**Response (200 OK)** — a WebAuthn `PublicKeyCredentialRequestOptions` document plus
the `session_id` that ties the challenge together:
```json
{
  "publicKey": {
    "challenge": "base64url...",
    "rpId": "example.com",
    "allowCredentials": [{ "type": "public-key", "id": "base64url..." }],
    "userVerification": "preferred"
  },
  "session_id": "was_a1b2c3d4"
}
```

Pass `publicKey` to `navigator.credentials.get()` in the browser.

---

## 5. Passkey login finish (`POST /v1/client/auth/2fa/webauthn/login/finish`)

**This endpoint does not follow the usual body convention** (audit finding D4).
The `go-webauthn` library requires the raw credential assertion JSON as the *entire*
request body, so `mfa_token` and `session_id` are read from the **query string**:

```
POST /v1/client/auth/2fa/webauthn/login/finish?mfa_token=eyJ...&session_id=was_a1b2c3d4
Content-Type: application/json

{ "id": "...", "rawId": "...", "type": "public-key", "response": { ... } }
```

A body fallback exists for both parameters, but the query form is what the flow is
built around. The body must otherwise be the unmodified output of
`navigator.credentials.get()`.

**Response (200 OK)** — same session-issuing shape as TOTP verification:
```json
{
  "user": { "id": "usr_...", "email": "user@example.com" },
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "e3b0c44298fc1c149afbf4c8996fb924..."
}
```

---

## Error envelope

Every error on these routes returns the standard engine envelope:

```json
{ "error": "human readable message", "code": "machine_readable_code" }
```

Branch on `code`, never on `error` — the prose is subject to change.
