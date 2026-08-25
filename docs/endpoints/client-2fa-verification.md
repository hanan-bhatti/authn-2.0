# Endpoint Specification: 2FA Verification & SMS/Passkey Challenge Routes

## Overview

These seven routes are registered in `internal/auth/handler.go` but were absent from
`docs/endpoints/` (audit finding D1). They cover the **verification** half of the 2FA
system — the enrollment half is documented in
[`mfa-enrollment-verification.md`](./mfa-enrollment-verification.md).

* **Routes**:
  * `POST /v1/client/auth/2fa/totp/verify` — Verify a TOTP/recovery code, completing login
  * `POST /v1/client/auth/2fa/verify` — Alias of the above, identical handler
  * `POST /v1/client/auth/2fa/sms/challenge` — Send the SMS code for a sign-in awaiting a second factor
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
| `POST /2fa/sms/challenge` | The `mfa_token` from `/login` |
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
  "methods": ["totp", "passkey", "sms", "backup_code"]
}
```

A `200` here does **not** mean the user is signed in. Integrators must branch on
`mfa_required` before assuming `access_token` is present. `methods` lists the factors
this user actually has enrolled — use it to decide which verification route to call.

The order is the presentation order: primary factors come **most recently used first**,
so `methods[0]` is what to show and the rest belong behind "try another way". Never-used
factors fall back to the fixed order `totp`, `passkey`, `sms`. `backup_code` is always
last, so a client walking the list never opens on a finite single-use code. The full rule
is in [`client-login.md`](./client-login.md).

`methods` is sealed into the signed `mfa_token`, so it is also the *limit* of what the
verify routes accept for this challenge — see the `method` field below.

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
| `code` | yes | 6-digit TOTP code, SMS OTP, or a recovery code |
| `mfa_token` | no | Present in the login flow. Omit when verifying with a bearer token. |
| `method` | conditional | One of `totp`, `sms`, `backup_code`. Required whenever the challenge offers more than one factor; may be omitted only when exactly one is offered. |

### `method` — how the factor is selected

The server never tries the code against each factor in turn: that would test one submitted
value against every enrolled method. So `method` names the single factor to check.

* **Omitted with several factors offered** → `400 missing_parameter`, "multiple 2FA methods
  are active; specify which one this code belongs to". Send the factor the user picked.
* **Omitted with exactly one factor offered** → that factor is used.
* **Outside the challenge's `methods`** → `400 validation_failed`, "that 2FA method is not
  available for this account". Refused *before* the code is checked, so a code is never
  tested against a factor the challenge did not offer. During a login challenge the set is
  the one sealed into the `mfa_token` at password time; on the bearer path it is resolved
  from the account's live enrollment.
* **`method: "passkey"`** → `400 validation_failed` naming
  `POST /v1/client/auth/2fa/webauthn/login/begin`. Passkeys appear in `methods` because the
  account can satisfy the challenge with one, but there is no code to submit — a passkey is
  proven by signing an assertion. See §5 and §6 below.

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
| `400` | `missing_parameter` | `code` absent or blank, or `method` omitted with several factors offered |
| `400` | `validation_failed` | Invalid `client_type`; `method` outside the challenge's set; `method: "passkey"` |
| `400` | `invalid_mfa_code` | Wrong or expired code, expired `mfa_token`, or a recovery code already spent |
| `401` | `session_expired` | Bearer-token path only: the `Authorization` access token is invalid or expired |
| `403` | `account_disabled` | The account was suspended or deleted between the password and the code |
| `503` | `service_unavailable` | The account's second factors could not be read, so the challenge cannot be resolved. Retryable; not a code failure. |

The `503` reaches this route the same way it reaches `/login`: rather than guessing at an
unreadable factor set, verification is refused. Present it as a retryable fault, not as a
wrong code — the user's code may well have been correct.

---

## 2. Send the SMS code for a login challenge (`POST /v1/client/auth/2fa/sms/challenge`)

Delivers a fresh code to the phone on file for the account behind an `mfa_token`, so a sign-in that
listed `sms` among its `methods` can actually satisfy it.

Public for the same reason `/2fa/verify` is: the caller holds a challenge token and has no session
yet. Do not confuse it with `POST /2fa/sms/enroll`, which adds a *new* number and needs a bearer
token. Verification loads the code from server memory, and a code exists only once it has been
sent — so on the login path this route is what creates one.

**Request**
```json
{ "mfa_token": "eyJhbGciOiJIUzI1NiIs..." }
```

| Field | Required | Notes |
|---|---|---|
| `mfa_token` | yes | The challenge token from `/login`. Its sealed `methods` must include `sms`. |

**Response (200 OK)**
```json
{
  "message": "Verification code sent via SMS",
  "phone_number": "+12•••99",
  "expires_in_seconds": 300
}
```

`phone_number` is redacted to its country prefix and last two digits — enough to say which handset
to check, without printing the number to a caller who has proven only the password.
`expires_in_seconds` follows `MFA_CHALLENGE_TTL`; read it rather than hardcoding 300.

Submit the delivered code to §1 with `method: "sms"`.

**Errors**

| Status | `code` | Cause |
|---|---|---|
| `400` | `missing_parameter` | `mfa_token` absent or blank |
| `400` | `validation_failed` | The challenge does not offer `sms` |
| `400` | `not_found` | No confirmed phone number is on file for this account |
| `401` | `invalid_token` | `mfa_token` is malformed, expired, tampered with, or names an unknown user |
| `403` | `account_disabled` | The account was suspended between the password and this send |
| `429` | `rate_limited` | 3 sends per 10 minutes per user |
| `503` | `service_unavailable` | The provider refused the message, or the stored number could not be read |

Three of those need care in a client:

* **`validation_failed`** — the gate is the challenge's own `methods`, not the account's current
  factors, matching §1. A number enrolled *during* the challenge window is not usable until the
  next sign-in, so send and verify can never disagree mid-login.
* **`not_found`** — only an **enabled** number is accepted as a destination. A number still pending
  confirmation is one an attacker could have submitted, and sending a login code there would hand
  them the second factor.
* **`503`** — there is deliberately **no email fallback here**, unlike SMS enrollment. The caller
  has proven the password and nothing else, so mailing the second factor to the account address
  would reduce two factors to one. Offer another entry from `methods` instead.

---

## 3. Confirm SMS enrollment (`POST /v1/client/auth/2fa/sms/confirm`)

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

## 4. Disable SMS 2FA (`DELETE /v1/client/auth/2fa/sms/disable`)

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

## 5. Passkey login begin (`POST /v1/client/auth/2fa/webauthn/login/begin`)

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

## 6. Passkey login finish (`POST /v1/client/auth/2fa/webauthn/login/finish`)

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

---

## Verification History

* **`2026-08-24`** — `POST /2fa/sms/challenge` verified live end to end against an SMS + recovery-code
  account. Before the route existed, `/2fa/verify` with `method:"sms"` answered `400 invalid_mfa_code`
  on every attempt, because a code is only written to memory by a send and the only sender was the
  session-protected `/2fa/sms/enroll` — so a challenge listing `sms` could never be satisfied. After:
  the send answered `200` with `phone_number:"+12•••99"` and `expires_in_seconds:300`, the delivered
  code answered `200` with a session, replaying that code answered `400 invalid_mfa_code`, a blank
  `mfa_token` answered `400 missing_parameter`, garbage and signature-tampered tokens answered
  `401 invalid_token`, a TOTP-only challenge answered `400 validation_failed`, the fourth send inside
  the window answered `429 rate_limited`, and reusing an older token after SMS was disabled answered
  `400 not_found`. Setting `MFA_CHALLENGE_TTL=7m` moved both this route and `/2fa/sms/enroll` to
  `expires_in_seconds:420`, confirming neither hardcodes 300.
* **`2026-08-22`** — `method` selection verified live against a TOTP + recovery-code account:
  `method:"sms"` (outside the challenge set) answered `400 validation_failed` without testing
  the code, `method:"backup_code"` with a wrong code answered `400 invalid_mfa_code`,
  `method:"passkey"` answered `400 validation_failed` naming the WebAuthn login route, and a
  real TOTP code answered `200` with a session.
