# MFA Enrollment & Verification Suite (`/v1/client/auth/2fa/*`)

> **Last Verified**: `2026-08-25` — 100% verified via live `curl` pentest suite against running server using `pyotp` for RFC 6238 TOTP validation. The TOTP teardown was re-checked end to end: disabling the last primary factor discards the account's recovery codes, `2fa.disabled` reports `remaining_factors: 0`, and the status endpoint then answers `has_recovery_codes: false`. `GET /v1/client/auth/2fa/methods` was verified across the full lifecycle — bare account, TOTP confirmed, SMS confirmed, TOTP used at a sign-in, SMS removed, last factor torn down — and its `methods` list matched the challenge's byte for byte at every step.

## Overview
The MFA Enrollment & Verification suite manages multi-factor authentication enrollment, TOTP setup, SMS OTP dispatch, WebAuthn passkey registration/revocation, single-use recovery code status tracking, and password step-up confirmation guards.

---

## Endpoint Specifications

### 1. Enroll TOTP Authenticator (`POST /v1/client/auth/2fa/totp/enroll`)
* **Headers**: `X-Authn-Publishable-Key: pk_test_...`, `Authorization: Bearer <sessionToken>`
* **Response (`200 OK`)**:
```json
{
  "secret": "MARS2VDXTC32GH3CI7OOOIFBM2PDNGID",
  "uri": "otpauth://totp/Authn%20Platform:user@example.com?algorithm=SHA1&digits=6&issuer=Authn%20Platform&period=30&secret=MARS2VDXTC32GH3CI7OOOIFBM2PDNGID"
}
```

### 2. Confirm TOTP Enrollment (`POST /v1/client/auth/2fa/totp/confirm`)
* **Request**:
```json
{
  "code": "828898"
}
```
* **Response (`200 OK`)**:
```json
{
  "message": "2FA TOTP successfully confirmed and activated",
  "recovery_codes": [
    "EPGK-7HAH", "3ZEX-CYTR", "3QG3-R2NR", "N6KL-JXYE",
    "R2WM-G4SS", "ULZ8-ZG3U", "XESG-CXC2", "X3UY-XXGD"
  ],
  "recovery_codes_created": true
}
```
* **Security Behavior**: Garbage or expired codes are rejected with `400 Bad Request` (`invalid 6-digit TOTP code`). Valid code activates TOTP and automatically provisions 16 single-use recovery codes.

### 3. Check Recovery Codes Status (`GET /v1/client/auth/2fa/recovery-codes/status`)
* **Headers**: `Authorization: Bearer <sessionToken>`
* **Response (`200 OK`)**:
```json
{
  "remaining_count": 16,
  "total_count": 16,
  "has_recovery_codes": true
}
```
* **Lifetime Note**: Recovery codes back a primary factor (TOTP, SMS, passkey) rather than standing as one. Removing the account's last primary factor discards them, and this endpoint then reports `has_recovery_codes: false`.

### 4. Regenerate Recovery Codes (`POST /v1/client/auth/2fa/recovery-codes/regenerate`)
* **Request**:
```json
{
  "password": "Password123!"
}
```
* **Response (`200 OK`)**:
```json
{
  "message": "recovery codes successfully regenerated",
  "recovery_codes": ["CJTQ-JYWE", "TGKW-CLJY", "CGRZ-ZSTT", "..."]
}
```
* **Security Guard**: Requires password step-up confirmation (`400 Bad Request` if password is omitted or invalid).

### 5. Disable TOTP Authenticator (`POST /v1/client/auth/2fa/totp/disable`)
* **Request**:
```json
{
  "password": "Password123!"
}
```
* **Response (`200 OK`)**:
```json
{
  "message": "2FA TOTP disabled. All active sessions have been revoked for security."
}
```
* **Security Guard**: Requires password step-up confirmation (`400 Bad Request` if password omitted). Disabling 2FA revokes all active user sessions to prevent session hijacking. When TOTP was the last primary factor, the account's recovery codes are discarded with it — codes left behind would still satisfy an authentication while securing nothing, and being finite and single-use they cannot gate an account on their own.

### 6. SMS 2FA Enrollment (`POST /v1/client/auth/2fa/sms/enroll`)
* **Request**:
```json
{
  "phone_number": "+15551234567"
}
```
* **Response (`200 OK`)**:
```json
{
  "expires_in_seconds": 300,
  "message": "OTP verification code sent via SMS"
}
```
* **Driver Note**: E2E tested via code path. When AWS SNS or Twilio credentials are not configured in `.env`, the engine falls back to the safe SMS Log Driver (`[SMS NO-OP DRIVER] To: +15551234567 | Message: ...`).

### 7. WebAuthn Register Begin (`POST /v1/client/auth/2fa/webauthn/register/begin`)
* **Response (`200 OK`)**:
```json
{
  "options": {
    "publicKey": {
      "rp": { "name": "Authn Platform", "id": "localhost" },
      "user": { "name": "user@example.com", "displayName": "User Name", "id": "dXNyX..." },
      "challenge": "IEkLDfsh_ZDRlZRaZh8Zi-vQWGq_fcLyV5TWli0GRzA",
      "timeout": 300000
    }
  },
  "session_id": "wasess_f28c12cb-52b"
}
```
* **Verification Note**: Once registered, the passkey counts as a primary factor and appears in the `methods` list `POST /v1/client/auth/login` returns. It is **not** verified with a code — sending `{"method":"passkey"}` to `/2fa/totp/verify` answers `400 validation_failed` naming `POST /v1/client/auth/2fa/webauthn/login/begin`, which is where a passkey challenge is signed. See [`client-2fa-verification.md`](./client-2fa-verification.md).

### 8. List WebAuthn Passkeys (`GET /v1/client/auth/2fa/webauthn/credentials`)
* **Response (`200 OK`)**: `{"credentials":[]}`

### 9. Revoke WebAuthn Passkey (`DELETE /v1/client/auth/2fa/webauthn/credentials/:id`)
* **Security Guard (IDOR Protection)**: Attempts to delete non-existent or foreign credentials return `400 Bad Request` (`passkey not found or does not belong to user`).

### 10. Read Enrolled Second Factors (`GET /v1/client/auth/2fa/methods`)
* **Headers**: `X-Authn-Publishable-Key: pk_test_...`, `Authorization: Bearer <accessToken>`
* **Purpose**: The read a security settings screen renders from. Every other factor could already be read — passkeys have a listing (§8), recovery codes have a status (§3) — while an authenticator app had nothing, so a client had no way to answer "is TOTP enrolled".
* **Response (`200 OK`)** — no factors enrolled:
```json
{
  "methods": [],
  "totp": { "enabled": false },
  "sms": { "enabled": false }
}
```
* **Response (`200 OK`)** — TOTP and SMS both enrolled, TOTP used at a sign-in:
```json
{
  "methods": ["totp", "sms", "backup_code"],
  "totp": {
    "enabled": true,
    "created_at": "2026-08-25T03:46:46Z",
    "last_used_at": "2026-08-25T03:54:17Z"
  },
  "sms": {
    "enabled": true,
    "created_at": "2026-08-25T03:47:16Z",
    "phone_number": "+447700900471"
  }
}
```
* **`methods` Contract**: The same list, from the same computation, that `POST /v1/client/auth/login` returns on a challenge — most recently used first, `backup_code` last. A settings screen can therefore state what the next sign-in will ask for rather than inferring it. `passkey` and `backup_code` appear in the list with no detail object of their own, because §8 and §3 carry that detail.
* **Field Notes**: `methods` is always an array, `[]` rather than `null`, when the account has no second factor. `created_at` and `last_used_at` are omitted rather than sent empty, and `last_used_at` is absent on a factor that has never satisfied a verification.
* **Phone Number Disclosure**: `sms.phone_number` is returned in full, unlike the masked form in the SMS challenge response. That one answers a caller holding an `mfa_token`, who has proven only the password; this route requires a session, and `GET /v1/client/user/profile` already returns the same number in full to the same caller. An SMS secret that fails to decrypt omits the number rather than failing the read — the factor is still enrolled and still answerable.
