# MFA Enrollment & Verification Suite (`/v1/client/2fa/*`)

> **Last Verified**: `2026-08-06` — 100% verified via live `curl` pentest suite against running server using `pyotp` for RFC 6238 TOTP validation.

## Overview
The MFA Enrollment & Verification suite manages multi-factor authentication enrollment, TOTP setup, SMS OTP dispatch, WebAuthn passkey registration/revocation, single-use recovery code status tracking, and password step-up confirmation guards.

---

## Endpoint Specifications

### 1. Enroll TOTP Authenticator (`POST /v1/client/2fa/totp/enroll`)
* **Headers**: `X-Authn-Publishable-Key: pk_test_...`, `Authorization: Bearer <sessionToken>`
* **Response (`200 OK`)**:
```json
{
  "secret": "MARS2VDXTC32GH3CI7OOOIFBM2PDNGID",
  "uri": "otpauth://totp/Authn%20Platform:user@example.com?algorithm=SHA1&digits=6&issuer=Authn%20Platform&period=30&secret=MARS2VDXTC32GH3CI7OOOIFBM2PDNGID"
}
```

### 2. Confirm TOTP Enrollment (`POST /v1/client/2fa/totp/confirm`)
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

### 3. Check Recovery Codes Status (`GET /v1/client/2fa/recovery-codes/status`)
* **Headers**: `Authorization: Bearer <sessionToken>`
* **Response (`200 OK`)**:
```json
{
  "remaining_count": 16,
  "total_count": 16,
  "has_recovery_codes": true
}
```

### 4. Regenerate Recovery Codes (`POST /v1/client/2fa/recovery-codes/regenerate`)
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

### 5. Disable TOTP Authenticator (`POST /v1/client/2fa/totp/disable`)
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
* **Security Guard**: Requires password step-up confirmation (`400 Bad Request` if password omitted). Disabling 2FA revokes all active user sessions to prevent session hijacking.

### 6. SMS 2FA Enrollment (`POST /v1/client/2fa/sms/enroll`)
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

### 7. WebAuthn Register Begin (`POST /v1/client/2fa/webauthn/register/begin`)
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

### 8. List WebAuthn Passkeys (`GET /v1/client/2fa/webauthn/credentials`)
* **Response (`200 OK`)**: `{"credentials":[]}`

### 9. Revoke WebAuthn Passkey (`DELETE /v1/client/2fa/webauthn/credentials/:id`)
* **Security Guard (IDOR Protection)**: Attempts to delete non-existent or foreign credentials return `400 Bad Request` (`passkey not found or does not belong to user`).
