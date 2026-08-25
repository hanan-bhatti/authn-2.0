# Feature Spec 09: Multi-Factor Authentication (TOTP, SMS, WebAuthn Passkeys, Backup Codes)

**Feature Code**: FR-4  
**Tier**: Core Security & Authentication Layer  
**Status**: Production Implemented & Verified  

---

## 1. Executive Summary

Authn provides a comprehensive, multi-factor authentication (MFA) suite supporting **TOTP Authenticator Apps**, **SMS/WhatsApp OTP** (with email fallback during enrollment), **Backup Recovery Codes**, and **WebAuthn / Passkeys (FIDO2)**.

All MFA methods are bound to user accounts and enforced during login challenges via a single, uniform `twoFactorToken` challenge token (120s TTL).

---

## 2. Supported MFA Methods & Endpoints

### 2.1 TOTP Authenticator Apps (RFC 6238)
- `POST /v1/client/auth/2fa/totp/enroll` — Generates a 160-bit high-entropy secret (`secret_enc` stored AES-256-GCM encrypted) and QR code provisioning URI (`otpauth://totp/...`). Status: `pending`.
- `POST /v1/client/auth/2fa/totp/confirm` — Validates initial TOTP code and transitions status `pending` $\to$ `active`.
- `POST /v1/client/auth/2fa/totp/verify` (or `POST /v1/client/auth/2fa/verify`) — Validates 6-digit TOTP code during login challenge (supports $\pm 1$ period time skew tolerance).
- `POST /v1/client/auth/2fa/totp/disable` — Requires password re-verification. Revokes active TOTP method and terminates active sessions.

### 2.2 Backup Recovery Codes
- `POST /v1/client/auth/2fa/recovery-codes/regenerate` — Issues 8 single-use cryptographically generated codes (`XXXX-XXXX`). Hashes are stored via Argon2id/SHA-256 in DB.
- `GET /v1/client/auth/2fa/recovery-codes/status` — Returns count of remaining unused recovery codes.

### 2.3 SMS / WhatsApp OTP
- `POST /v1/client/auth/2fa/sms/enroll` — Registers E.164 phone number.
- `POST /v1/client/auth/2fa/sms/confirm` — Validates initial SMS verification code.
- `POST /v1/client/auth/2fa/sms/challenge` — Sends the code for a login already holding an `mfa_token`. Public, since that caller has no session yet, and the only sender on the login path — verification reads the code from memory, and a code exists only once it has been sent.
- `DELETE /v1/client/auth/2fa/sms/disable` — Disables SMS 2FA with step-up authentication.
- **Rate Limiting**: Strictly enforces 3 SMS requests per 10 minutes per user, counted across enrollment and login sends alike.
- **Email fallback applies to enrollment only.** A login challenge that cannot reach the provider answers `503` rather than mailing the code: that caller has proven the password alone, and a second factor delivered to the account address is not a second factor.

### 2.4 WebAuthn / Passkeys (FIDO2)
- `POST /v1/client/auth/2fa/webauthn/register/begin` & `finish` — Enrolls biometrics/hardware keys (FaceID, TouchID, YubiKey). Credential ID and public key stored AES-256-GCM encrypted.
- `POST /v1/client/auth/2fa/webauthn/login/begin` & `finish` — Authenticates user via passkey assertion.
- `GET /v1/client/auth/2fa/webauthn/passkeys` & `DELETE /v1/client/auth/2fa/webauthn/passkeys/:id` — Manages passkeys while enforcing a safety rule: cannot delete last active 2FA method unless password auth is enabled.

---

## 3. Single Source of Truth Challenge Flow

During `POST /v1/client/auth/login`, if 2FA is active:
1. Returns `200 OK` with payload:
```json
{
  "requires2FA": true,
  "twoFactorToken": "tft_9a8b7c...",
  "methods": ["totp", "webauthn", "backup_codes"]
}
```
2. Client submits verification payload to `/v1/client/auth/2fa/verify` or method-specific endpoint.
3. Upon clean validation, issues session tokens (`accessToken` & `authn_refresh_token` cookie).
