# Endpoint Specification: Account Recovery & 2FA Recovery Suite (`/v1/client/auth/recovery/*` & `/v1/client/2fa/recovery-codes/*`)

## Overview
* **Routes**:
  * `POST /v1/client/auth/recovery/initiate` — Initiate account recovery flow
  * `POST /v1/client/auth/recovery/proof/old-password` — Submit old password proof (trusted device required)
  * `POST /v1/client/auth/recovery/proof/guardian` — Submit guardian Shamir secret share proof
  * `POST /v1/client/auth/recovery/proof/security-questions` — Submit security questions answers proof
  * `POST /v1/client/auth/recovery/claim` — Claim account & set new password
  * `POST /v1/client/auth/recovery/cancel` — Cancel recovery (authenticated session)
  * `POST /v1/client/auth/recovery/cancel/token` — Cancel recovery (public signed cancellation link)
  * `POST /v1/client/2fa/recovery-codes/regenerate` — Step-up re-generate 16 2FA recovery codes
  * `GET /v1/client/2fa/recovery-codes/status` — Query remaining unused recovery codes count
* **HTTP Methods**: `POST`, `GET`
* **Purpose**: Production account recovery engine supporting dynamic multi-factor identity proof (Guardians, Old Passwords, Email/Phone OTP, Security Questions), timing-safe user enumeration defense, trusted device gating, and 7-day origin IP blacklisting upon security cancellation.

---

## Authentication & Access Control
* **Public Endpoints (`/v1/client/auth/recovery/initiate`, `/proof/*`, `/claim`, `/cancel/token`)**: Require Publishable Key (`X-Authn-Publishable-Key: pk_<env>_<hash>`).
* **Authenticated Endpoints (`/v1/client/2fa/recovery-codes/*`, `/v1/client/auth/recovery/cancel`)**: Require valid Access Token JWT (`Authorization: Bearer <jwt>`).

---

## Security Mechanics & Defense Architecture

1. **User Enumeration & Timing Attack Defense**:
   * Non-existent emails perform a dummy Argon2id CPU calculation (`argon2.IDKey`) matching existing user hash timing (~190ms vs ~200ms).
   * Payload returned for missing accounts is identical (`"status":"initiated"`, `"available_methods":["email_otp"]`), completely preventing email enumeration.

2. **Trusted Device Gating for Old Password Proof**:
   * `old_password` proof is restricted to recognized devices matching `authn_td_token` cookie or familiar IP subnets.
   * Untrusted devices attempting old password proof are rejected with `400 Bad Request` (`"old password proof is disallowed from unfamiliar device or network"`).

3. **Signed Cancellation Link & 7-Day IP Blacklisting**:
   * `POST /v1/client/auth/recovery/initiate` issues a signed `cancellation_token` sent to the registered email.
   * If the owner clicks the cancellation link (`POST /v1/client/auth/recovery/cancel/token`), the recovery request is terminated and the originating attacker's IP/subnet is blacklisted in Redis for 7 days (`403 Forbidden`).

---

## Request & Response Examples

### 1. Initiate Account Recovery (`POST /v1/client/auth/recovery/initiate`)
```json
{
  "email": "user.vanilla@authn.local"
}
```
**Response (200 OK — Valid Account)**:
```json
{
  "recovery_request_id": "req_3e2f8c17-a80",
  "status": "initiated",
  "is_trusted_device_origin": false,
  "available_methods": ["email_otp"],
  "cancellation_token": "539d51ae12546f05021de68590ff751235001293f7f47709d2b5d70b96c132bc"
}
```

### 2. Owner Security Cancellation (`POST /v1/client/auth/recovery/cancel/token`)
```json
{
  "cancellation_token": "539d51ae12546f05021de68590ff751235001293f7f47709d2b5d70b96c132bc"
}
```
**Response (200 OK — Cancelled & Blacklisted)**:
```json
{
  "status": "cancelled",
  "message": "Recovery request successfully cancelled. Originating request details blacklisted for 7 days. Account flagged for security review."
}
```

### 3. Subsequent Attacker Attempt (Blacklisted Origin)
```bash
$ curl -i -X POST -H "Content-Type: application/json" -H "X-Authn-Publishable-Key: $PK" \
  -d '{"email":"user.vanilla@authn.local"}' \
  http://localhost:8080/v1/client/auth/recovery/initiate
```
**Response (403 Forbidden)**:
```json
{
  "error": "origin_blacklisted",
  "message": "origin IP, subnet, or device fingerprint is temporarily blacklisted following a security cancellation"
}
```

---

## Security Audit & Attack Mitigation Log

| Attack Vector / Test | Payload / Input | Response Status | Security Defense Execution |
| :--- | :--- | :--- | :--- |
| **Missing Email Field** | `POST /v1/client/auth/recovery/initiate {}` | `400 Bad Request` | Input validation rejection |
| **Email Enumeration Attack** | Initiate recovery with non-existent email | `200 OK` (Timing-safe) | Executed dummy Argon2id hash + returned identical generic payload |
| **Untrusted Device Old Pass** | `POST /proof/old-password` from new IP | `400 Bad Request` | Device telemetry rejected untrusted origin |
| **Invalid Claim Token** | `POST /claim` with fake claim token | `400 Bad Request` | Request state validation (`not in ready_for_claim state`) |
| **Security Cancellation** | `POST /cancel/token` with signed token | `200 OK` | Recovery request terminated + Redis 7-day IP blacklist armed |
| **Blacklisted IP Re-attack** | Initiate recovery from blacklisted IP | `403 Forbidden` | Telemetry blacklist check blocked request |

*Last Verified*: `2026-08-06` — live `curl` attack suite against running server.
