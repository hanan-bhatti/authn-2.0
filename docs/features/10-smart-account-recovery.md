# Feature Spec 10: Smart Account Recovery & 7-Day Security Shield

**Feature Code**: FR-5  
**Tier**: Core Security & Fraud Prevention Layer  
**Status**: Production Implemented & Verified  

---

## 1. Executive Summary

FR-5 implements a zero-trust, multi-layered account recovery architecture designed to eliminate account takeover risks for locked-out users.

It combines **Dynamic Identity Proof Resolution**, **Shamir's Secret Sharing ($GF(2^8)$)** pre-enrolled guardian recovery, **Telemetry Trust Engine** (HMAC-SHA256 device cookies + IPv4/IPv6 CIDR subnet parsing), a **Mandatory 48-Hour Security Freeze Window**, **Per-Tenant Admin `RecoveryPolicy`**, and **Multi-Channel Security Cancellation with 7-Day Blacklisting**.

---

## 2. Dynamic Priority Resolution Engine

When a locked-out user initiates recovery (`POST /v1/client/auth/recovery/initiate`), the engine dynamically evaluates available identity-proof methods in priority order based on the user's account configuration and tenant `RecoveryPolicy`:

1. **Guardians** (Offered FIRST if pre-enrolled recovery contacts exist).
2. **Recovery Phone OTP** (SMS/WhatsApp OTP if verified phone number exists).
3. **Recovery Email OTP** (Single-use OTP code sent to verified email).
4. **Old Password** (Surfaced ONLY if Telemetry Engine confirms recognized device token cookie + familiar IP subnet).
5. **Security Questions** (Surfaced ONLY when higher-tier methods 1-4 are empty or exhausted).

*Dead-End Rule*: If no methods are enabled/available, returns `400 Bad Request` with `no_recovery_methods_available`, directing the user to manual administrative support.

---

## 3. Shamir's Secret Sharing ($GF(2^8)$) Engine

Users can pre-enroll 1 to 5 trusted guardians (`POST /v1/client/account/guardians/invite`).
- **Master Secret $M$**: 256-bit cryptographically random secret generated in memory.
- **Majority Threshold $k$**: Calculated as $k = \lfloor N/2 \rfloor + 1$ (e.g. 2-of-2, 2-of-3, 3-of-4, 3-of-5).
- **Polynomial Evaluation**: $f(x) = M + a_1 x + a_2 x^2 + \dots + a_{k-1} x^{k-1} \pmod{P(x)}$ over $GF(2^8)$ with irreducible polynomial $x^8 + x^4 + x^3 + x + 1$ ($0\text{x}11\text{B}$).
- **Zero-Knowledge Token Delivery**: Raw shares exist in memory briefly during split computation and are delivered to guardians via URL fragments (`#token=...`), ensuring raw shares never touch HTTP logs or database storage. DB persists SHA-256 share hashes (`share_hash`) only.
- **Re-Key & Re-Split Protocol**: Revoking a guardian invalidates prior shares and forces a full re-key split across remaining active guardians.

---

## 4. Telemetry Trust Engine

- **Signed Device Cookie**: `authn_td_token` HMAC-SHA256 signed cookie with 90-day sliding expiration and User-Agent/Accept-Language client fingerprint validation.
- **IP Subnet History**: Parses IPv4 `/24` (or configurable bits) and IPv6 `/48` subnets. Records first/last seen timestamps and login counts.
- **Auto-Purge**: Background worker automatically purges device records and subnet history inactive for >90 days (or tenant `trusted_device_window_days`).

---

## 5. State Machine & 48-Hour Freeze Window

Recovery lifecycle transitions:
`INITIATED` $\to$ `AWAITING_PROOF` $\to$ `PROOF_VERIFIED` $\to$ `FREEZE_ACTIVE` ($48\text{h}$) $\to$ `READY_FOR_CLAIM` ($15\text{m}$) $\to$ `COMPLETED` or `CANCELLED`.

- **Freeze Delay**: Once proof is verified, recovery enters `FREEZE_ACTIVE` for 48 hours (configurable 24-168h). System dispatches security alerts across all active user sessions and emails.
- **Account Claim**: After freeze expiration, a background job transitions request to `READY_FOR_CLAIM` and generates a 15-minute single-use claim token. Calling `POST /v1/client/auth/recovery/claim` resets password with RFC 9106 Argon2id, wipes 2FA, issues 8 fresh recovery codes, and revokes prior sessions.

---

## 6. Per-Tenant Admin `RecoveryPolicy`

Configurable per tenant via `GET/PUT /v1/tenant/recovery-policy`. Enforces 9 strict validation rules:
1. `freeze_window_hours`: 24 to 168 hours.
2. `claim_token_ttl_minutes`: 5 to 60 minutes.
3. `lockout_schedule`: Monotonically non-decreasing durations (first step $\ge 1\text{h}$, 3 to 10 total steps).
4. `lockout_reset_days`: 7 to 90 days.
5. `trusted_device_window_days`: 30 to 365 days.
6. `min_guardians` & `max_guardians`: $1 \le \text{min} \le \text{max} \le 5$.
7. At least ONE method toggle must remain `true` tenant-wide.
8. Subnet bit bounds: IPv4 16-30, IPv6 32-64.
9. `max_proof_attempts_per_window`: 1 to 10.

---

## 7. Multi-Channel Cancellation & 7-Day Blacklist Shield

If an illegitimate recovery attempt is initiated by an attacker:
1. **Authenticated Session Cancellation (`POST /v1/client/auth/recovery/cancel`)**: Legitimate owner cancels from active session. Preserves cancelling session while revoking secondary sessions.
2. **Public Signed Link Cancellation (`POST /v1/client/auth/recovery/cancel/token`)**: Unauthenticated cancellation via signed link token.
3. **Remediation Action**:
   - Recovery request status set to `CANCELLED`.
   - 7-day multi-dimensional `SecurityBlacklist` record created for attacker's IP, subnet, and client fingerprint hash.
   - `User.SecurityReviewRequired` set to `true`.
   - Subsequent recovery/login attempts from blacklisted origin return `403 Forbidden` (`ErrOriginBlacklisted`).
