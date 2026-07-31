# Security & Threat Model Specification

**Document Version**: 1.0.0  
**Date**: 2026-08-01  
**Status**: Approved Specification (Execution Ready)  
**Author**: Authn Core Team  

---

## 1. Threat Vectors & Countermeasures (OWASP & Threat Matrix)

| Threat Vector | Attack Scenario | Authn Mitigation Strategy & Architecture |
| :--- | :--- | :--- |
| **Credential Stuffing / Brute Force** | Automated botnets submitting thousands of passwords per second. | **Redis Lua Pipelined Rate Limiter**: Multi-dimensional throttling by IP, User-Agent, Device Token digest, and API key in a single network hop. Fail-closed policy on auth mutation endpoints. |
| **Push Fatigue Attacks** | Spamming user with 100s of push notifications to coerce `[Approve]`. | **Number Matching & Payload Insulation**: Login screen displays 2-digit `matchNumber` (e.g. `47`). The push payload delivered to the phone carries ONLY shuffled `options: [12, 47, 89]` and **NEVER contains `matchNumber`**. Phone cannot auto-select the right answer. |
| **Database Compromise (Leaked DB Dump)** | Attacker gains access to full SQL database dump. | **Argon2id & Key Hardening**: Passwords hashed via RFC 9106 Argon2id ($t=3, m=64MB, p=4$). Secret API keys hashed via **peppered HMAC-SHA256**. Refresh tokens stored as **SHA-256 hashes**. OAuth third-party tokens AES-256-GCM encrypted using KMS keys out-of-database. |
| **Cross-Site Scripting (XSS) Token Theft** | Malicious client script steals access/refresh tokens. | **HttpOnly Cookie Delivery**: Web sessions deliver long-lived refresh tokens strictly via `HttpOnly`, `Secure`, `SameSite=Lax` cookies, preventing JavaScript reading of refresh tokens. Native mobile apps receive tokens via JSON for OS KeyStore/Secure Enclave storage. |
| **Cross-Site Request Forgery (CSRF)** | Malicious origin triggers unauthorized session actions. | **OAuth State Cookie & SameSite Lax**: Social auth flows enforce 32-byte cryptographically random `state` parameter bound to `HttpOnly` state cookies (`authn_oauth_state`). Custom client API routes require `X-Authn-Publishable-Key` headers. |
| **Open Redirect Vulnerability** | Attacker redirects victim to phishing domain post-login. | **Exact-Match URI Validation**: `exact_redirect_uris` enforced strictly. No wildcards permitted per OAuth 2.0 BCP. |
| **Multi-Tenant Data Leakage** | Tenant A queries Tenant B's users or sessions. | **Ent Privacy Interceptors**: Ent middleware hooks execute at runtime query generation, injecting `WHERE tenant_id = ? AND environment = ?` filters. **Missing Context Policy**: If tenant context is missing, privacy interceptors **fail closed** and abort query execution. |
| **Refresh Token Replay & Theft** | Stolen refresh token presented after rotation. | **Token Rotation & Anomaly Revocation**: Refresh tokens rotated on every use with a 10-second grace window (`status = rotated_grace`). If a superseded token is presented after grace window expiry, all sessions for that user are revoked immediately. |
| **Account Recovery Takeover** | Attacker attempts to hijack account via recovery flows. | **Universal 48-Hour Freeze Window & Shamir SSS**: ALL recovery flows enforce a mandatory 48-hour delay freeze with push/email alerts. Pre-enrolled Guardian Recovery uses 2-of-3 Shamir's Secret Sharing threshold splitting. GDPR device telemetry retained for max 90 days. |
| **Cache / Redis Layer Outage** | Redis cluster experiences downtime or network split. | **Fail-Closed / Fail-Open Outage Policy**: Sensitive auth mutations (`/login`, `/signup`, `/oauth/token`, `/2fa/verify`) **fail-closed** to prevent unthrottled brute forcing. Read-only token checks (`/v1/client/user/me`) **fail-open** via local Go in-memory JWKS validation with `X-Authn-Degraded-Mode: true` header. |

---

## 2. Cryptographic Standards & Key Management

### 2.1 Password Hashing (RFC 9106 Argon2id Production Profile)
- **Algorithm**: Argon2id
- **Time Cost ($t$)**: 3 iterations
- **Memory Cost ($m$)**: 64 MB (65,536 KB)
- **Parallelism ($p$)**: 4 threads
- **Salt**: 16 bytes cryptographically random salt per user

### 2.2 Secret API Key Hashing (Peppered HMAC-SHA256)
- Secret keys (`sk_...`) are hashed using **HMAC-SHA256** with an out-of-database server pepper key (`AUTHN_API_KEY_PEPPER`), neutralizing offline rainbow-table attacks on leaked DB dumps.

### 2.3 Token Signing & JWKS Key Rotation
- **Asymmetric Algorithm**: RS256 (RSA-2048) or ES256 (ECDSA-P256)
- **Rotation Interval**: Automated 30-day rotation
- **Grace Period**: 7-day overlapping grace period where previous public keys remain published in JWKS (`/.well-known/jwks.json`) to prevent token validation failures on active sessions.
