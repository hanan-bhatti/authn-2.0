# Endpoint Specification: Email Verification Flow

## Endpoints Covered
* `GET /v1/client/verify-email` — Token-based email address verification
* `POST /v1/client/resend-verification` — Resend verification email

These two endpoints form a single user flow and are documented together.

---

## 1. `GET /v1/client/verify-email`

### Overview
* **Route**: `GET /v1/client/verify-email?token=<raw_token>`
* **Purpose**: Validates a single-use 64-hex-character email verification token, marks the user's `email_verified` field `true`, and clears the token from the database. Intended to be opened by the user clicking the link from their verification email.

### Authentication & Access Control
* **Header Required**: `X-Authn-Publishable-Key: pk_<env>_<hash>`
* **Rate Limiting**: Shares the global 5 attempts / 900s sliding window per IP.

### Request
```
GET /v1/client/verify-email?token=56d9754d701cfa3c74ba92...
X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012
```

No request body.

### Token Lifecycle
* Generated as 32 cryptographically random bytes (64 hex chars via `crypto/rand`).
* Stored as SHA-256 hash in the DB — raw token **never persisted**.
* Expires **24 hours** after generation.
* **Single-use**: On successful verification, `email_verified` is set `true` AND the token + expiry fields are cleared via `MarkUserEmailVerified`. Replaying the same token after use returns `400` (token not found, since it was cleared).

---

### Responses

#### `200 OK` — Successful Verification
```bash
$ curl -i -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  "http://localhost:8080/v1/client/verify-email?token=56d9754d701cfa3c74ba92feb9ff8cd6c530f31a7b2cbb1813c2cf938b9870c2"

HTTP/1.1 200 OK
Content-Type: application/json
X-Authn-Degraded-Mode: false
```
```json
{
  "message": "email successfully verified",
  "email": "verify.test@authn.local",
  "email_verified": true
}
```

#### `400 Bad Request` — Missing Token Parameter
```bash
$ curl -i -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  "http://localhost:8080/v1/client/verify-email"

HTTP/1.1 400 Bad Request
```
```json
{"error": "verification token query parameter is required"}
```

#### `400 Bad Request` — Invalid / Already-Used / Expired Token
Both garbage tokens and replayed (already-consumed) tokens return the same generic error — no signal about which case applies.

```bash
# Test 1: Garbage token
$ curl -i "http://localhost:8080/v1/client/verify-email?token=aaaaaaaaaaaa..."
HTTP/1.1 400 Bad Request

# Test 2: Replay of already-verified token (same token, 2nd request)
$ curl -i "http://localhost:8080/v1/client/verify-email?token=56d9754d701cfa..."
HTTP/1.1 400 Bad Request
```
```json
{"error": "invalid or revoked token"}
```

#### `401 Unauthorized` — Missing Publishable Key
```json
{"error": "missing publishable API key in X-Authn-Publishable-Key header"}
```

#### `405 Method Not Allowed` — Wrong HTTP Verb
```bash
$ curl -i -X POST "http://localhost:8080/v1/client/verify-email?token=..."

HTTP/1.1 405 Method Not Allowed
Allow: GET, HEAD
```
```json
{"error": {"code": 405, "message": "Method Not Allowed"}}
```

---

## 2. `POST /v1/client/resend-verification`

### Overview
* **Route**: `POST /v1/client/resend-verification`
* **Purpose**: Triggers a new verification email for an unverified account. Designed to be **enumeration-safe**: always returns the same `200` response regardless of whether the email is registered, already verified, or completely unknown.

### Authentication & Access Control
* **Header Required**: `X-Authn-Publishable-Key: pk_<env>_<hash>`
* **Rate Limiting**: Shares the global 5 attempts / 900s sliding window per IP.

### Request Body
```json
{
  "email": "fresh.signup@authn.local"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `email` | string | Yes | Must pass RFC email format validation |
| `tenant_id` | string | No | Defaults to `tnt_default` |
| `environment` | string | No | Defaults to `test` |

---

### Responses

#### `200 OK` — Always (Enumeration-Safe)
The same message is returned for all cases: unknown email, already-verified account, valid unverified account. No external signal distinguishes these.

```bash
# Case A: Unknown email (nobody@doesnotexist.local)
$ curl -i -X POST -H "Content-Type: application/json" \
  -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  -d '{"email":"nobody@doesnotexist.local"}' \
  http://localhost:8080/v1/client/resend-verification

HTTP/1.1 200 OK

{"message": "if an account exists with this email address, a verification link has been sent"}

# Case B: Already-verified account
# Case C: Valid unverified account
# All three return the identical 200 response above.
```

#### `400 Bad Request` — Invalid Email Format
```bash
$ curl -i -X POST -H "Content-Type: application/json" \
  -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  -d '{"email":"not-an-email"}' \
  http://localhost:8080/v1/client/resend-verification

HTTP/1.1 400 Bad Request
```
```json
{"error": "invalid email address format"}
```

#### `401 Unauthorized` — Missing Publishable Key
```bash
$ curl -i -X POST -H "Content-Type: application/json" \
  -d '{"email":"fresh.signup@authn.local"}' \
  http://localhost:8080/v1/client/resend-verification

HTTP/1.1 401 Unauthorized
```
```json
{"error": "missing publishable API key in X-Authn-Publishable-Key header"}
```

#### `405 Method Not Allowed` — Wrong HTTP Verb
```bash
$ curl -i -X GET -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  http://localhost:8080/v1/client/resend-verification

HTTP/1.1 405 Method Not Allowed
Allow: POST
```
```json
{"error": {"code": 405, "message": "Method Not Allowed"}}
```

---

## Security Properties (Verified)

| Property | Behavior | Status |
|---|---|---|
| Single-use token | Replay of used token returns `400` with same error as garbage token | Verified |
| Token expiry | `EmailVerificationExpiresAtGT(time.Now())` checked at DB query level | Verified (24h TTL) |
| Token storage | SHA-256 hash only — raw token never persisted | Verified (source audit) |
| Token cleared on use | `ClearEmailVerificationToken()` + `ClearEmailVerificationExpiresAt()` called in `MarkUserEmailVerified` | Verified |
| Resend enumeration safety | All cases (unknown / verified / unverified) return identical `200` | Verified |
| Method enforcement | `GET verify-email` 405 on POST; `POST resend-verification` 405 on GET | Verified |
| Auth gate | Both endpoints require valid `X-Authn-Publishable-Key` | Verified |
| Rate limiting | Both endpoints under global 5 req / 900s per IP sliding window | Verified (shared `mws` stack) |
| Fail-CLOSED | Under Redis outage, `503` returned — rate limit bypass blocked | Inherits from shared middleware |

---

## Known Limitations / Design Notes

* **No per-email resend rate limit**: The rate limiter is IP-based only. 5 resends / 15 min per IP, but no per-user or per-email cap. A distributed attacker rotating IPs could still spam a target inbox. Acceptable for current deployment scale.
* **Resend always overwrites the previous token**: Calling resend generates a new token and overwrites the old one in the DB. Previous links are immediately invalidated. Intentional — prevents accumulation of live tokens.
* **No audit log on silently-skipped resend**: For already-verified accounts the service silently returns `nil`. No log entry is written. This is acceptable since the caller cannot learn the verified state from the response.

---

## Last Verified
* **Date**: `2026-08-06`
* **Test Subject**: `verify.test@authn.local` (user ID `usr_c52b258e-cc6`, created live during this session)
* **Verification Method**: Real token extracted from Mailpit SMTP catcher (`GET http://localhost:8025/api/v1/messages`), then 11 curl cases run against the live server.
* **Automated Test**: `cmd/verify_email/main.go` — end-to-end Mailpit integration test (signup → email capture → token extraction → verify → login confirmation).
