# Endpoint Specification: `POST /v1/client/auth/refresh`

## Overview
* **Route**: `POST /v1/client/auth/refresh`
* **HTTP Method**: `POST`
* **Purpose**: Refresh Token Rotation Endpoint. Exchanges a valid refresh token for a new Access Token JWT and a newly rotated Refresh Token. Enforces a 10-second grace window for concurrent network retries and automatic compromise mitigation (revoking all user sessions) if token reuse is detected outside the grace period.

---

## Authentication & Access Control
* **Authentication Required**: `X-Authn-Publishable-Key` (Public Client API Key)
* **Headers Required**:
  * `X-Authn-Publishable-Key: pk_<env>_<hash>`
  * `Content-Type: application/json`
* **Token Source Order**:
  1. Request body JSON (`{"refresh_token": "..."}`)
  2. Fallback to `authn_refresh_token` HttpOnly cookie

---

## Request Payload (`POST /v1/client/auth/refresh`)

```json
{
  "refresh_token": "266cb73e6f9aecffa0dbd527c24baab0e9a4fe03864cedfdd34296aa4c698da2"
}
```

---

## Refresh Token Rotation & Security Lifecycle

```
[ Active Session ] ──( 1st Refresh Call )──> [ Issued New Token Pair ]
                                                     │
                                                     ├── ( Within 10s Grace Window ) ──> Return Active Token Pair (200 OK)
                                                     │
                                                     └── ( After 10s Grace Window ) ──> REUSE DETECTED!
                                                                                           │
                                                                                           └── Revoke ALL User Sessions (401 Unauthorized)
```

1. **Active Token Rotation**: Calling `/v1/client/auth/refresh` with an active refresh token invalidates the old token (moving it to `rotated_grace` status for 10 seconds) and issues a new session token pair.
2. **10-Second Grace Window**: Concurrent requests or network retries replaying the old token within 10 seconds of rotation succeed (`200 OK`) and return the active session token without re-rotating (prevents race condition token loss across browser tabs).
3. **Automatic Compromise Mitigation & Configurable Tenant Policy**: Replaying a rotated token *after* the 10-second grace window indicates token theft or replay attack. The engine executes tenant `SecurityPolicy.token_reuse_policy`:
   * `"global_revoke"` (Default / Enterprise): Immediately **revokes ALL active sessions** for the user across all devices.
   * `"session_revoke"` (Consumer App): **Revokes ONLY the specific compromised session family** (`ses_id`), allowing un-impacted devices to remain logged in.
   Returns `401 Unauthorized` with `code: "session_compromised"`.

---

## Responses & Status Codes

### `200 OK` — Successful Refresh Token Rotation
```bash
$ curl -i -X POST -H "Content-Type: application/json" \
  -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  -d '{"refresh_token":"266cb73e6f9aecffa0dbd527c24baab0e9a4fe03864cedfdd34296aa4c698da2"}' \
  http://localhost:8080/v1/client/auth/refresh

HTTP/1.1 200 OK
Content-Type: application/json
X-Authn-Degraded-Mode: false
```
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "512bbc00-1004-4607-9279-752897038b18a14100aa-cf80-4f3a-a18a-30f9176585bc",
  "token_type": "Bearer",
  "expires_in": 900,
  "session_id": "ses_1e12795c-48f"
}
```

### `200 OK` — Grace Window Concurrent Request Handshake
Returned when a recently rotated token is replayed within the 10-second grace period. Returns the current active session access token without re-rotating; `refresh_token` is set to `""`.

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "",
  "token_type": "Bearer",
  "expires_in": 900,
  "session_id": "ses_1e12795c-48f"
}
```

`expires_in` is the lifetime of the token in the same response, in seconds, and both come from one resolution: the tenant's `access_token_ttl_minutes` where the session policy sets one, otherwise the deployment's `ACCESS_TOKEN_TTL`, bounded in `test` by `TEST_ACCESS_TOKEN_TTL`. The `900` above is the deployment default; a tenant that chose 60 minutes sees `3600` here and a `test` credential sees the ceiling. A client scheduling its next refresh from this field therefore stays correct without knowing what any of those are set to.

### `400 Bad Request` — Missing Refresh Token

Returned when neither request body `refresh_token` nor `authn_refresh_token` cookie is present.

```json
{
  "error": "refresh_token required"
}
```

### `401 Unauthorized` — Invalid or Expired Refresh Token
Returned when token is unknown, garbage, or has passed the absolute expiration of the session it belongs to — the tenant's `refresh_token_ttl_days` where the session policy sets one, otherwise the deployment's `REFRESH_TOKEN_TTL` (30 days by default), bounded in `test` by `TEST_SESSION_TTL`. The check is against the stored session rather than the cookie, so a token presented past that point is refused however it was kept.

```json
{
  "code": "invalid_token",
  "error": "invalid or expired refresh token"
}
```

### `401 Unauthorized` — Session Compromised (Reuse Attack Detected)
Returned when a rotated token is replayed after the 10-second grace period. **Triggers automatic revocation of all user sessions**.

```json
{
  "code": "session_compromised",
  "error": "session reuse detected; all sessions revoked for security"
}
```

### `401 Unauthorized` — Missing Publishable Key
```json
{
  "error": "missing publishable API key in X-Authn-Publishable-Key header"
}
```

### `405 Method Not Allowed` — Wrong HTTP Verb
```json
{
  "error": {
    "code": 405,
    "message": "Method Not Allowed"
  }
}
```

---

## Security Properties (Verified)

| Property | Mechanism | Status |
|---|---|---|
| Refresh Token Rotation (RTR) | Each refresh invocation invalidates the old refresh token and issues a new pair | Verified |
| Concurrent Request Grace Period | 10-second grace window absorbs parallel browser tab requests | Verified (`200 OK` + `""` refresh_token) |
| Token Reuse Detection | Replaying a token past 10s grace window triggers automatic account-wide session revocation | Verified (`code: session_compromised`) |
| Cookie & Body Parsing | Dual fallback: parses JSON body `refresh_token` first, then `authn_refresh_token` cookie | Verified |
| Proper Error Categorization | Invalid/missing tokens return `401`/`400` (fixed 500 error code leak) | Verified |

---

## Verification & Pentest History
* **Last Verified Date**: `2026-08-06`
* **Test Subject**: `user.vanilla@authn.local`
* **Verification Method**: Manual live `curl` pentest against running server (verified happy path rotation, 10s grace window, 11s reuse compromise revocation, missing token 400, garbage token 401, missing key 401, 405 method enforcement).
