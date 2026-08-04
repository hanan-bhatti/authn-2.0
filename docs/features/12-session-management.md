# Feature Spec 12: Advanced Session Management & Revocation

**Feature Code**: FR-8  
**Tier**: Core Authentication & Session Lifecycle Layer  
**Status**: Production Implemented & Verified (100% Postman & Integration Test Pass)  

---

## 1. Executive Summary

Authn provides a high-security, breach-resistant **Session Management Engine** featuring:
1. **SHA-256 Hashed Refresh Tokens**: Opaque 64-byte tokens stored strictly as SHA-256 digests in the database (`Session.refresh_token_hash`). Raw tokens are never logged or stored in plaintext.
2. **Refresh Token Rotation (RTR) & 10-Second Grace Window**: Token exchange invalidates the previous refresh token, transitions status to `rotated_grace` with `grace_expires_at = now + 10s`, and issues a new token pair. Concurrent parallel requests within 10s receive the same token without error.
3. **Breach Detection & Token Reuse Revocation**: Presenting a rotated token *after* the 10-second grace window expires triggers automatic revocation of **all** sessions for that user to mitigate stolen token attacks.
4. **Device & Location Intelligence**: Parsed User-Agent metadata (Browser name, OS, Device type, formatted label), IP address, and `last_active_at` timestamp.
5. **Session Control APIs**: Client endpoints to list active sessions (with `is_current` flag), revoke a specific session, revoke all other sessions, or revoke all sessions; and Admin endpoints for remote session termination.

---

## 2. Key Architecture & Security Controls

### 2.1 Refresh Token Rotation Flow (RTR)
```
Client                      Auth Server                       Database
  │                              │                               │
  ├────── POST /refresh ────────►│                               │
  │     (Raw Token A)            ├───── Hash(Token A) ──────────►│
  │                              │                               │ Read status: 'active'
  │                              │◄──── Session A Record ────────┤
  │                              │                               │
  │                              ├───── Rotate Session A ───────►│ Set status: 'rotated_grace'
  │                              │                               │ Set grace_expires_at = NOW + 10s
  │                              ├───── Create Session B ───────►│ Status: 'active'
  │                              │                               │ Set superseded_by = Session B
  │◄───── Return Token B ────────┤                               │
```

### 2.2 Parallel Request Handling (10s Grace Window)
If 2 parallel API requests arrive at the same time:
- **Request #1**: Arrives at $t=0\text{s}$. Rotates Session A $\to$ Session B. Session A becomes `rotated_grace` (10s TTL).
- **Request #2**: Arrives at $t=0.05\text{s}$ with Token A. Server detects `rotated_grace` and `now < grace_expires_at`. Safely returns Access Token for Session B without throwing an error.

### 2.3 Reuse Detection (Stolen Token Defense)
If an attacker attempts to use Token A at $t=15\text{s}$ (after the 10s grace window expires):
- Server detects `rotated_grace` and `now >= grace_expires_at` (or `revoked`).
- **Reuse Detected!** Server executes `RevokeAllUserSessions(userID)`.
- Returns `401 Unauthorized` with `"code": "session_compromised"`.

---

## 3. Policy & Validation Rules

Admin configurable via `PUT /v1/tenant/security-policy`:

| Setting | Type | Range | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `sliding_window_enabled` | `bool` | `true` / `false` | `true` | Enables rolling expiration on active use. |
| `idle_timeout_days` | `int` | `1` - `365` | `7` | Days of inactivity before session expires. Must be $\le$ `session_ttl_days`. |
| `session_ttl_days` | `int` | `1` - `730` | `30` | Absolute maximum lifespan of session. |
| `max_active_sessions_per_user` | `int` | `0` - `50` | `0` | Max concurrent logins per user (`0` = unlimited). |
| `rotation_grace_period_seconds` | `int` | `1` - `60` | `10` | Rotation grace period for parallel requests. |

---

## 4. REST API Endpoint Index

### 4.1 Client Endpoints (Publishable Key `pk_test_...`)
- `POST /v1/client/auth/refresh` — Rotate refresh token, return new access token & refresh token.
- `GET /v1/client/sessions` — List active sessions for authenticated user with device details.
- `POST /v1/client/sessions/revoke` — Revoke a specific session (`{"session_id": "ses_..."}`).
- `POST /v1/client/sessions/revoke-others` — Revoke all other active user sessions.
- `POST /v1/client/sessions/revoke-all` — Revoke all active user sessions (logout all devices).

### 4.2 Admin Endpoints (Secret Key `sk_test_...`)
- `GET /v1/admin/users/:user_id/sessions` — Admin list user active sessions.
- `POST /v1/admin/users/:user_id/sessions/revoke-all` — Admin kill-switch to terminate all user sessions.
