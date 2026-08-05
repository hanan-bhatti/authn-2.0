# Endpoint Specification: `GET /v1/client/sessions` & `POST /v1/client/sessions/revoke*`

## Overview
* **Routes**:
  * `GET /v1/client/sessions` — List active user sessions
  * `POST /v1/client/sessions/revoke` — Revoke specific session by ID
  * `POST /v1/client/sessions/revoke-others` — Bulk revoke all other sessions except current
  * `POST /v1/client/sessions/revoke-all` — Bulk revoke all sessions for active user
  * `GET /v1/admin/users/:user_id/sessions` — Admin list sessions for target user
  * `POST /v1/admin/users/:user_id/sessions/revoke-all` — Admin revoke all sessions for target user
* **HTTP Methods**: `GET`, `POST`
* **Purpose**: Session management governance and IDOR-safe revocation suite. Allows users and admins to inspect active devices (`browser`, `os`, `device`), flag current session (`is_current: true`), and terminate individual or bulk sessions across devices.

---

## Authentication & Access Control
* **Client Endpoints**: Require `X-Authn-Publishable-Key` header **AND** a valid JWT Access Token (`Authorization: Bearer <access_token>`).
* **Admin Endpoints**: Require `X-Authn-Secret-Key` header (`sk_<env>_<hash>`) or console admin JWT.
* **IDOR Protection**: Strict ownership verification (`sess.UserID == caller.UserID`). Rejects cross-user session revocation attempts with `403 Forbidden`.

---

## Request Payloads

### `POST /v1/client/sessions/revoke`
```json
{
  "session_id": "ses_06599d51-82f"
}
```

---

## Responses & Status Codes

### `200 OK` — List Active Sessions (`GET /v1/client/sessions`)
```bash
$ curl -i -X GET -H "Authorization: Bearer <jwt>" \
  -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  http://localhost:8080/v1/client/sessions

HTTP/1.1 200 OK
Content-Type: application/json
X-Authn-Degraded-Mode: false
```
```json
{
  "sessions": [
    {
      "id": "ses_06599d51-82f",
      "device": {
        "browser": "Chrome",
        "os": "Windows",
        "device": "Desktop",
        "label": "Chrome on Windows"
      },
      "ip_address": "127.0.0.1",
      "location": "",
      "created_at": "2026-08-06T02:27:13Z",
      "is_current": true
    },
    {
      "id": "ses_b07badbd-34e",
      "device": {
        "browser": "Mobile Safari",
        "os": "iOS",
        "device": "Mobile",
        "label": "Mobile Safari on iOS"
      },
      "ip_address": "127.0.0.1",
      "location": "",
      "created_at": "2026-08-06T02:25:53Z",
      "is_current": false
    }
  ]
}
```

### `200 OK` — Revoke Specific Session (`POST /v1/client/sessions/revoke`)
```json
{
  "message": "session revoked",
  "session_id": "ses_06599d51-82f"
}
```

### `200 OK` — Revoke Other Sessions (`POST /v1/client/sessions/revoke-others`)
```json
{
  "count": 2,
  "message": "all other sessions revoked"
}
```

### `200 OK` — Revoke All Sessions (`POST /v1/client/sessions/revoke-all`)
```json
{
  "count": 3,
  "message": "all sessions revoked"
}
```

### `400 Bad Request` — Missing Session ID
```json
{
  "error": "session_id is required"
}
```

### `401 Unauthorized` — Missing or Invalid Access Token
```json
{
  "error": "session authentication required: missing or invalid access token"
}
```

### `403 Forbidden` — IDOR Cross-User Revocation Attempt
Returned when User A attempts to revoke a session belonging to User B.
```json
{
  "error": "unauthorized: session does not belong to user"
}
```

### `404 Not Found` — Unknown Session ID
```json
{
  "error": "session not found"
}
```

---

## Pentest & Security Verification Log

| Test Case | Request | Observed Status | Defense Verification |
| :--- | :--- | :--- | :--- |
| **Unauthenticated List** | `GET /v1/client/sessions` (No Auth) | `401 Unauthorized` | Access token validation enforced |
| **Session Listing** | `GET /v1/client/sessions` (Valid JWT) | `200 OK` | Correct device parsing & `is_current: true` flag |
| **IDOR Cross-User Attack** | User 2 attempts to revoke User 1 session | `403 Forbidden` | Strict `sess.UserID == userID` ownership check |
| **Missing Parameter** | `POST /v1/client/sessions/revoke` (`{}`) | `400 Bad Request` | Payload validation |
| **Non-existent Session** | `POST /v1/client/sessions/revoke` (`ses_fake`) | `404 Not Found` | Entity existence check |
| **Legitimate Revoke** | Revoke secondary device session | `200 OK` | Target session status updated to `revoked` |
| **Bulk Revoke-Others** | `POST /v1/client/sessions/revoke-others` | `200 OK` | All sessions except `currentSessionID` revoked |
| **Bulk Revoke-All** | `POST /v1/client/sessions/revoke-all` | `200 OK` | All user sessions revoked |
| **Admin List** | `GET /v1/admin/users/:id/sessions` (`sk_...`) | `200 OK` | Secret key admin authorization |
| **Admin Revoke-All** | `POST /v1/admin/users/:id/sessions/revoke-all` | `200 OK` | Secret key admin revocation |

*Last Verified*: `2026-08-06` — live `curl` against running server.
