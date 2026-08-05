# Endpoint Specification: Admin User Impersonation & Audit Controls (`/v1/admin/users/:id/impersonate`, `/v1/tenant/impersonation-policy`, `/v1/client/auth/impersonate/exit`)

## Overview
* **Routes**:
  * `POST /v1/admin/users/:user_id/impersonate` — Initiate admin user impersonation session
  * `GET /v1/tenant/impersonation-policy` — Get tenant impersonation policy rules
  * `PUT /v1/tenant/impersonation-policy` — Update tenant impersonation policy rules
  * `POST /v1/client/auth/impersonate/exit` — Exit active impersonation session
* **HTTP Methods**: `POST`, `GET`, `PUT`
* **Purpose**: Production admin user impersonation engine with step-up re-authentication guards, short-lived JWT issuance (`is_impersonated: true`), support ticket mandatory tracing, user opt-in enforcement, and immediate security notice emails.

---

## Authentication & Access Control
* **Admin & Tenant Endpoints (`/v1/admin/users/:id/impersonate`, `/v1/tenant/impersonation-policy`)**: Require Secret Key (`X-Authn-Secret-Key: sk_<env>_<hash>`) or Console Admin JWT with `tenant_admin` or `support_admin` role.
* **Exit Endpoint (`POST /v1/client/auth/impersonate/exit`)**: Requires active Impersonation Access Token JWT (`Authorization: Bearer <jwt>`).

---

## Impersonation Policy & Guardrails

| Guardrail Parameter | Description | Default Value | Security Impact |
| :--- | :--- | :--- | :--- |
| `enabled` | Master toggle for tenant impersonation | `true` | When `false`, all impersonation requests return `403 Forbidden` |
| `max_duration_minutes` | Upper bound for impersonation JWT TTL | `15` mins | Limits token lifetime window (max 60 mins) |
| `require_step_up_auth` | Mandates admin re-auth before impersonation | `true` | Requires password/TOTP step-up to prevent session takeover |
| `require_user_opt_in` | Requires user consent in metadata | `false` | When `true`, blocks impersonation unless user opted in |
| `restrict_admin_impersonation` | Restricts impersonating admin users | `true` | Prevents support admins from impersonating tenant admins |
| `email_notification_policy` | Automatic notification email | `"IMMEDIATE"` | Sends transparency email to target user upon impersonation |

---

## Request & Response Examples

### 1. Initiate Impersonation (`POST /v1/admin/users/:user_id/impersonate`)
```json
{
  "reason": "Investigating billing ticket",
  "ticket_id": "SUPP-9921",
  "duration_minutes": 15
}
```
**Response (200 OK)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "impersonated_user": {
    "id": "usr_vanilla_007",
    "email": "user.vanilla@authn.local",
    "status": "active",
    "email_verified": true
  },
  "impersonator_id": "key_test_sk_demo123_v3",
  "session_id": "ses_imp_1785967693080143764"
}
```

### 2. Exit Impersonation (`POST /v1/client/auth/impersonate/exit`)
```bash
$ curl -i -X POST -H "Authorization: Bearer <impersonation_jwt>" \
  -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  http://localhost:8080/v1/client/auth/impersonate/exit
```
**Response (200 OK)**:
```json
{
  "impersonated_id": "usr_vanilla_007",
  "impersonator_id": "key_test_sk_demo123_v3",
  "message": "impersonation session exited successfully"
}
```

---

## Security Audit & Attack Mitigation Log

| Attack Vector / Test | Payload / Input | Response Status | Security Defense Execution |
| :--- | :--- | :--- | :--- |
| **Unauthenticated Impersonation** | `POST /v1/admin/users/:id/impersonate` (No `sk_`) | `401 Unauthorized` | Blocked by admin auth middleware |
| **Missing Admin Step-Up** | Initiate impersonation when `require_step_up_auth: true` | `400 Bad Request` | Step-up re-authentication enforced (`admin_step_up_required`) |
| **Non-Existent User IDOR** | Impersonating `usr_fake_9999` | `404 Not Found` | Target user existence check |
| **User Opt-In Enforcement** | Impersonating user with `support_access_enabled: false` | `403 Forbidden` | Policy opt-in check (`user_opt_in_required`) |
| **Policy Validation** | Setting `max_duration_minutes: 120` | `422 Unprocessable Entity` | Policy bound check (`must be between 1 and 60 minutes`) |
| **Impersonation Exit** | `POST /v1/client/auth/impersonate/exit` | `200 OK` | Validates impersonation JWT claims & clears context |

*Last Verified*: `2026-08-06` — live `curl` attack suite against running server.
