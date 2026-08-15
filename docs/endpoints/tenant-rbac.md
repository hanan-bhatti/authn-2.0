# Endpoint Specification: Role-Based Access Control (`/v1/tenant/roles`, `/v1/admin/users/:id/roles`, `/v1/client/user/permissions`)

## Overview
* **Routes**:
  * `POST /v1/tenant/roles` — Create custom RBAC role with permissions
  * `GET /v1/tenant/roles` — List all active roles and permissions for tenant
  * `PUT /v1/tenant/roles/:role_id/permissions` — Update permission list for role
  * `POST /v1/admin/users/:user_id/roles` — Assign role to user
  * `DELETE /v1/admin/users/:user_id/roles/:role_slug` — Revoke role from user
  * `GET /v1/client/user/permissions` — Evaluate active user's roles and permissions
* **HTTP Methods**: `POST`, `GET`, `PUT`, `DELETE`
* **Purpose**: Fine-grained Role-Based Access Control (RBAC) engine. Handles regex format validation for permission strings (`resource:action` or `domain:resource:action`), restricts illegal action verbs, prevents privilege escalation via policy bounds, and records immutable audit logs.

---

## Authentication & Access Control
* **Tenant & Admin Endpoints (`/v1/tenant/roles`, `/v1/admin/*`)**: Require Secret Key (`X-Authn-Secret-Key: sk_<env>_<hash>`) or Console Admin JWT with `tenant_admin` role.
* **Client Permission Endpoint (`/v1/client/user/permissions`)**: Requires valid Access Token JWT (`Authorization: Bearer <jwt>`) and Publishable Key (`X-Authn-Publishable-Key`).

---

## Permission String Syntax Rules
Permissions are strictly validated against `^[a-z0-9_]+:([a-z0-9_]+|\*)(:([a-z0-9_]+|\*))?$` and valid action verbs (`read`, `write`, `create`, `update`, `delete`, `revoke`, `manage`, `execute`, `*`):
* `users:read` — Read access on users resource
* `posts:create` — Create access on posts resource
* `org:billing:manage` — Namespace scoped manage permission
* `*` — Super-admin wildcard

---

## Request & Response Examples

### 1. Create Role (`POST /v1/tenant/roles`)
```json
{
  "name": "Content Manager",
  "slug": "content_manager",
  "description": "Manages articles and media",
  "permissions": ["posts:create", "posts:read", "posts:update"]
}
```
**Response (201 Created)**:
```json
{
  "id": "rol_a87d51ff-021",
  "tenant_id": "tnt_00000000000000000000000000000001",
  "name": "Content Manager",
  "slug": "content_manager",
  "description": "Manages articles and media",
  "created_by_user_id": "admin_system",
  "created_at": "2026-08-06T02:43:11.239Z",
  "updated_at": "2026-08-06T02:43:11.239Z"
}
```

### 2. Evaluate User Permissions (`GET /v1/client/user/permissions`)
```bash
$ curl -i -X GET -H "Authorization: Bearer <jwt>" \
  -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  http://localhost:8080/v1/client/user/permissions
```
**Response (200 OK)**:
```json
{
  "user_id": "usr_vanilla_007",
  "roles": [
    "content_manager"
  ],
  "permissions": [
    "posts:create",
    "posts:delete",
    "posts:read",
    "posts:update"
  ]
}
```

---

## Security Audit & Attack Mitigation Log

| Attack Vector / Test | Payload / Input | Response Status | Security Defense Execution |
| :--- | :--- | :--- | :--- |
| **Unauthenticated Creation** | `POST /v1/tenant/roles` (No `sk_`) | `401 Unauthorized` | Blocked by admin auth middleware |
| **SQL Injection Attack** | `"permissions":["users:read' OR 1=1; DROP TABLE users; --"]` | `422 Unprocessable Entity` | Regex validator rejected invalid format |
| **XSS Injection Attack** | `"permissions":["<script>alert(1)</script>:read"]` | `422 Unprocessable Entity` | Regex validator rejected invalid syntax |
| **Invalid Action Verb** | `"permissions":["users:exploit"]` | `422 Unprocessable Entity` | Rejected invalid verb `'exploit'` |
| **Privilege Escalation** | Assign `"users:write"` to `"viewer"` role | `422 Unprocessable Entity` | Blocked by `ValidatePermissionsAgainstPolicy` |
| **Duplicate Slug Attack** | Creating existing `"content_manager"` slug | `409 Conflict` | Unique constraint enforcement |
| **Non-existent Role IDOR** | Assign `"non_existent_role"` to user | `404 Not Found` | Entity existence verification |
| **Role Assignment** | Assign `"content_manager"` to `usr_vanilla_007` | `200 OK` | User-role junction record created + audit log |
| **Client Evaluation** | `GET /v1/client/user/permissions` | `200 OK` | Evaluates assigned roles & resolves permissions |
| **Role Revocation** | `DELETE /v1/admin/users/:id/roles/:slug` | `200 OK` | User-role junction record purged + audit log |

*Last Verified*: `2026-08-06` — live `curl` injection attack suite against running server.
