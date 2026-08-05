# Feature Spec 13: Role-Based Access Control (RBAC) & Fine-Grained Permissions

**Feature Code**: FR-12  
**Tier**: Core Authentication & Security Layer  
**Status**: Production Implemented & Verified (100% Postman & Integration Test Pass)  

---

## 1. Executive Summary

Authn provides a enterprise-grade **Role-Based Access Control (RBAC) & Fine-Grained Permission Engine** with:
1. **User-Friendly Role Models**: Built-in system roles (`Platform Owner`, `Security Administrator`, `Developer`, `Support Manager`, `Auditor`) and custom tenant roles with human-readable names and system slugs.
2. **3-Step Permission Validation**: Bulletproof regex validation (`resource:action`), verb constraints (`read`, `write`, `create`, `update`, `delete`, `revoke`, `manage`, `execute`), and namespace checking to prevent invalid strings (e.g. `banana-permission:write`).
3. **Configurable Policy Safety Guards (`RolePermissionPolicy`)**: Configurable policy rules preventing privilege escalation (e.g. restricting `keys:write` or `system:*` from lower-tier roles) while empowering Tenant Admins to customize rules.
4. **Immutable Security Audit Trail**: Every role creation, permission modification, role assignment, and role revocation records an immutable `AuditLog` entry detailing:
   - `who` (actor user ID / admin key)
   - `changed_whose` (target user ID)
   - `what_changed` (role name, old vs new permissions)
   - `timestamp`, `ip_address`, and `user_agent`.

---

## 2. System Role Specifications

| Role Name | System Slug | Scope | Default Permissions | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Platform Owner** | `owner` / `tenant_admin` | Global | `["*"]` | Unrestricted super-admin control over tenant, policies, API keys, and team members. |
| **Security Administrator** | `security_admin` | Global | `["security:*", "sessions:*", "audit:read"]` | Configures security policies, 2FA rules, session revocations, and audit logs. |
| **Developer / API Admin** | `developer` | Global | `["keys:*", "webhooks:*", "social:*", "oauth:*"]` | Manages API keys, webhooks, social providers, and OAuth client settings. |
| **Support Manager** | `support_admin` | Global | `["users:*", "sessions:read", "impersonate:create"]` | Manages user directory, triggers password resets, and performs support impersonation. |
| **Auditor / Read-Only** | `auditor` | Global | `["*:read"]` | Read-only access to tenant metrics, user lists, active sessions, and security audit logs. |

---

## 3. REST API Endpoint Index

### 3.1 Tenant Admin Endpoints (`sk_test_...` or Console Admin JWT)
- `GET /v1/tenant/roles?tenant_id=tnt_...` — List all roles and assigned permission strings for tenant.
- `POST /v1/tenant/roles` — Create a new custom role with validated permission format and policy checks.
- `PUT /v1/tenant/roles/:role_id/permissions` — Replace role permissions with audit logging.
- `POST /v1/admin/users/:user_id/roles` — Assign a role to a target user with audit log recording who assigned it.
- `DELETE /v1/admin/users/:user_id/roles/:role_slug` — Revoke a role from a user with audit log recording who revoked it.

### 3.2 Client Endpoints (`pk_test_...` + User Access Token JWT)
- `GET /v1/client/user/permissions` — Retrieve accumulated roles and fine-grained permission strings for current user.
