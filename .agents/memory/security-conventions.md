# Security & Permission Conventions

## 1. Mandatory Endpoint Permission Guarding
Whenever ANY new API endpoint is created in the engine (Client, Admin, or Tenant surface):
1. **Explicit Permission Assignment**: The endpoint MUST be assigned a standardized permission string following the `resource:action` format (e.g. `webhooks:write`, `orgs:delete`, `impersonate:create`).
2. **Upfront Interception**: The route handler MUST be wrapped with `rbac.RequirePermission(svc, "resource:action")` or `rbac.RequireRole(svc, "role_slug")` so permissions are evaluated **BEFORE** executing any business logic or database operations.
3. **Permission Catalog & API Spec Updates**: The new permission string MUST be added to the RBAC permission catalog and documented in [`docs/03-API-SPECIFICATION.md`](../../docs/03-API-SPECIFICATION.md).

## 2. Immutable Security Audit Trail
Every security-sensitive operation (role creation, permission modification, role assignment, session revocation, policy changes) MUST trigger an immutable `AuditLog` entry detailing:
- `actor_id` / `user_id` (who made the change)
- `target_id` / `target_user_id` (whose access was changed)
- `event_type` and `metadata` (what permissions/roles were modified)
- `timestamp`, `ip_address`, and `user_agent`.

## 3. Privilege Escalation & Lockout Prevention
- **At Least One Active Owner Rule**: The system strictly forbids revoking the `owner` role or removing permissions from the last active Owner account in a tenant to prevent admin lockout.
- **Immutable System Roles**: Built-in system roles (`owner`, `tenant_admin`) cannot be deleted or stripped to 0 permissions.
