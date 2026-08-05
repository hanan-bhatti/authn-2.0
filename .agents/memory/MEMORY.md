# Memory Index

## Project
- [project] Always create a new dedicated branch for major code changes → project-conventions.md
- [project] AG Kit only supports Gemini CLI and Google Antigravity (not other AI coding tools) → project-conventions.md
- [project] Component metadata uses SemVer while toolkit releases use CalVer → tech-decisions.md
- [security] Mandatory upfront RBAC permission evaluation & audit logging on all new API endpoints → security-conventions.md

## Feature Status
- [fr12] ✅ DONE — RBAC engine fully implemented and verified (23/23 tests pass, commit 0b002b8)
- [fr13] ✅ DONE — Webhooks with tenant isolation, HMAC signing, async dispatch (security-proof.html verified)

## RBAC Design Decisions (FR-12)
- [rbac] Role slug is a real DB column with unique (tenant_id, slug) index — NOT a name alias
- [rbac] Role slug auto-derived from name (lowercase + underscores) if not provided by caller
- [rbac] GetUserRolesAndPermissions returns role.Slug (machine-readable), not role.Name (display)
- [rbac] First user created in any tenant automatically gets role=tenant_admin in JWT
- [rbac] Client endpoints (/v1/client/*) need BOTH pk_ key (tenant context) AND Bearer JWT (user identity)
- [rbac] Admin endpoints (/v1/tenant/*, /v1/admin/*) accept sk_... OR JWT with role=tenant_admin
- [rbac] Test proof: rbac-proof.html — 23 tests, uses Charlie (3rd user) for guard tests since Alice=tenant_admin

## Auth Engine Architecture
- [auth] Privacy interceptor is fail-closed — no silent no-ops on write operations
- [auth] SQLite DB at apps/auth-engine/authn.db (dev) — wipe and restart for schema changes
- [auth] Ent ORM code generation: go run entgo.io/ent/cmd/ent generate ./ent/schema
