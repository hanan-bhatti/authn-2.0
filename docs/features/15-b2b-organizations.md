# Feature Specification: FR-15 B2B Organizations & Team Member Invitations

## 1. Overview

**FR-15: B2B Organizations & Team Member Invitations** provides multi-tenant workspace hierarchy and team management capabilities for Authn Platform. It enables B2B SaaS applications to group users into Organizations (`org_...`) under a Tenant (`tnt_...`), manage org-scoped roles/permissions, and handle cryptographically secure 7-day single-use team member invitations.

---

## 2. Architecture & Data Model

The organization system relies on three Ent ORM schemas in `apps/auth-engine/ent/schema`:

- [`organization.go`](file:///home/hanan-bhatti/authn/apps/auth-engine/ent/schema/organization.go): Workspace entity (`id`: `org_...`, `tenant_id`, `name`, `slug`, `logo_url`, `metadata` JSON).
- [`org_member.go`](file:///home/hanan-bhatti/authn/apps/auth-engine/ent/schema/org_member.go): Membership join table (`id`: `mem_...`, `organization_id`, `user_id`, `role_id`, `assigned_by_user_id`).
- [`org_invitation.go`](file:///home/hanan-bhatti/authn/apps/auth-engine/ent/schema/org_invitation.go): Pending invitations (`id`: `inv_...`, `organization_id`, `email`, `role_id`, `invitation_token`, `status`: `pending` | `accepted` | `expired`, `expires_at`).

---

## 3. Validation Bounds & Limits

| Attribute | Validation / Limit Bound |
| :--- | :--- |
| **Organization Name** | Min 2, Max 100 characters. |
| **Organization Slug** | Min 2, Max 50 lowercase alphanumeric chars/hyphens. Auto-derived if empty. Unique per tenant `(tenant_id, slug)`. |
| **Logo URL** | Valid URL format, Max 2048 characters. |
| **Invitation Token** | Cryptographically random 32-byte hex string (`crypto/rand`). Single-use. |
| **Invitation Expiration** | Default 168 hours (7 days). Min 1 hour, Max 720 hours (30 days). |
| **Pagination Limit** | Default 20, Max 100. |

---

## 4. API Endpoints

### Client Endpoints (`/v1/client/...`)
*Requires Publishable Key `pk_...` and User Bearer JWT*

- `POST /v1/client/organizations` — Create organization (creator auto-assigned `org_admin`).
- `GET /v1/client/organizations` — List active organizations for the authenticated user.
- `GET /v1/client/organizations/:orgId` — Get organization details.
- `PATCH /v1/client/organizations/:orgId` — Update organization name, logo, metadata.
- `DELETE /v1/client/organizations/:orgId` — Delete organization.
- `GET /v1/client/organizations/:orgId/members` — List organization members.
- `POST /v1/client/organizations/:orgId/members` — Add member directly to organization.
- `PATCH /v1/client/organizations/:orgId/members/:userId` — Update member role.
- `DELETE /v1/client/organizations/:orgId/members/:userId` — Remove member from organization.
- `POST /v1/client/organizations/:orgId/invitations` — Send team invitation token via email.
- `GET /v1/client/organizations/:orgId/invitations` — List pending invitations.
- `DELETE /v1/client/organizations/:orgId/invitations/:invitationId` — Revoke pending invitation.
- `POST /v1/client/invitations/accept` — Accept invitation via 32-byte token.

### Tenant Admin Endpoints (`/v1/tenant/...`)
*Requires Secret Key `sk_...` or `tenant_admin` JWT*

- `GET /v1/tenant/organizations` — Admin list all organizations in tenant.
- `GET /v1/tenant/organizations/:orgId` — Admin get organization details.
- `POST /v1/tenant/organizations` — Admin create organization.
- `DELETE /v1/tenant/organizations/:orgId` — Admin delete organization.

---

## 5. Webhooks & Audit Events

Every organization action records an immutable audit log entry and dispatches real-time webhooks:

- `org.created`
- `org.updated`
- `org.deleted`
- `org.member_joined`
- `org.member_removed`
- `org.invitation_sent`
- `org.invitation_revoked`
- `org.invitation_accepted`

---

## 6. Verification

Run automated Go tests:
```bash
go test -v ./internal/org/...
```

Or open [`org-proof.html`](file:///home/hanan-bhatti/authn/org-proof.html) in any web browser to execute live HTTP verification requests.
