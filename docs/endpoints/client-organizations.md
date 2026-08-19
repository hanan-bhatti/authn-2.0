# Endpoint Specification: B2B Organizations & Team Invitations (`/v1/client/organizations/*` & `/v1/tenant/organizations/*`)

## Overview
* **Routes**:
  * `POST /v1/client/organizations` — Create organization workspace
  * `GET /v1/client/organizations` — List organizations for user
  * `GET /v1/client/organizations/:orgId` — Get organization details
  * `PATCH /v1/client/organizations/:orgId` — Update organization details
  * `DELETE /v1/client/organizations/:orgId` — Delete organization
  * `GET /v1/client/organizations/:orgId/members` — List organization members
  * `POST /v1/client/organizations/:orgId/members` — Add member to organization
  * `POST /v1/client/organizations/:orgId/invitations` — Create team invitation
  * `POST /v1/client/invitations/accept` — Accept team invitation using single-use token
  * `GET /v1/tenant/organizations` — List tenant organizations (Admin)
  * `DELETE /v1/tenant/organizations/:orgId` — Delete organization with cascading member/invitation purge (Admin)
* **HTTP Methods**: `POST`, `GET`, `PATCH`, `DELETE`
* **Purpose**: Multi-tenant B2B organization workspace management engine. Supports URL-safe slug validation, 32-byte cryptographic invitation tokens with single-use replay defense, cascading deletion of associated members & invitations, and audit logging.

---

## Authentication & Access Control
* **Client Endpoints (`/v1/client/organizations/*`)**: Require Publishable Key (`X-Authn-Publishable-Key: pk_<env>_<hash>`) and User Context.
* **Tenant Admin Endpoints (`/v1/tenant/organizations/*`)**: Require Secret Key (`X-Authn-Secret-Key: sk_<env>_<hash>`) or Console Admin JWT with `tenant_admin` role.
* **Environment**: the `<env>` segment of the presented key selects it, and no request field can override that. A workspace is created in the environment of the key that created it and is visible only to keys in that environment — a `pk_test_` caller neither lists nor reads a live workspace, and a `sk_test_` caller cannot delete one. Cross-environment reads and deletes answer `404`, not `403`, so an ID is never confirmed to a credential that cannot use it.

---

## Environment Scope

| Property | Behaviour |
| :--- | :--- |
| Response field | Every organization response carries `environment`: `test` or `live`. |
| Slug uniqueness | Unique per `(tenant, environment)`. The same slug is claimable once in test and once in live, so a team rehearses under the slug it means to ship. |
| Volume | A test credential is refused with `403 test_quota_exceeded` once the tenant holds `TEST_MAX_ORGANIZATIONS` test workspaces. Live workspaces neither count against that ceiling nor are bounded by it. |
| Members and invitations | Confined through their parent organization, so a roster never outlives its workspace's environment. |
| SAML connections | The exception: a connection carries its own `environment` so it can be promoted from a trial into production without being re-registered at the identity provider. See [`saml-idp-config.md`](saml-idp-config.md). |

---

## Request & Response Examples

### 1. Create Organization (`POST /v1/client/organizations`)
```json
{
  "name": "Acme Corporation",
  "slug": "acme-corp-101",
  "logo_url": "https://acme.local/logo.png"
}
```
**Response (201 Created)**:
```json
{
  "id": "org_9038723e-062",
  "tenant_id": "tnt_00000000000000000000000000000001",
  "environment": "test",
  "name": "Acme Corporation",
  "slug": "acme-corp-101",
  "logo_url": "https://acme.local/logo.png",
  "created_at": "2026-08-06T03:05:29.432Z"
}
```

### 2. Create Team Invitation (`POST /v1/client/organizations/:orgId/invitations`)
```json
{
  "email": "invited.dev@authn.local",
  "role_id": "editor",
  "expires_hrs": 48
}
```
**Response (201 Created)**:
```json
{
  "id": "inv_aebcf1c1-c66",
  "organization_id": "org_9038723e-062",
  "email": "invited.dev@authn.local",
  "role_id": "role_editor",
  "invitation_token": "a6449b0d2c322041d58c6f769dac4d7ee90fc5dd5ea9ca67dfaab7c9a182bfb0",
  "status": "pending",
  "expires_at": "2026-08-08T03:05:29.480Z",
  "created_at": "2026-08-06T03:05:29.480Z"
}
```

### 3. Accept Team Invitation (`POST /v1/client/invitations/accept`)
```json
{
  "invitation_token": "a6449b0d2c322041d58c6f769dac4d7ee90fc5dd5ea9ca67dfaab7c9a182bfb0"
}
```
**Response (200 OK)**:
```json
{
  "member": {
    "id": "mem_8517007d-937",
    "organization_id": "org_9038723e-062",
    "user_id": "usr_44941592-6b1",
    "role_id": "role_editor"
  },
  "message": "invitation accepted successfully"
}
```

### 4. Token Replay Attack Attempt
```json
{
  "invitation_token": "a6449b0d2c322041d58c6f769dac4d7ee90fc5dd5ea9ca67dfaab7c9a182bfb0"
}
```
**Response (400 Bad Request)**:
```json
{
  "error": "invitation has already been accepted"
}
```

---

## Security Audit & Attack Mitigation Log

| Attack Vector / Test | Payload / Input | Response Status | Security Defense Execution |
| :--- | :--- | :--- | :--- |
| **Unauthenticated Org Creation** | `POST /v1/client/organizations` (No `pk_`) | `401 Unauthorized` | Blocked by publishable key middleware |
| **XSS / Invalid Slug Attack** | `"slug":"invalid slug with spaces!"` | `400 Bad Request` | Slug format validation (`2-50 lowercase alphanumeric or hyphens`) |
| **Duplicate Slug Attack** | Re-creating existing slug `"acme-corp"` | `400 Bad Request` | Unique constraint check per tenant and environment |
| **Cross-Environment Read** | `GET /v1/tenant/organizations/:testOrgId` with `sk_live_` | `404 Not Found` | Privacy interceptor predicate on `environment` |
| **Invitation Token Replay** | Replaying accepted 32-byte hex token | `400 Bad Request` | Single-use consumption check (`invitation has already been accepted`) |
| **Cascading Org Deletion** | `DELETE /v1/tenant/organizations/:id` | `200 OK` | Cascading deletion of `OrgMember` + `OrgInvitation` records |
| **Access Deleted Org** | `GET /v1/client/organizations/:deletedId` | `404 Not Found` | Entity query returns not found |

*Last Verified*: `2026-08-06` — live `curl` attack suite against running server.
