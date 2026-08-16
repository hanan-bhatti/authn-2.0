# Hosted Platform Control Plane — Tenant Provisioning (`/v1/platform/tenants`)

**Surface**: Hosted control plane
**Credential**: End-user JWT belonging to the platform tenant — never an API key
**Verified**: `2026-08-16` — 14 middleware unit cases, 2 handler unit cases and 8 integration tests, each regression assertion confirmed against a deliberately mutated build

## Overview

The control plane is how a SaaS customer gets a tenant of their own. It is a tenant of itself: one reserved **platform tenant** whose end users are the customers, signing up and signing in through the ordinary `/v1/client/auth/*` stack — password, 2FA, sessions, email verification, all of it. Having done that, they present the resulting session here and receive a tenant, its first application, its system roles and its first API key pair.

Two consequences follow from that arrangement, and they explain most of the behaviour below:

1. **The credential is a person, not a machine.** Provisioning attributes ownership to a human, so an API key — which names a tenant — cannot authenticate here at all. See [Refusal ladder](#refusal-ladder).
2. **Anyone can sign up into the platform tenant.** Its publishable key ships in the console's browser bundle; that is what self-serve means. So membership alone is not sufficient — a verified email address is the barrier between an arbitrary address and a tenant-minting credential.

## Configuration

Both variables are required together; setting one without the other is a startup validation error.

| Variable | Meaning |
| :--- | :--- |
| `PLATFORM_TENANT_ID` | The tenant identifier of the control plane. Must begin with `tnt_`, and must not be `tnt_default` (that tenant is created by the seeder for local development and is not a control plane). |
| `PLATFORM_TENANT_SLUG` | The slug the control plane occupies. Added to the provisioner's reserved list so no customer tenant can claim it. |

**Leaving both unset disables the surface entirely.** Route registration is skipped, so `/v1/platform/tenants` returns `404` from the router with nothing mounted behind it — which is the correct posture for a self-hosted OSS deployment that has no control plane and no business advertising one.

---

## `POST /v1/platform/tenants` — Provision a tenant

### Request

```http
POST /v1/platform/tenants HTTP/1.1
Host: api.authn.example.com
Authorization: Bearer <platform_session_access_token>
Content-Type: application/json

{
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "environment": "test",
  "application_name": "Acme Web",
  "redirect_uris": ["https://app.acme.example.com/callback"],
  "allowed_cors_origins": ["https://app.acme.example.com"]
}
```

The session may also arrive in the `authn_access_token` cookie (or the legacy `access_token` cookie), since the console is a browser application and that is how its session is normally held.

| Field | Required | Notes |
| :--- | :--- | :--- |
| `name` | yes | Display name. 1–200 characters after trimming. |
| `slug` | no | Derived from `name` when omitted. 3–63 characters of lowercase letters, digits and interior hyphens. |
| `environment` | no | `test` or `live`. Defaults to `test`. Sets the environment of the first application and key pair. |
| `application_name` | no | Labels the first application. Defaults to `Default`. At most 200 characters. |
| `redirect_uris` | no | Initial exact-match OAuth redirect allowlist. At most 20 entries, each at most 2048 characters. |
| `allowed_cors_origins` | no | Initial browser-origin allowlist. Same bounds. |

**There is no owner field, and supplying one has no effect.** `owner_user_id`, `user_id`, `tenant_id` and similar keys are ignored: ownership is attributed to the caller the guard resolved from the token. Accepting an identifier from the body would let any platform member provision a tenant into another member's account, so the payload struct simply has nowhere to put one.

### `201 Created`

```json
{
  "tenant": {
    "id": "tnt_9f2c4a7e1b3d5f80a6c2e4b8d0f1a3c5",
    "name": "Acme Corporation",
    "slug": "acme-corp",
    "environment": "test"
  },
  "application": {
    "id": "app_5d1b8f3a9c7e2064b1d3f5a7c9e0b2d4",
    "name": "Acme Web"
  },
  "roles_installed": 4,
  "publishable_key": "pk_test_a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "secret_key": "sk_test_0f9e8d7c6b5a49382716f5e4d3c2b1a0",
  "message": "store the secret key now: it is shown only in this response and only its hash is retained. the publishable key is safe to ship to a browser; the secret key must never leave a server."
}
```

**The raw keys appear here and nowhere else.** Only their hashes are stored, and neither is written to a log line at any level. A caller who loses the secret key mints a replacement through `POST /v1/admin/keys/`; there is no endpoint that reads an existing one back.

The two keys are not interchangeable and the distinction is load-bearing:

- `publishable_key` is designed to be public. It belongs in a browser bundle, and in a Next.js application in a `NEXT_PUBLIC_`-prefixed variable.
- `secret_key` carries the tenant's entire admin surface. It must never appear in a `NEXT_PUBLIC_` variable, a client component, or anything that reaches a browser.

### Error responses

| Status | `code` | Condition |
| :--- | :--- | :--- |
| `400` | `validation_failed` | `name` missing or over 200 characters; `application_name` over 200; a slug that is not 3–63 lowercase alphanumerics with interior hyphens; `environment` other than `test`/`live`; a reserved slug; an allowlist over 20 entries or an entry over 2048 characters. |
| `400` | `invalid_body` | The body is not parseable JSON. |
| `409` | `already_exists` | The slug is taken. See [Idempotency](#idempotency-is-deliberately-not-exposed). |
| `429` | `rate_limited` | The caller has exhausted their provisioning budget. Carries `Retry-After` in seconds. |
| `503` | `service_unavailable` | The rate limiter is unreachable, so the budget cannot be enforced. Fails closed. |

Plus the whole [refusal ladder](#refusal-ladder), which applies to both routes.

### Reserved slugs

Refused regardless of configuration: `platform`, `admin`, `system`, `default`, `internal`, `authn`, `console`, `api`, `www`. `PLATFORM_TENANT_SLUG` is added to that list at wiring time — which slug the control plane occupies is deployment configuration, and the provisioning package must not have to know it.

A reserved slug produces `400 validation_failed`, not `409`: it was never available, as distinct from having been claimed by someone.

### Provisioning budget

Metered per **platform user**, at **5 tenants** per the rate limiter's configured window.

The key is the user rather than the IP because signing up is free — an IP budget alone is defeated by one more signup from the same machine, while a per-user budget costs an attacker a fresh *verified* email address per bucket. Five is generous for the legitimate shape of the request (a customer sets up one tenant, occasionally a second for staging) while bounding what one signup can spend of the database. The window belongs to the limiter, so a deployment tunes the period once and every metered operation follows it.

### Idempotency is deliberately not exposed

The underlying provisioning service *is* idempotent by slug: asked twice for `acme-corp`, it returns the existing tenant and mints no new keys. That is exactly right for its original caller — a container entrypoint re-running its own provisioning on restart must not create a second tenant every boot.

On a public endpoint the same behaviour is a vulnerability. A caller who guessed a slug would be handed the tenant that already owns it, and the ownership row written immediately afterwards would give them a durable claim on somebody else's data. So the handler checks for that outcome and converts it into `409 already_exists`. The slug is simply unavailable; nothing about the existing tenant is disclosed beyond that.

### If ownership recording fails

The tenant is created before the ownership row. Should that second write fail, the caller gets `500` even though the tenant exists — the least bad of the available outcomes. Reporting success would hand out keys for a tenant that appears in nobody's list and can never be administered. The orphan is visible in the `tenants` table and its slug is now taken, so a retry with the same slug returns `409` rather than silently repairing itself, which is the signal an operator needs.

---

## `GET /v1/platform/tenants` — List owned tenants

### Request

```http
GET /v1/platform/tenants HTTP/1.1
Host: api.authn.example.com
Authorization: Bearer <platform_session_access_token>
```

### `200 OK`

```json
{
  "tenants": [
    {
      "id": "tnt_9f2c4a7e1b3d5f80a6c2e4b8d0f1a3c5",
      "name": "Acme Corporation",
      "slug": "acme-corp",
      "role": "owner",
      "acquired_at": "2026-08-16T09:14:22Z"
    }
  ],
  "count": 1
}
```

Newest first. `role` is the caller's relationship to the tenant (`owner` today). `acquired_at` is when the ownership record was written, which for an owner is when they provisioned it. A record pointing at a tenant that has since been deleted is omitted rather than reported with empty fields.

**Scoped to the calling user, twice over.** Ownership rows are themselves tenant-owned, and their `tenant_id` is the *platform* tenant rather than the tenant they describe — so the privacy interceptor confines them to the control plane exactly as it confines any other row, which is what stops one hosted customer reading another's ownership records. The query then narrows that to the one owner. Resolving the customer tenants those rows point at requires a privacy bypass (a scoped `Tenant` query would be rewritten to `AND id = <platform tenant>` and return nothing), and that bypass is safe only because of the order: authorization runs first, and the ID set handed to it comes from rows the caller demonstrably owns. An ID set derived from request input must never be passed there.

---

## Refusal ladder

Both routes sit behind the same guard. The checks run in order, each answering before the next is reached.

| Order | Status | `code` | Condition | Why it is distinct |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `404` | `not_found` | No platform tenant configured. | A deployment hosting no control plane should not disclose that the route exists. `401` or `403` would confirm the surface is there. Registration is normally skipped entirely, so this is the backstop for a miswiring. |
| 2 | `503` | `service_unavailable` | The account lookup is not wired. | The verified-email check is not optional. A guard that cannot perform it admits nobody, making a wiring mistake an outage rather than an open door. |
| 3 | `401` | `unauthorized` | An API key in any position — `X-Authn-Secret-Key`, a `sk_`/`pk_` bearer, or a `sk_` in the access-token cookie. | A `pk_` is public; an `sk_` carries a tenant's whole admin surface. Neither establishes which human is asking. Refusing them *as keys* also means the caller is told to sign in rather than handed "invalid token" for a credential that is perfectly valid elsewhere, and the key never reaches a verifier a later refactor might make more forgiving. |
| 4 | `401` | `unauthorized` | No token at all. | |
| 5 | `401` | `invalid_token` | Unverifiable, malformed, expired, or revoked token. Revocation covers sign-out, impersonation exit and forced logout. | |
| 6 | `403` | `impersonation_blocked` | The token is marked impersonated. | An operator impersonating a customer holds a token naming that customer. Admitting it would turn a read-only support session into a credential that provisions tenants owned by the person being supported. |
| 7 | `403` | `tenant_mismatch` | The token belongs to another tenant. | A customer's own end-user token is a perfectly valid JWT signed by this deployment; what disqualifies it is which tenant it names. This is the check that keeps the control plane from being reachable by every user of every hosted tenant. The subject is never looked up. |
| 8 | `401` | `invalid_token` | The token names no subject, or an account that no longer exists. | A session naming a deleted account is not recoverable by any action the caller can take, so it is invalidated rather than reported as a permissions problem. |
| 9 | `403` | `email_verification_required` | The address is unverified. | A live session that has not finished signing up. Fixed by clicking the link in the verification email — a different remedy from either neighbour, which is why the three lookup outcomes are not collapsed. |
| 10 | `503` | `service_unavailable` | The lookup itself failed. | Fails closed, unlike the 2FA validator in `RequireAdminAuth` — that one lets an operator through on a database blip because locking every administrator out of the console is worse. Here the guarded operations write to the same database that just failed, so admitting the request buys nothing and would let an unverified address through precisely when the check cannot see. |

On success the guard installs the platform tenant on the privacy context — taken from configuration, not from the claim it was just compared against, so a future edit to that comparison cannot widen a request's reach — and puts the caller's identity on the request locals. The account lookup runs *after* the scope is installed, so it reads the platform tenant's own user rows and cannot be answered by a same-numbered row belonging to another tenant. Handlers read the tenant and the user from those locals and never from the request.

### Not `RequireAdminAuth`

The obvious guard is the wrong one. `RequireAdminAuth` demands `role=tenant_admin`, and the first-admin slot is single-shot per tenant — so on the platform tenant exactly one human on the whole deployment would ever qualify, and self-serve signup would be dead on arrival. Membership of the platform tenant is the credential here instead, which makes the tenant check authentication rather than authorization.

---

## Verification

| Layer | File | Covers |
| :--- | :--- | :--- |
| Middleware unit | `internal/middleware/platform_auth_test.go` | All ten rungs of the refusal ladder, cookie delivery, the resolved identity, and that the privacy scope is installed before the account lookup runs. |
| Handler unit | `internal/platform/handler_test.go` | A nil guard mounts nothing (and the same paths resolve behind a real guard, so the `404` is not a typo); an unconfigured slug reserves nothing rather than reserving the empty string. |
| Integration | `test/platform_tenants_test.go` | End-to-end provisioning through the real guard, ending by registering a user into the new tenant with the returned publishable key; ownership filed under the control plane; `409` on a taken slug with no ownership row written; listing confined to the caller; owner fields in the body ignored; reserved slugs; payload validation; and non-platform credentials refused. |

Every assertion in those files was confirmed against a mutated build — the check it guards was removed or inverted and the test was required to fail. Two did not on the first pass: dropping the `sk_` prefix check still produced `401` from the JWT parser downstream, and reserving the configured slug was masked because the harness had been using `platform`, which the built-in list already covers. Both are why the assertions above name error codes rather than status codes alone, and why the harness reserves `authn-console`.
