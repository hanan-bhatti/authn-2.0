# Real-Time Outgoing Event Webhooks (FR-13)

**Feature Status**: Completed & Verified  
**Package**: `apps/auth-engine/internal/webhook`  
**License**: GNU AGPLv3 — Authn Platform Authors  

---

## 1. Overview & Architecture

The **Outgoing Event Webhook Engine** delivers real-time HTTP event notifications to developer endpoints whenever critical identity, security, session, or role changes occur.

### Security Guarantees
1. **HMAC-SHA256 Payload Signature (`X-Authn-Signature`)**: Every webhook payload is signed with the endpoint's unique secret (`whsec_...`) using HMAC-SHA256. Header format: `X-Authn-Signature: t=<timestamp>,v1=<hex_hmac>`.
2. **Replay Protection**: Receiver verification code compares timestamp `t` against current time (rejecting requests older than 5 minutes) and uses constant-time string comparison (`hmac.Equal`).
3. **Secret Collision Prevention**: Secrets use `whsec_<48_hex_chars>`. A SHA-256 hash (`secret_key_hash`) is indexed with a `UNIQUE` constraint in the database, preventing secret collisions across endpoints.
4. **AES-256-GCM Encryption**: Webhook secrets are encrypted at rest using AES-256-GCM (`AUTHN_ENCRYPTION_KEY`). Plaintext secrets are displayed **ONCE** upon endpoint creation or secret rotation.
5. **Asynchronous Worker Pool**: Dispatches webhooks asynchronously via a 5-goroutine worker pool with a 1,000-buffered task channel and a strict 5-second HTTP timeout.
6. **Live Key Required to Write**: A write may name the `live` environment — or `all` — whichever key made it, so a test key able to register endpoints could still point live traffic at a destination of its choosing, repoint an entry to redirect a live event, or delete one to silence a live integration. `middleware.RequireLiveKey` therefore guards every route that changes the list or makes it emit a request, answering `403 Forbidden` with code `live_key_required`. Reads stay open to either key: seeing the other environment's configuration crosses nothing, changing it does.

### Environment Separation

Each endpoint carries `environment` — `test`, `live` or `all` — chosen at registration. The field is required and has no default, because an endpoint that silently defaulted would either miss the events its owner expected or deliver sandbox activity to a production subscriber. `POST /endpoints` answers `422 Unprocessable Entity` with code `validation_failed` when it is absent or unrecognised.

`Dispatcher.Dispatch(tenantID, environment, eventType, data)` carries the environment, and `Repository.GetActiveEndpointsForEvent` selects a tenant's active endpoints whose environment equals the event's, plus every endpoint set to `all`. A sandbox sign-up therefore never reaches a live-only receiver, and a live one never reaches a sandbox receiver.

Three properties make this hold in practice:

- **The event's environment comes from its subject, not from the caller.** Each dispatch site reads it off the row it just wrote or loaded — the organization, user or SAML connection. A tenant administrator holding a live key who edits a sandbox organization has produced a sandbox event, and reporting it as live would deliver it to production subscribers.
- **It is captured at enqueue time.** `Dispatch` is called on the request path but processed by a worker later, so `DispatchTask` carries the environment; there is no request context to read at delivery time.
- **Dispatch fails closed.** An event whose environment names neither `test` nor `live` is dropped with a warning rather than broadcast to both. `all` is an endpoint's subscription choice, never an event's origin.

The privacy interceptor deliberately does *not* narrow `webhook_endpoint` by environment (`internal/privacy/scope.go`). Doing so would hide every `all` endpoint from a test-scoped read and make the match above unreachable. Privacy enforces tenant isolation; the repository's explicit `Where` expresses routing.

---

## 2. Event Types & Format

### Currently Emitted
- `user.updated` — Profile changed
- `user.deleted` — Account deleted
- `password.changed` — Password reset or changed
- `user.impersonated` — Support session started
- `org.created`, `org.updated`, `org.deleted` — Organization lifecycle
- `org.member_joined`, `org.member_removed` — Membership changes
- `org.invitation_sent`, `org.invitation_revoked`, `org.invitation_accepted` — Invitation lifecycle
- `saml.connection_created`, `saml.connection_updated`, `saml.connection_deleted` — SSO connection lifecycle
- `saml.login_success` — SSO sign-in completed
- `ping` — Fired manually via `/ping`, never by system activity
- `*` — Wildcard, matches every event including ones added later

### Accepted But Not Yet Emitted
These names validate on subscription, so an integration can register for them today, but no code path raises them yet: `user.created`, `user.signup`, `user.login.success`, `user.login.failed`, `session.revoked`, `2fa.enabled`, `2fa.disabled`, `rbac.role.assigned`, `rbac.role.revoked`, `user.impersonation_exited`. A subscriber wanting sign-in or session activity should read the audit log until they are wired up.

### Standard Webhook Payload Format
```json
{
  "id": "evt_76708407-e98",
  "event": "org.created",
  "tenant_id": "tnt_demo123",
  "environment": "test",
  "timestamp": 1785895387,
  "data": {
    "organization_id": "org_1a2b3c",
    "name": "Acme Inc",
    "slug": "acme-inc"
  }
}
```

`environment` travels in the signed body rather than in a header, because the signature covers the serialised body only: a subscriber deciding whether to act on an event for real must be able to prove the value came from the engine. An endpoint set to `all` relies on this field to tell the two streams apart, and the delivery log records the same envelope, so a redelivery replays a sandbox event as a sandbox event.

---

## 3. REST API Endpoints

| Method | Endpoint | Description | Permission / Auth |
| :--- | :--- | :--- | :--- |
| `POST` | `/v1/admin/webhooks/endpoints` | Register new webhook endpoint | `webhooks:write` / Admin **Live** Secret Key |
| `GET` | `/v1/admin/webhooks/endpoints` | List all webhook endpoints for tenant | `webhooks:read` / Admin Secret Key |
| `GET` | `/v1/admin/webhooks/endpoints/:id` | Fetch specific webhook endpoint details | `webhooks:read` / Admin Secret Key |
| `PUT` | `/v1/admin/webhooks/endpoints/:id` | Update URL, description, environment, or subscribed events | `webhooks:write` / Admin **Live** Secret Key |
| `DELETE` | `/v1/admin/webhooks/endpoints/:id` | Delete endpoint and cascade delete child events | `webhooks:delete` / Admin **Live** Secret Key |
| `POST` | `/v1/admin/webhooks/endpoints/:id/ping` | Send immediate test ping event | `webhooks:write` / Admin **Live** Secret Key |
| `POST` | `/v1/admin/webhooks/endpoints/:id/rotate-secret` | Rotate signing secret key | `webhooks:write` / Admin **Live** Secret Key |
| `GET` | `/v1/admin/webhooks/deliveries` | List webhook delivery audit logs | `webhooks:read` / Admin Secret Key |
| `POST` | `/v1/admin/webhooks/deliveries/:id/redeliver` | Re-send a recorded delivery to its endpoint | `webhooks:write` / Admin **Live** Secret Key |

Rows marked **Live** are refused a `sk_test_` credential with `403 live_key_required`. Covered by `test/live_key_test.go`.

---

## 4. Input Validation & Strict Error Handling

1. **URL Validation**: Requires well-formed HTTPS scheme (allowing `http://localhost` or `http://127.0.0.1` in development mode).
2. **Environment Validation**: Requires `test`, `live` or `all`. Absent or unrecognised values are rejected with `422 Unprocessable Entity` and code `validation_failed`; nothing is guessed.
3. **Subscribed Events Validation**: Rejects empty array or invalid event strings with `422 Unprocessable Entity`.
4. **Cascade Deletion**: Deleting an endpoint (`DELETE /v1/admin/webhooks/endpoints/:id`) automatically deletes all child delivery logs (`WebhookEvent`) within an Ent transaction under standard request context.
