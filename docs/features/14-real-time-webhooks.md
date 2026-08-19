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
6. **Live Key Required to Write**: An endpoint has no `environment` column. There is one list per tenant and the dispatcher delivers every event to all of it, so the list is live configuration whichever key wrote it — a test key repointing an entry would redirect a live event, and deleting one would silence a live integration. `middleware.RequireLiveKey` therefore guards every route that changes the list or makes it emit a request, answering `403 Forbidden` with code `live_key_required`. Reads stay open to either key: seeing the other environment's configuration crosses nothing, changing it does.

### Known Limitation: The Dispatcher Is Environment-Blind

`Dispatcher.Dispatch(tenantID, eventType, data)` takes no environment, and a `WebhookEndpoint` has no column to match one against. An event raised in the test environment — carrying a sandbox user's address — is delivered to the tenant's production receivers and is indistinguishable there from a live event.

A receiver that needs to tell them apart has to do it from the payload: `data` carries the acting user, and a test user's row has `environment = "test"`. The engine does not yet stamp the envelope itself.

Closing this properly means either an `environment` column on the endpoint plus a threaded environment through every `Dispatch` call site, or a decision that test events are not delivered at all. Both are feature-sized and change what existing receivers see, so neither is done here.

---

## 2. Event Types & Format

### Supported Event Types
- `user.created` — Fired on new user signup
- `session.revoked` — Fired on session revocation
- `2fa.enabled` — Fired when user enables a 2FA method
- `password.changed` — Fired on password reset/change
- `rbac.role.assigned` — Fired when user is assigned a role
- `ping` — Fired manually via `/ping` test endpoint
- `*` — Wildcard (matches all event types)

### Standard Webhook Payload Format
```json
{
  "id": "evt_76708407-e98",
  "event": "user.created",
  "tenant_id": "tnt_demo123",
  "timestamp": 1785895387,
  "data": {
    "user_id": "usr_1a2b3c",
    "email": "newuser@example.com",
    "created_at": "2026-08-05T07:00:00Z"
  }
}
```

---

## 3. REST API Endpoints

| Method | Endpoint | Description | Permission / Auth |
| :--- | :--- | :--- | :--- |
| `POST` | `/v1/admin/webhooks/endpoints` | Register new webhook endpoint | `webhooks:write` / Admin **Live** Secret Key |
| `GET` | `/v1/admin/webhooks/endpoints` | List all webhook endpoints for tenant | `webhooks:read` / Admin Secret Key |
| `GET` | `/v1/admin/webhooks/endpoints/:id` | Fetch specific webhook endpoint details | `webhooks:read` / Admin Secret Key |
| `PUT` | `/v1/admin/webhooks/endpoints/:id` | Update URL, description, or subscribed events | `webhooks:write` / Admin **Live** Secret Key |
| `DELETE` | `/v1/admin/webhooks/endpoints/:id` | Delete endpoint and cascade delete child events | `webhooks:delete` / Admin **Live** Secret Key |
| `POST` | `/v1/admin/webhooks/endpoints/:id/ping` | Send immediate test ping event | `webhooks:write` / Admin **Live** Secret Key |
| `POST` | `/v1/admin/webhooks/endpoints/:id/rotate-secret` | Rotate signing secret key | `webhooks:write` / Admin **Live** Secret Key |
| `GET` | `/v1/admin/webhooks/deliveries` | List webhook delivery audit logs | `webhooks:read` / Admin Secret Key |
| `POST` | `/v1/admin/webhooks/deliveries/:id/redeliver` | Re-send a recorded delivery to its endpoint | `webhooks:write` / Admin **Live** Secret Key |

Rows marked **Live** are refused a `sk_test_` credential with `403 live_key_required`. Covered by `test/live_key_test.go`.

---

## 4. Input Validation & Strict Error Handling

1. **URL Validation**: Requires well-formed HTTPS scheme (allowing `http://localhost` or `http://127.0.0.1` in development mode).
2. **Subscribed Events Validation**: Rejects empty array or invalid event strings with `422 Unprocessable Entity`.
3. **Cascade Deletion**: Deleting an endpoint (`DELETE /v1/admin/webhooks/endpoints/:id`) automatically deletes all child delivery logs (`WebhookEvent`) within an Ent transaction under standard request context.
