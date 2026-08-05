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
| `POST` | `/v1/admin/webhooks/endpoints` | Register new webhook endpoint | `webhooks:write` / Admin Secret Key |
| `GET` | `/v1/admin/webhooks/endpoints` | List all webhook endpoints for tenant | `webhooks:read` / Admin Secret Key |
| `GET` | `/v1/admin/webhooks/endpoints/:id` | Fetch specific webhook endpoint details | `webhooks:read` / Admin Secret Key |
| `PUT` | `/v1/admin/webhooks/endpoints/:id` | Update URL, description, or subscribed events | `webhooks:write` / Admin Secret Key |
| `DELETE` | `/v1/admin/webhooks/endpoints/:id` | Delete endpoint and cascade delete child events | `webhooks:delete` / Admin Secret Key |
| `POST` | `/v1/admin/webhooks/endpoints/:id/ping` | Send immediate test ping event | `webhooks:write` / Admin Secret Key |
| `POST` | `/v1/admin/webhooks/endpoints/:id/rotate-secret` | Rotate signing secret key | `webhooks:write` / Admin Secret Key |
| `GET` | `/v1/admin/webhooks/deliveries` | List webhook delivery audit logs | `webhooks:read` / Admin Secret Key |

---

## 4. Input Validation & Strict Error Handling

1. **URL Validation**: Requires well-formed HTTPS scheme (allowing `http://localhost` or `http://127.0.0.1` in development mode).
2. **Subscribed Events Validation**: Rejects empty array or invalid event strings with `422 Unprocessable Entity`.
3. **Cascade Deletion**: Deleting an endpoint (`DELETE /v1/admin/webhooks/endpoints/:id`) automatically deletes all child delivery logs (`WebhookEvent`) within an Ent transaction under standard request context.
