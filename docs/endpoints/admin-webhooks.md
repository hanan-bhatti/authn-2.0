# Endpoint Specification: Outgoing Event Webhooks (`/v1/admin/webhooks/*`)

## Overview
* **Routes**:
  * `POST /v1/admin/webhooks/endpoints` — Register new webhook endpoint & issue HMAC signing secret (`whsec_...`)
  * `GET /v1/admin/webhooks/endpoints` — List all webhook endpoints for tenant
  * `GET /v1/admin/webhooks/endpoints/:id` — Get webhook endpoint details
  * `PUT /v1/admin/webhooks/endpoints/:id` — Update URL, description, or subscribed events
  * `DELETE /v1/admin/webhooks/endpoints/:id` — Delete webhook endpoint
  * `POST /v1/admin/webhooks/endpoints/:id/ping` — Dispatch test ping webhook event
  * `POST /v1/admin/webhooks/endpoints/:id/rotate-secret` — Rotate signing secret key
  * `GET /v1/admin/webhooks/deliveries` — List delivery logs & HTTP status codes
  * `POST /v1/admin/webhooks/deliveries/:id/redeliver` — Re-send a recorded delivery to its endpoint
* **HTTP Methods**: `POST`, `GET`, `PUT`, `DELETE`
* **Purpose**: Outgoing real-time webhook event engine. Sign payloads with HMAC SHA-256 signatures (`X-Authn-Signature`), handle worker retries with backoff, prevent SSRF (`file://` or non-HTTP schemes), and enforce event category validation (`user.created`, `user.login.success`, etc.).

---

## Authentication & Access Control
* **Protected By**: `RequireSecretKey` middleware (`X-Authn-Secret-Key: sk_<env>_<hash>`) or Console Admin JWT with `tenant_admin` role.
* **Live key required to write**: an endpoint carries no `environment` column — there is one list per tenant and the dispatcher delivers every event to all of it. The list is therefore live configuration whichever key wrote it, so `middleware.RequireLiveKey` guards every route that changes it or makes it emit an HTTP request: create, update, delete, ping, rotate-secret and redeliver. A `sk_test_` key on any of them is answered `403 Forbidden` with code `live_key_required`.
* **Reads stay open to either key**: the two endpoint reads and the delivery list are ungated, matching the settings publish rule — seeing the other environment's configuration crosses nothing, changing it does. A console signed in against test can still show a tenant what is configured.

---

## Webhook Signature Verification (`X-Authn-Signature`)
Outgoing webhooks include standard security headers for HMAC validation:
* `X-Authn-Signature`: `t=<timestamp>,v1=<hex_hmac_sha256_signature>`
* `X-Authn-Event`: Event category string (e.g. `user.created`)

---

## Request & Response Examples

### 1. Register Webhook Endpoint (`POST /v1/admin/webhooks/endpoints`)
```json
{
  "url": "https://api.acme.local/webhooks/authn",
  "description": "Acme Webhook Handler",
  "events": ["user.created", "user.login.success"]
}
```
**Response (201 Created)**:
```json
{
  "id": "whe_5eb5f1be-ed3",
  "url": "https://api.acme.local/webhooks/authn",
  "description": "Acme Webhook Handler",
  "secret": "whsec_da306471c3d10fcad2e4e08aca0ead0743ed56629c82929d",
  "subscribed_events": ["user.created", "user.login.success"],
  "is_active": true,
  "created_at": "2026-08-06T03:21:18Z"
}
```

### 2. Dispatch Test Ping Event (`POST /v1/admin/webhooks/endpoints/:id/ping`)
```bash
$ curl -i -X POST -H "X-Authn-Secret-Key: sk_live_..." \
  http://localhost:8080/v1/admin/webhooks/endpoints/whe_5eb5f1be-ed3/ping
```
**Response (200 OK)**:
```json
{
  "delivery": {
    "id": "whd_2dae1f24-036",
    "endpoint_id": "whe_5eb5f1be-ed3",
    "event_type": "ping",
    "status": "failed",
    "error_message": "dial tcp: lookup api.acme.local: Temporary failure in name resolution"
  },
  "message": "test ping webhook event delivered"
}
```

---

## Security Audit & Attack Mitigation Log

| Attack Vector / Test | Payload / Input | Response Status | Security Defense Execution |
| :--- | :--- | :--- | :--- |
| **Unauthenticated Request** | `POST /v1/admin/webhooks/endpoints` (No `sk_`) | `401 Unauthorized` | Blocked by secret key middleware |
| **SSRF Scheme Injection** | `"url":"file:///etc/passwd"` | `422 Unprocessable Entity` | Scheme validation enforced (`must be http or https`) |
| **Unsupported Event Attack** | `"events":["user.exploit_system"]` | `422 Unprocessable Entity` | Event category validation (`unsupported event type`) |
| **Rotate Secret** | `POST /endpoints/:id/rotate-secret` | `200 OK` | Issues new `whsec_...` HMAC key |
| **Delete Webhook** | `DELETE /endpoints/:id` | `200 OK` | Endpoint purged + returns 404 on subsequent queries |
| **Test Key Repointing a Live Receiver** | `PUT /endpoints/:id` with `sk_test_` and `"url":"https://attacker.example.com/collect"` | `403 Forbidden` | `middleware.RequireLiveKey` refuses with `live_key_required`; the stored URL is unchanged |
| **Test Key Silencing a Live Integration** | `DELETE /endpoints/:id` with `sk_test_` | `403 Forbidden` | Same guard; the endpoint survives |

*Last Verified*: `2026-08-06` — live `curl` attack suite against running server. The live-key rows were added afterwards and are covered by `test/live_key_test.go` rather than by that run.
