# Endpoint Specification: Outgoing Event Webhooks (`/v1/admin/webhooks/*`)

## Overview
* **Routes**:
  * `POST /v1/admin/webhooks/endpoints` — Register new webhook endpoint for one environment & issue HMAC signing secret (`whsec_...`)
  * `GET /v1/admin/webhooks/endpoints` — List all webhook endpoints for tenant
  * `GET /v1/admin/webhooks/endpoints/:id` — Get webhook endpoint details
  * `PUT /v1/admin/webhooks/endpoints/:id` — Update URL, description, environment, or subscribed events
  * `DELETE /v1/admin/webhooks/endpoints/:id` — Delete webhook endpoint
  * `POST /v1/admin/webhooks/endpoints/:id/ping` — Dispatch test ping webhook event
  * `POST /v1/admin/webhooks/endpoints/:id/rotate-secret` — Rotate signing secret key
  * `GET /v1/admin/webhooks/deliveries` — List delivery logs & HTTP status codes
  * `POST /v1/admin/webhooks/deliveries/:id/redeliver` — Re-send a recorded delivery to its endpoint
* **HTTP Methods**: `POST`, `GET`, `PUT`, `DELETE`
* **Purpose**: Outgoing real-time webhook event engine. Route each event to the endpoints registered for the environment it came from, sign payloads with HMAC SHA-256 signatures (`X-Authn-Signature`), handle worker retries with backoff, prevent SSRF (`file://` or non-HTTP schemes), and enforce event category validation (`user.created`, `user.login.success`, etc.).

---

## Authentication & Access Control
* **Protected By**: `RequireSecretKey` middleware (`X-Authn-Secret-Key: sk_<env>_<hash>`) or Console Admin JWT with `tenant_admin` role.
* **Live key required to write**: an endpoint names the environment whose events it receives, and a write may name `live` or `all` whichever key made it — so a test key able to register endpoints could still point live traffic at a destination of its choosing. `middleware.RequireLiveKey` therefore guards every route that changes the list or makes it emit an HTTP request: create, update, delete, ping, rotate-secret and redeliver. A `sk_test_` key on any of them is answered `403 Forbidden` with code `live_key_required`.
* **Reads stay open to either key**: the two endpoint reads and the delivery list are ungated, matching the settings publish rule — seeing the other environment's configuration crosses nothing, changing it does. A console signed in against test can still show a tenant what is configured.

---

## Environment Routing
Every endpoint carries an `environment` of `test`, `live` or `all`, chosen at registration. There is no default: an endpoint that silently defaulted would either miss the events its owner expected or deliver sandbox activity to a production subscriber, so `POST /endpoints` answers `422 Unprocessable Entity` with code `validation_failed` when the field is absent or holds anything else.

Dispatch selects a tenant's active endpoints whose environment matches the event's, plus every endpoint set to `all`. A test sign-up is therefore never delivered to a live-only receiver, and a live sign-up never reaches a sandbox one. The event's environment is taken from the record it concerns — the organization, user or SAML connection — not from the credential that triggered it, so a tenant administrator holding a live key who edits a sandbox organization produces a sandbox event.

Every delivered payload names its environment inside the signed body:

```json
{
  "id": "evt_...",
  "event": "user.created",
  "tenant_id": "ten_...",
  "environment": "test",
  "timestamp": "2026-08-19T09:14:02Z",
  "data": { "user_id": "usr_..." }
}
```

It travels in the body rather than in a header because the signature covers the serialised body only: a subscriber running one receiver for both environments can branch on `environment` and prove the value came from the engine. An endpoint set to `all` relies on this field to tell the two streams apart.

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
  "environment": "live",
  "events": ["user.created", "user.login.success"]
}
```
**Response (201 Created)**:
```json
{
  "id": "whe_5eb5f1be-ed3",
  "url": "https://api.acme.local/webhooks/authn",
  "description": "Acme Webhook Handler",
  "environment": "live",
  "secret": "whsec_da306471c3d10fcad2e4e08aca0ead0743ed56629c82929d",
  "subscribed_events": ["user.created", "user.login.success"],
  "is_active": true,
  "created_at": "2026-08-06T03:21:18Z"
}
```
The `secret` is returned by this call and by rotate-secret only; it is stored encrypted and never read back.

**Response (422 Unprocessable Entity)** — `environment` omitted:
```json
{
  "error": "environment is required: must be one of \"test\", \"live\" or \"all\"",
  "code": "validation_failed"
}
```

### 2. Dispatch Test Ping Event (`POST /v1/admin/webhooks/endpoints/:id/ping`)
```bash
$ curl -i -X POST -H "X-Authn-Secret-Key: sk_live_..." \
  http://localhost:8080/v1/admin/webhooks/endpoints/whe_5eb5f1be-ed3/ping
```
The ping reports the endpoint's own environment, so a subscriber's environment-branching code is exercised by the test rather than bypassed by it. For an endpoint set to `all`, which has no single truthful environment, it reports the calling key's instead.

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
| **Environment Omitted** | `POST /endpoints` with no `environment` | `422 Unprocessable Entity` | `ValidateEndpointEnvironment` refuses to guess; the endpoint is not created |
| **Unknown Environment** | `"environment":"production"` | `422 Unprocessable Entity` | Same validator (`must be one of "test", "live" or "all"`) |
| **Sandbox Activity Leaking to a Live Receiver** | Sign up a user with `sk_test_` while only a `live` endpoint is registered | No delivery | `GetActiveEndpointsForEvent` matches on the event's environment; the delivery log records nothing for that endpoint |
| **Live Activity Reaching a Sandbox Receiver** | Sign up a user with `sk_live_` while only a `test` endpoint is registered | No delivery | Same filter, in the other direction |
| **Rotate Secret** | `POST /endpoints/:id/rotate-secret` | `200 OK` | Issues new `whsec_...` HMAC key |
| **Delete Webhook** | `DELETE /endpoints/:id` | `200 OK` | Endpoint purged + returns 404 on subsequent queries |
| **Test Key Repointing a Live Receiver** | `PUT /endpoints/:id` with `sk_test_` and `"url":"https://attacker.example.com/collect"` | `403 Forbidden` | `middleware.RequireLiveKey` refuses with `live_key_required`; the stored URL is unchanged |
| **Test Key Silencing a Live Integration** | `DELETE /endpoints/:id` with `sk_test_` | `403 Forbidden` | Same guard; the endpoint survives |

*Last Verified*: `2026-08-20` — live `curl` suite against a running engine with three receivers registered for `test`, `live` and `all`. A `test` organization delivered to the test and `all` receivers only; a `live` one to the live and `all` receivers only; every `X-Authn-Signature` recomputed and matched; the delivery log recorded the originating environment on all four rows.
