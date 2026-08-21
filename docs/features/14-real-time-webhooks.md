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

### Emitted Events

Every name on the subscription allowlist (`internal/webhook/validator.go`) is raised by a real code path. Nothing validates on subscription that cannot fire.

**Account lifecycle**
- `user.created` — An account row came into existence. `via` names the route: `password`, `magic_link`, `social`, `saml`, `invitation`.
- `user.signup` — Someone registered themselves. Raised only where the person supplied their own address and nobody else initiated it: `password`, `magic_link`, `social`. A SAML subject provisioned just-in-time and an invitee redeeming a token get `user.created` alone, since neither of them signed up.
- `user.updated` — Profile changed, by the account holder or by an administrator. The administrative form carries `actor_id` and names the fields that moved (`fields_changed`) without their values; a status change carries `status` and `previous_status`, and a restore carries `restored`.
- `user.deleted` — The account no longer signs in. `soft: true` marks the administrative retirement, whose row survives and can be restored; the account holder's own deletion removes the row.
- `password.changed` — Password reset or changed.

**Authentication**
- `user.login.success` — A session was issued. `method` is `password`, `magic_link`, `passkey`, or the second factor that completed a challenge (`totp`, `sms`, `recovery_code`); `session_id` names the session. **SSO is the exception**: a SAML sign-in raises `saml.login_success` and no `user.login.success`, so a subscriber wanting every sign-in must take both names.
- `user.login.failed` — An attempt was refused. `reason` is `invalid_credentials` (unknown address or wrong password — `user_id` is present only when an account matched), `account_status` (correct credentials, restricted account, with `status`), or `invalid_2fa_code` (correct password, rejected second factor).
- `2fa.enabled` / `2fa.disabled` — `method` is `totp`, `sms` or `passkey`. `2fa.disabled` names the factor that was removed rather than asserting the account has none left; `remaining_factors` counts the primary factors still enrolled, which tells apart removing one of several from losing the last one. Recovery codes are not counted: they are a way past a factor the account holds, so `remaining_factors: 0` means the account is back to signing in on its password alone, and the codes have been discarded with the factor they backed.
- `session.revoked` — `scope` is `session`, `others` or `all`, and `reason` says who ended it and why: `user_request`, `refresh_token_reuse`, `revoked_session_reuse`, `2fa_disabled`, `account_banned`, `account_suspended`, `account_deleted`, `admin_force_logout`. Every wholesale form carries `count`, which may legitimately be `0` for an account with nothing live; the administrative ones carry `actor_id` and `access_tokens_cut`, which reports whether outstanding access tokens were refused immediately or run to their own expiry. The event is raised only once the revocation has actually landed — a failed sweep is logged and stays silent, so a subscriber rebuilding a session list from the stream never shows an account signed out while its sessions still answer.
- `rbac.role.assigned` / `rbac.role.revoked` — Carries `role_id`, `role_slug`, `role_name` and the `actor_id` who made the change.

**Support sessions**
- `user.impersonated` / `user.impersonation_exited` — Both carry the same `session_id`, which travels in the impersonation token's `sid` claim. Nothing about a support session is stored server-side, so the token is what lets the end be matched to the start.

**Organizations and SSO**
- `org.created`, `org.updated`, `org.deleted` — Organization lifecycle.
- `org.member_joined`, `org.member_removed` — Membership changes. `org.member_joined` fires on all three routes into an organization, with `via` distinguishing a direct add (absent), `invitation` and `saml`.
- `org.invitation_sent`, `org.invitation_revoked`, `org.invitation_accepted` — Invitation lifecycle. Redeeming an invitation raises `org.member_joined` as well, because the token being spent and the membership existing are separate facts.
- `saml.connection_created`, `saml.connection_updated`, `saml.connection_deleted` — SSO connection lifecycle.
- `saml.login_success` — SSO sign-in completed.

**Meta**
- `ping` — Fired manually via `/ping`, never by system activity.
- `*` — Wildcard, matches every event including ones added later.

### Payload conventions

- **Every event names its subject by ID**, and account events carry `email` alongside it, so a subscriber need not hold a prior mapping to act on one.
- **An event's environment comes from the row it concerns**, never from the caller's key — see *Environment Separation* above.
- **Failed authentication is reported in full to the tenant's own subscriber.** The HTTP response deliberately cannot distinguish an unknown address from a wrong password, but the webhook does: telling a spray across many addresses from repeated attempts on one account is what makes the stream usable against credential stuffing, and it reveals nothing to anyone outside the tenant.
- **Personal data is not accumulated.** Profile events name which fields changed, not what they now contain; a subscriber needing the values reads the account back over the API it is already authenticated for.
- **Emission never fails an operation.** Dispatch is a bounded non-blocking send, and every call site treats it as a notification: an account change that committed is not undone because its announcement had nowhere to go.

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

---

## 5. Verification Record

**Last Verified**: `2026-08-21`

**Method**: live `curl` against a running engine, with three endpoints registered on one tenant — one `test`, one `live`, one `all`, each subscribed to `["*"]` — and a local receiver recording every request it was handed. Routing is asserted from what arrived where, not from the dispatcher's own account of it.

**Result**: 70 deliveries carrying 13 distinct event names. Every event reached both the `test` receiver and the `all` receiver; the `live` receiver was handed nothing, and all 70 envelopes read `"environment": "test"`.

| Event | Action that raised it |
| :--- | :--- |
| `user.created`, `user.signup` | Password registration (both names, one request) |
| `user.login.success` | Password login, and a login completed by a TOTP challenge (`method: totp`) |
| `user.login.failed` | Wrong password against a real account (`reason: invalid_credentials`) |
| `2fa.enabled` / `2fa.disabled` | TOTP confirm, then TOTP disable — the disable reporting `remaining_factors: 0` |
| `session.revoked` | `account_banned` (`count: 0`), `2fa_disabled` (2), `account_suspended` (4), `admin_force_logout` (2), `account_deleted` (3) |
| `rbac.role.assigned` / `rbac.role.revoked` | Admin assign and revoke of the same role |
| `user.updated` | Seven distinguishable forms: an `email_verified` flip, a profile edit naming `fields_changed`, ban, unban, suspend, unsuspend, restore |
| `user.deleted` | Administrative soft-delete (`soft: true`) |
| `user.impersonated` / `user.impersonation_exited` | Support session started, then exited |

Four of those figures were checked against a source outside the payload, because an emitter agreeing with itself proves nothing:

- Force-logout's `count: 2` equals the `sessions_revoked: 2` in that endpoint's own HTTP response.
- The `session_id` on `user.impersonated` and on `user.impersonation_exited` are equal, and both equal the `sid` claim decoded from the impersonation token — which is the only record of the session, since none is stored server-side.
- The `account_banned` sweep reported `count: 0` on an account holding no live session, confirming that a zero is the honest answer rather than a swallowed failure.
- After a role change made with a secret key, the audit row names the key (`key_…`) where every row written before that fix names `admin_system`.

**Not exercised in this pass**: `password.changed`, the eight `org.*` events, the four `saml.*` events, and `ping`. Each is covered by its own feature's verification, and none of them was touched by the emission work above.
