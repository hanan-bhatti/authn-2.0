# Feature Specification: FR-18 Sandbox Message Inbox

## 1. Overview

**FR-18: Sandbox Message Inbox** makes the test environment stop sending. Every email and SMS the engine would have dispatched in `test` is stored instead, and read back through an inbox API with its verification link and one-time code intact. In `live` nothing changes.

This is what makes a test environment usable rather than merely separate. [FR-17](17-test-live-environments.md) gives a tenant two sets of data and two sets of rules; it does not stop a test signup from mailing a real address. Without capture, rehearsing a password reset means either delivering to somebody's inbox or not testing the reset.

Two surfaces, answering questions that do not substitute for each other:

| Concern | Mechanism |
| :--- | :--- |
| **Did the engine produce the right message?** — template, code, link | The inbox. No provider is involved. |
| **Do the configured provider credentials work?** | A single endpoint that deliberately bypasses the capture and sends for real. |

A thousand captured messages say nothing about whether SMTP accepts mail, and one successful delivery test says nothing about whether the 2FA template renders a code.

---

## 2. Architecture & Data Model

### Interception at the provider interface

[`capture.go`](../../apps/auth-engine/internal/sandbox/capture.go) decorates `email.EmailProvider` and `sms.SMSProvider`. `cmd/server/wiring.go` wraps each once, before any service takes a reference:

```go
emailProvider := sandbox.WrapEmail(directEmail, sandboxStore)
smsProvider := sandbox.WrapSMS(directSMS, sandboxStore)
```

**Wrapping at the interface rather than at each send site is a security property, not a convenience.** The engine has seven places that decide to send a message and will grow more; a site nobody remembered to route through the sandbox is a real message leaving a test environment, addressed to whoever a fixture named. One wrap covers every sender the engine has and every one it gains.

The wrapped providers keep the obvious names. The undecorated ones are `directEmail` and `directSMS`, so a service reaching for `emailProvider` — the natural choice — gets the safe behaviour.

Neither provider signature carries a tenant or an environment, and neither needs to. Every authenticating middleware has already called `privacy.NewContext(...)` and `c.SetUserContext(...)` for the Ent interceptors, so the context at every send site already knows both.

### What counts as capturing

```go
func capturing(ctx context.Context) bool {
    p, ok := privacy.FromContext(ctx)
    if !ok || p.Bypass {
        return false
    }
    return p.TenantID != "" && p.Environment == string(sandboxmessage.EnvironmentTest)
}
```

**Only an explicit test scope captures. An absent or bypassing scope delivers** — the opposite default to the one FR-17 takes on reads, and deliberately so. There, an unknown environment reads as `test` because the narrow answer is the harmless one. Here the narrow answer would swallow a live password reset and lock a customer out of their own account.

### The stored row

[`sandbox_message.go`](../../apps/auth-engine/ent/schema/sandbox_message.go):

- `id`: string (immutable)
- `tenant_id`: string — a required edge to `tenant`, so a capture cannot name a tenant that does not exist
- `environment`: enum `test` | `live`, default `test`, immutable
- `channel`: enum `email` | `sms` (immutable)
- `recipient`: string — an email address, or E.164 for SMS
- `subject`: string, optional — empty for SMS, which has none
- `body`: text — the message exactly as the provider would have received it
- `template`: string, optional — which template produced it
- `code`: string, optional — the one-time code, lifted out at capture time
- `metadata`: JSON, optional — the action link, and the plain-text alternative
- `created_at`: time (immutable)

`environment` exists on an entity only ever written as `test` so that this table is narrowed by the same interceptor predicate as every other environment-scoped one. A live-key query therefore cannot read sandbox traffic even if a row were somehow written as `live`.

Indexes: `(tenant_id, environment, created_at)` serves the newest-first inbox read and the age sweep; `(tenant_id, recipient, created_at)` serves "the code that just went to this address", which is the common polling query and must not degrade into a scan as captures accumulate.

### Extraction at capture time

[`extract.go`](../../apps/auth-engine/internal/sandbox/extract.go) lifts the code, the link and the template identifier into their own columns, so completing a flow against the sandbox does not mean parsing rendered HTML. The rendering is styling and changes freely; the code and the link are the contract.

Every extractor is strict, because a loose match is worse than no match: a harness reading a wrong value fails in a way that looks like the engine generated the wrong credential.

- `otpPattern` matches a standalone run of exactly six digits. The neighbouring characters are part of the match rather than a lookaround, which RE2 does not offer, so the digits come from the second submatch. Both character classes exclude `#` specifically — the inlined stylesheet in the email templates contains `#334155`, six digits with no letters, and a pattern ignoring the leading `#` would report a border colour as the user's verification code.
- The code is read from the plain-text alternative in preference to the HTML one. Both carry the same code, and only one of them is wrapped in a stylesheet.
- `linkPattern` requires a `token=` query parameter rather than merely a URL, because a rendered message contains the product's own links too and the only one worth lifting is the one that authenticates.
- `classifyEmail` maps a subject to a template identifier using the sender's own subject constants rather than copies of their text, so a reworded subject changes one value and every entry still resolves. An unrecognised subject yields `""` rather than a guess.

### Failure is reported, not swallowed

A failed capture returns an error, matching what a provider does when it cannot accept a message. Callers that log and continue keep doing so, and the reason a message never arrived stays visible instead of being absorbed by the layer that was supposed to store it.

The store refuses a capture on a context carrying no tenant and environment (`ErrNoScope`) rather than filling in a default. A row written under the wrong scope is invisible to the inbox that ought to show it, which reads as *"the message was never sent"* — the one conclusion a sandbox must never produce falsely.

---

## 3. Retention

`SANDBOX_MESSAGE_RETENTION` (default `24h`) bounds how long a capture is kept. The retention sweeper from `cmd/server/wiring.go` registers `sandboxStore.PurgeExpired` as a task alongside the session, social-state and device-telemetry sweeps, deleting in batches so a backlog does not become one statement holding locks across the table.

The window is short because captures hold verification links and one-time codes **in plain text** — which is the point of the entity, since a harness has to read them, and exactly why a long window is an accumulating archive of working credentials rather than a convenience. A test reads its message within seconds of triggering it.

The loader rejects a zero or negative duration, so `SANDBOX_MESSAGE_RETENTION=0` fails at boot rather than disabling the sweep.

---

## 4. Validation Bounds & Limits

| Attribute | Validation / Limit Bound |
| :--- | :--- |
| **Inbox environment** | `test` only. All three inbox routes answer `403` to a `live` credential. |
| **`channel` filter** | `email` or `sms`; anything else is `400`. |
| **`limit`** | Default `50`, capped at `200`. Non-integer values are `400`. |
| **`offset`** | Negative values are treated as `0`. Non-integer values are `400`. |
| **Listing payload** | `body` is omitted from a listing and present only on a single-message read. |
| **Delivery verification recipient** | Not a request field. Always the signed-in operator's own stored address. |
| **Delivery verification credential** | Console admin JWT only. A secret key is `403`. |
| **Delivery verification rate** | 3 per rate-limit window per tenant and channel. |
| **Retention** | `SANDBOX_MESSAGE_RETENTION`, default `24h`, must be positive. |

---

## 5. API Endpoints

### Sandbox Inbox
*Requires a **test** secret key `sk_test_...` or a console admin JWT. A live credential is refused.*
- `GET /v1/tenant/sandbox/messages` — one page of captures, newest first, with `total` before paging. Filters: `recipient`, `channel`, `limit`, `offset`.
- `GET /v1/tenant/sandbox/messages/:id` — one capture including `body`. `404` for another tenant's message.
- `DELETE /v1/tenant/sandbox/messages` — empty the caller's inbox, reporting `removed`.

### Delivery Verification
*Requires a console admin JWT.*
- `POST /v1/tenant/delivery/verify` — send one real message through the configured provider to the operator's own address. `{"channel": "email" | "sms"}`.

See [`docs/endpoints/tenant-sandbox-inbox.md`](../endpoints/tenant-sandbox-inbox.md).

---

## 6. Webhooks & Audit Events

None. A captured message is not an event a customer's system needs to react to — the inbox is the record, and it is read by the test that triggered the send. Delivery verification is an operator action against their own address whose result is the response.

---

## 7. Scope Boundaries

- **The inbox refuses a live credential rather than returning an empty list.** Nothing is captured outside `test`, so an empty list would be a true answer to the wrong question, and "my message is missing" is a worse conclusion to leave an operator with than "you are looking at the wrong environment".
- **A cross-tenant read is `404`, not `403`.** Distinguishing the two would confirm that the ID exists.
- **`Store.Purge` states its tenant and environment predicates itself** as well as relying on the interceptor. A delete carrying no predicate of its own is one line away from erasing every tenant's captures if it is ever run under a bypassing context.
- **Delivery verification takes the undecorated providers and a non-privacy context.** Routing it through the wrapper would capture the one message whose entire purpose is to reach a provider.
- **The engine does not queue or retry captures.** A capture is a single insert on the request path; if it fails, the send fails, in the same way a provider outage does.

---

## 8. Verification

```bash
go test ./internal/sandbox/...
go test -tags integration -run 'TestSandbox|TestDelivery' ./test/
```

The unit tests cover the store, the capture decision and the extractors: that reads are confined to the caller's tenant and environment, that a capture without a scope is refused, that `PurgeExpired` respects its cutoff and batch size, and that `extractOTP` reads a code out of every message shape the engine sends while ignoring the six-digit palette value in the rendered stylesheet — asserted against the real template rather than a quoted snippet, so the test fails loudly if the stylesheet changes rather than silently passing on an absent hazard.

The integration tests drive the HTTP surface with the real guard: a signup captured and read back with its link intact and nothing reaching the provider behind the sandbox, `body` absent from the listing and present on the detail read, the filters and the page total, a `403` on every inbox route for a live secret key, a purge that leaves another tenant's captures alone, a `404` for another tenant's message, and delivery verification refusing a secret key, refusing an unverified address, then reaching the provider rather than the inbox — with the recipient taken from the operator's account even when the request body names a different one.

The shared integration harness wraps its recording provider in the real sandbox rather than intercepting mail ahead of it, so the eight pre-existing token round-trip assertions across four test files exercise the capture path as well. A harness that captured mail itself would be testing an arrangement no deployment runs, and would report a broken sandbox as a passing suite.
