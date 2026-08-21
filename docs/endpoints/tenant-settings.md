# Tenant Settings & The Test/Live Split (`/v1/tenant/...`)

> **Last Verified**: `2026-08-21` — `internal/policy` unit and integration tests, plus live `curl` verification of the access-token lifetime across two tenants (see [The access token lifetime is a menu, not a range](#the-access-token-lifetime-is-a-menu-not-a-range)).

## Overview

Every setting a customer can change — password rules, security enforcement, recovery rules, session lifetimes, branding, social providers, the default role — is stored **once per environment**. A tenant has exactly one `test` row and one `live` row, and the two are independent.

This is what makes a policy change rehearsable. Raising the password minimum to 12 characters in test governs test sign-ins alone; live keeps accepting 8 until the change is deliberately applied there.

---

## How An Environment Is Selected

**The credential decides. The request never does.**

| Key | Reads and writes |
| :--- | :--- |
| `sk_test_...` | the tenant's `test` settings |
| `sk_live_...` | the tenant's `live` settings |

There is no `?environment=` parameter and no `environment` body field on any of these endpoints. Supplying one has no effect. A key cannot address the environment it does not belong to, which is the property the split exists to provide: a script holding a test key cannot change what governs live sign-ins, whatever it sends.

Every response echoes the environment it describes:

```json
{
  "min_length": 12,
  "require_numeric": true,
  "environment": "test"
}
```

The policy fields sit at the top level rather than nested under a key, so a client that reads `min_length` keeps working. `environment` is echoed because "I changed the policy and nothing happened" is otherwise indistinguishable from having configured the other environment by mistake.

Console admin JWTs also work on these endpoints. Where no environment has been established, the engine reads `test` — the safe end of the split.

---

## Per-Environment Endpoints

These already existed; each now reads and writes one environment.

| Method | Path | Governs |
| :--- | :--- | :--- |
| `GET` / `PUT` | `/v1/tenant/password-policy` | Password complexity |
| `GET` / `PUT` | `/v1/tenant/security-policy` | Email verification, token reuse |
| `GET` / `PUT` | `/v1/tenant/recovery-policy` | Recovery proofs, freeze windows, lockout |
| `GET` / `PUT` | `/v1/tenant/session-policy` | Cookie `SameSite`, token lifetimes |
| `GET` / `PUT` | `/v1/tenant/branding` | Hosted-page branding |
| `GET` / `PUT` / `DELETE` | `/v1/tenant/social-providers/:provider` | OAuth client per provider |

A social provider configured in test is **not** configured in live. Each environment holds its own OAuth client, which is usually what you want — a Google client registered against `localhost` redirect URIs has no business serving production sign-ins.

### The access token lifetime is a menu, not a range

`session-policy` accepts `access_token_ttl_minutes` of **15, 30 or 60**, or `0` to inherit the deployment default. Anything else is refused with `422 validation_failed`.

It is a menu because the number trades off two things it does not state: how long a stolen token keeps working, and how often every client pays a refresh round-trip. Three points make that a choice between postures — 15 for a console moving money, 60 for an app whose users resent re-authenticating — where a free-form minute count invites `1440` and calls it convenience.

Rejecting rather than clamping follows from the same reasoning. There is no nearest legal value worth guessing, and a caller who asked for 45 and was handed 30 has no way to notice: the write returns `200` with the stored policy, which they would reasonably read as agreement. The other two fields keep their older clamping contract — `refresh_token_ttl_days` is a genuine range, and an unrecognised `cookie_same_site` becomes `lax`.

The chosen lifetime reaches every route that signs an access token: password login, second-factor completion, magic link, passkey, refresh and its grace-window handshake, social sign-in, SAML SSO, and the OAuth token exchange. Where a response advertises `expires_in`, that figure is resolved by the same call, so the advertised lifetime and the signed `exp` cannot drift apart. In `test` the result then passes through `TEST_ACCESS_TOKEN_TTL` (default `15m`), which lowers it and never raises it — so a tenant asking for 60 sees 60 in live and 15 in test.

**Verified**: `2026-08-21` — live `curl` against a running engine, two tenants in one deployment. Storing 15, 30 and 60 on one of them produced access tokens whose decoded `exp - iat` read 900, 1800 and 3600 seconds, while the second tenant, left at `0`, kept the deployment's 900 throughout — so the value is honoured per tenant rather than per deployment. `1`, `14`, `16`, `45`, `59`, `120`, `1440` and `-1` were each refused `422 validation_failed`, and `0`, `15`, `30`, `60` each stored as sent. On `POST /v1/client/auth/refresh` the response's `expires_in` equalled the decoded `exp - iat` of the token beside it (3600 against a tenant set to 60). Restarting with the default `TEST_ACCESS_TOKEN_TTL` lowered that same tenant's tokens to 900 with its stored `60` unchanged, confirming the ceiling still bounds a tenant's choice in `test`.

---

## Reading A Whole Environment (`GET /v1/tenant/settings`)

Returns every policy column of the credential's environment in one read, as stored. Intended for a console showing what an environment currently holds; the typed endpoints above are what you configure against.

```json
{
  "environment": "test",
  "settings": {
    "branding_config": { "logo_url": "https://cdn.acme.test/logo.svg" },
    "password_policy": { "min_length": 12, "require_numeric": true },
    "security_policy": {},
    "recovery_policy": {},
    "social_providers": {
      "google": { "enabled": true, "client_id": "123.apps.googleusercontent.com", "client_secret_set": true }
    },
    "role_policy": {},
    "session_policy": { "access_token_ttl_minutes": 15 }
  }
}
```

An **empty or absent column** means nothing has been configured there and the engine's defaults apply. `{}` is not "everything off".

Each provider's client secret is replaced by `client_secret_set`. That boolean is the part a console needs — whether the provider is configured — and an administrator comparing two environments does not need to see either secret to know they differ.

`role_policy` is stored, published and diffed with the rest, but no endpoint writes it yet; it reads as `{}` for every tenant today.

---

## Comparing The Two (`GET /v1/tenant/settings/diff`)

Answers **"what will change in live if I publish test"**, which is the question to ask before publishing. Both settings objects are complete in the real response; the example below is abbreviated to the column that differs.

```json
{
  "environment": "test",
  "test":  { "password_policy": { "min_length": 12 } },
  "live":  { "password_policy": { "min_length": 8 } },
  "differs": ["password_policy"]
}
```

* `differs` lists the columns whose stored values differ, in a stable order. When the two environments already match it is `[]`.
* Both environments come back whichever key you used. Reading across the boundary exposes nothing the same tenant does not already own, and a comparison that could only see one side would not be a comparison. Secrets are redacted on both sides.
* An absent column and an empty one compare **equal**, since both mean "nothing stored, run the defaults" — they do not show up as a difference publishing would not change.

---

## Publishing (`POST /v1/tenant/settings/publish`)

Copies every policy column from one environment onto the other and records the promotion in the audit trail.

```bash
curl -X POST https://api.authn.com/v1/tenant/settings/publish \
  -H "Authorization: Bearer sk_live_..." \
  -H "Content-Type: application/json" \
  -d '{"from": "test", "to": "live"}'
```

* **Request** — the body may be omitted entirely, which means `test` → `live`:
```json
{
  "from": "test",
  "to": "live"
}
```
* **Response (`200 OK`)**:
```json
{
  "message": "settings published",
  "from": "test",
  "to": "live",
  "changed": ["password_policy", "session_policy"],
  "settings": { "password_policy": { "min_length": 12 } }
}
```

`changed` is measured against the destination as it stood **before** the write — after it, the two environments are identical by construction, so this is the only moment the question can be answered. An empty array means the destination already matched; the publish recorded itself and changed nothing else. Only column names are reported, never values, because the values include provider secrets.

### The copy is wholesale

All seven columns move, not a chosen few. A half-published configuration is a state nobody chose and nobody tested.

It follows that **publishing an empty test environment clears live**. That is the faithful meaning of "make live match test", not a bug — but it is why `GET /v1/tenant/settings/diff` exists. Read it first if you are not certain what test currently holds.

### Who may publish

The destination must be the environment of the key making the request.

* **Response (`403 Forbidden`)** — a `sk_test_` key trying to publish into live:
```json
{
  "error": "publishing into live requires a live secret key"
}
```

This is the guard that matters. Without it a test key could overwrite a live configuration, which is the one thing the environment split exists to prevent. Reading the *source* across the boundary is safe by comparison: it is the same tenant's data, and a publish that could not read test could not publish anything.

* **Response (`400 Bad Request`)** — an unparseable body, an environment name that is neither `test` nor `live`, or:
```json
{
  "error": "from and to must name different environments"
}
```

Publishing an environment onto itself is refused rather than treated as a no-op. It would report success while stamping `published_at`, making the audit trail claim a promotion that never happened.

* **Response (`404 Not Found`)** — unknown tenant.

### Audit trail

Each publish appends a `tenant.settings.published` audit row carrying `from`, `to`, `changed_columns` and the actor, attributed to a console user where one can be identified and to the API key otherwise. Publishing is the one settings operation that changes what governs live sign-ins without anybody editing a live policy, so it is the one that most needs a trail: *"live started requiring 12-character passwords on Tuesday"* is otherwise unanswerable from the data alone.

The audit row is best-effort. The promotion is already durable by the time it is written, and reporting a completed publish as failed would invite an operator to publish a second time — so a failure to record is logged, not returned.

---

## A Typical Change

1. `PUT /v1/tenant/password-policy` with `sk_test_...` — raise `min_length` to 12.
2. Sign a test user up. Confirm an 8-character password is now refused and the message on your sign-up page reads correctly.
3. `GET /v1/tenant/settings/diff` — confirm `differs` is exactly `["password_policy"]` and nothing else drifted while you were working.
4. `POST /v1/tenant/settings/publish` with `sk_live_...` — live now enforces 12.

Step 3 is the one people skip. It is also the one that catches the branding edit or the social provider you changed in test three weeks ago and forgot about, which step 4 would otherwise carry into live along with the password rule.

---

## What The Split Does Not Cover

* **Organizations** are separated by the environment filter on reads and writes, not by having per-environment settings. A workspace carries an `environment` of its own, so each key sees only its own list and a slug is claimable once per environment — but there is nothing about an organization to publish from test into live.
* **SAML connections** carry their own `environment` field, supplied in the request body rather than inferred from the key, because an organization has one connection that has to be able to move from a trial into production. See [`saml-idp-config.md`](saml-idp-config.md).
* **Users, sessions and audit rows** are separated by the environment filter on reads rather than by having per-environment settings. A test key cannot see live users.
