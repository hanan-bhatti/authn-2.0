# Feature Specification: FR-17 Test & Live Environments

## 1. Overview

**FR-17: Test & Live Environments** gives every tenant two independent environments. A `test` environment for building and rehearsing, a `live` one that serves real customers, and a deliberate step between them.

Three mechanisms, doing different jobs:

| Concern | Mechanism |
| :--- | :--- |
| **Data** — which users, sessions, organizations and audit rows a key can see | A privacy-interceptor predicate on reads and writes |
| **Behaviour** — which password rules, session lifetimes, branding and OAuth clients apply | A separate settings row per environment |
| **Volume** — how much a test environment may hold, for how long, and how long a credential it issues lives | An Ent mutation hook counting each create against a configured ceiling, a lifetime clamp on `Config`, and a retention sweep |

The first two are the split itself, and the distinction between them matters. Data separation is a filter over rows that already exist, so a filter is enough. Settings are not rows a key looks at — they are the rules the engine runs by. A filter cannot make two environments enforce different password minimums; the settings have to be *stored* twice to differ at all.

The third is asymmetric on purpose: it binds test and never live. A free, unmetered environment is the cheapest place to run something that is not a test, and the ceilings are what keep it a development surface.

---

## 2. Architecture & Data Model

### The settings row

[`tenant_environment.go`](../../apps/auth-engine/ent/schema/tenant_environment.go) holds one row per `(tenant, environment)`:

- `id`: string (immutable)
- `tenant_id`: string
- `environment`: enum `test` | `live`
- `branding_config`, `password_policy`, `security_policy`, `recovery_policy`, `social_providers`, `role_policy`, `session_policy`: JSON blobs
- `published_at`: time — stamped on the destination each time settings are published onto it
- `created_at`, `updated_at`: time

`index.Fields("tenant_id", "environment").Unique()` — a tenant configuring one environment twice would leave the engine with two answers to every policy question and no rule for choosing.

Every policy a customer can change lives here rather than on the `tenant` row. That relocation is the feature: a policy on the tenant is a policy that governs everything at once, which is exactly what cannot be rehearsed.

### Selecting an environment

`middleware.GetEnvironment(c)` reads the environment the authenticating credential established, defaulting to `test` when none was — the safe end of the split. `policy.scopeOf(c)` pairs it with the tenant, and every policy handler starts there:

```go
tenantID, environment, ok := scopeOf(c)
if !ok {
    return nil
}
```

No handler accepts an environment from the request. A `sk_test_` key addresses test settings and a `sk_live_` key live ones, and neither can reach the other. Responses echo the environment they describe, inlined alongside the policy fields so an existing client reading `min_length` at the top level keeps working.

### Data separation

`privacy.NewContext(ctx, tenantID, appID, environment)` carries the scope into Ent, where the interceptors narrow reads and mutations. `privacy.NewBypassContext(ctx)` exists for provisioning, the one caller that legitimately spans environments.

The predicate is omitted when the environment is empty, so an unscoped context reads everything — which is why provisioning uses an explicit bypass rather than an absent scope. An accidental omission and a deliberate one would otherwise be indistinguishable.

Which entities are narrowed by environment follows from which ones carry the column:

| Entity | Environment predicate | Why |
| :--- | :--- | :--- |
| `user` | own column | An account belongs to one environment. |
| `application`, `api_key` | own column | A key addresses one environment; that is how the credential establishes the scope in the first place. |
| `tenant_environment` | own column | One settings row per environment is the point. |
| `sandbox_message` | own column | Captured bodies hold live-readable one-time codes. |
| `organization` | own column | A workspace is owned by one environment, not read by both. |
| `org_member`, `org_invitation` | through the organization | A roster that outlived its workspace's boundary would leak out of an environment meant to be self-contained. |
| `session_app_activity` | through the application | A row pairs a session with an application, and the application carries the environment. |
| `saml_connection` | **none** | It carries an `environment` field the SAML flow reads explicitly, so it can be promoted from a trial into production without being re-registered at the identity provider. A predicate here would make a promoted connection unreachable from the environment it was promoted into. Because no predicate hides a live connection from a test credential, the boundary is drawn by the live-key rule below instead. |
| everything else | tenant only | Sessions, audit rows, roles and the rest hang off a parent that is already confined. |

### Volume ceilings

[`internal/quota`](../../apps/auth-engine/internal/quota/quota.go) bounds how many users, organizations and API keys a tenant may hold in test. `Limits` is read from `TEST_MAX_USERS`, `TEST_MAX_ORGANIZATIONS` and `TEST_MAX_API_KEYS`. A non-positive field leaves that kind uncapped, so a zero-valued `Limits` — one nobody configured — bounds nothing rather than refusing a deployment's first sign-up.

The ceiling is a mutation hook on the Ent client, not a check in a handler:

```go
quota.AttachHook(client, limits)   // after AttachPrivacyInterceptors
```

Every create passes through the ORM, and five paths create a user — sign-up, magic-link auto-provisioning, social sign-in, SAML provisioning and invitation acceptance — so a check per handler holds only until the sixth is written. Four properties follow from where the hook sits:

- **Installed after the privacy interceptors.** The counting query is scoped by them, which is what makes the count per tenant and per environment with no predicate written in `quota` at all.
- **Creates only.** `ent.OpCreate` is the only op inspected. A tenant at its ceiling can still edit its rows, and must still be able to delete its way back under.
- **Test only.** A context with no scope, a bypass context or a live one passes untouched. Bypass belongs to migration, seeding and the retention sweeps, none of which is a tenant spending an allowance.
- **Unlisted entities are allowed.** Audit rows, identities and the rest follow from the three capped kinds rather than being provisioned on their own. This is the one place the package deliberately inverts the privacy interceptor next door, whose default must be to refuse. Sessions pass the count too — the hook touches them only to clamp a lifetime, below.

A refusal is a `*quota.Exceeded`, and `httperr.SendInternal` answers it `403 test_quota_exceeded` instead of `500`. It is a type rather than a formatted error so the handler can recover the caller-facing message with `errors.As` after a repository has wrapped it as `failed creating user: …` — rebuilding the message is more reliable than cutting that prefix back off a string, and the prefix names an internal operation that must not reach a response.

### Lifetime ceilings

A test environment is also the cheapest place to mint a long-lived credential. `TEST_ACCESS_TOKEN_TTL` (default 15m) and `TEST_SESSION_TTL` (default 24h) bound one, and they lower a lifetime without ever raising it: a deployment or tenant that asked for something shorter keeps it, and live is returned untouched. A non-positive ceiling bounds nothing, on the same reading as the volume limits — a zero-valued `Config` is one nobody loaded, and a zero read as "expire immediately" would kill every test sign-in.

The ceilings live on [`internal/config`](../../apps/auth-engine/internal/config/config.go) rather than in `pkg/jwt`, where `resolveTTL` is the single choke point every access token passes through. `pkg/jwt` cannot import `internal/policy`, which imports `internal/middleware`, which imports `pkg/jwt`; `internal/config` imports only `strings` and `time`, and every service already holds a pointer to it. Four methods, and callers ask for the environment rather than the ceiling:

```go
cfg.AccessTokenTTLFor(environment)                 // the deployment default, clamped
cfg.RefreshTokenTTLFor(environment)                // the session lifetime, clamped
cfg.ClampAccessTokenTTL(environment, ttl)          // a lifetime resolved elsewhere, clamped
cfg.ClampSessionTTL(environment, ttl)              // likewise, for a session
```

The `Clamp*` pair takes a lifetime rather than reading one, which is what makes a tenant's own `access_token_ttl_minutes` pass through the same ceiling as the deployment default. A tenant sets one value across both environments, so without that a tenant asking for a day in live would also be handing test a day-long token.

A lifetime is decided in four places that have to agree, and each resolves it through the same call:

| Artifact | Where | Why it cannot be left out |
| :--- | :--- | :--- |
| The signed access token | every `IssueAccessToken` call in `auth`, `session`, `social`, `oauth`, `saml` | It authenticates requests on its own, with nothing to check it against until it expires. |
| The session row's `expires_at` | each service's `refreshTokenTTL(environment)`, plus `auth.Service.clampSessionTTL` for the passkey login's week | The row is what makes a refresh token work, so one past the ceiling keeps minting access tokens however short each is. |
| The refresh cookie | `authcookie.Writer.RefreshTokenTTL` | A browser holding a cookie for a session the sweep deleted refreshes into a 401 it cannot tell from theft detection. |
| `expires_in` | `session.Service.accessTokenExpiresIn`, `oauth.Service.accessTokenExpiresIn` | It is what a client schedules its next refresh from; advertising the unclamped figure has every test client refresh after its token has already expired. |

Underneath all four, `quota.Limits.SessionTTL` clamps a test session's `expires_at` in the same mutation hook that counts the volume ceilings, and rewrites the row rather than refusing it — a sign-in asking for too long a session is a lifetime to shorten, not a request to turn away. The session row is the one artifact with no single choke point: two repositories create sessions, one taking a TTL and an environment, the other an absolute time and no environment. The services are where the ceiling is legible; the hook is the floor under whatever path is written next.

### Idle test data

`TEST_USER_RETENTION` (default 720h) is what keeps `TEST_MAX_USERS` from becoming a wall. Suites create accounts by the thousand and abandon them, and a tenant that reached its ceiling through months of accumulated runs would start failing runs with nothing wrong with them.

`auth.Repository.PurgeIdleTestUsers` runs as an `idle test users` task on the retention sweeper alongside the session, social-state, telemetry and sandbox sweeps. Idle means no sign-in since the cutoff, or — for an account that never signed in — a registration before it, because an abandoned half-finished signup is the most common thing a suite leaves behind and would otherwise be the one row class that accumulates forever.

- **Live accounts are never swept**, and by predicate rather than by the caller's choice of cutoff, so a misconfigured retention window cannot reach a paying customer's account. An idle customer is still a customer.
- **Eleven dependent tables are cleared first.** Every foreign key into `users` is declared `OnDelete: NoAction`, so the database refuses the account delete while any child still points at it. `session_app_activity` is the exception and is left to the database, its key being the one declared to cascade.
- **One transaction per batch.** An account whose second factors were deleted but whose password hash survived is a weakened account rather than an absent one.
- **Batches run in ascending ID order**, so two servers sweeping at once take row locks in the same sequence rather than deadlocking, and a sweep that hits its deadline leaves partial progress the next one resumes.

### Live-only configuration

Two surfaces let a caller name the environment its write lands in, so the split alone cannot keep a test credential out of live and a rule has to. Both answer `403 live_key_required`, a code distinct from `forbidden` because the fix is to present the live key rather than to gain a permission — the same operator already holds both.

**Webhook endpoints.** An endpoint carries its own `environment`, but the value is chosen by whoever registers it: a write may name `live`, or `all`, whichever key made it. A test key able to register endpoints could therefore point live traffic at a destination of its choosing, repoint an entry to redirect a live event, or delete one to silence a live integration. `middleware.RequireLiveKey` guards the seven routes that change the list or make it emit a request — create, update, delete, ping, rotate-secret and redeliver. The decision needs only the credential, so the guard is a route-level `fiber.Handler`.

**SAML connections in live.** A connection's environment arrives in the request body, and the schema default for this one entity is `live`, so without a rule a test credential picks its own environment and does so by supplying nothing. `saml.callerMayWrite` refuses a test-scoped caller that creates a live connection, edits one, promotes its own trial into live, or deletes one. Here the decision needs the stored row and not just the credential — a test key may edit a connection that stays in test, and only reading the row says which case a `PATCH` is — so the guard sits in the service and signals with a sentinel the handler maps to `403`.

Three properties are shared with the ceilings next door, for the same reasons:

- **One-directional.** Live is protected; test is not. A live key may still write a connection sitting in test, which is what a promotion has to read before it writes. A symmetric rule would make promotion impossible, and a rule that checked only the destination would let a test key *demote* a live connection and break an organization's production SSO.
- **Reads are ungated.** The same asymmetry the publish endpoint draws: seeing the other environment's configuration crosses nothing, changing it does. A console signed in against test can still show a tenant what is configured.
- **Bypass and unscoped callers are exempt.** Provisioning, seeding and the retention sweeps address both environments at once, and every HTTP entry point installs a scope, so an absent one is not a request.

The caller's environment is read from the privacy context the auth middleware already installed, not from a parameter, so the rule applies identically across the `pk_` client tier and the `sk_` tenant and admin tiers with no signature to keep in step.

**What is not gated.** Custom domain verification is named in the schema — `custom_domain`, `domain_verified` and `domain_verification_token` on `ent/schema/tenant.go` — but no endpoint reads or writes those columns, so there is nothing to hold behind a key yet.

---

## 3. Publishing

`POST /v1/tenant/settings/publish` copies all seven policy columns from one environment onto the other in a single update and stamps the destination's `published_at`.

**The copy is wholesale rather than selective.** All seven columns move, not a chosen few, because a partially published configuration is a state nobody chose and nobody tested. Publishing an empty source therefore clears the destination — the faithful meaning of "make live match test", and the reason the diff endpoint exists.

**One update rather than seven**, so live is never briefly running half of test's configuration and half of its own.

**`changed` is measured before the write.** After it the two environments are identical by construction, so that is the only point at which "what did publishing change" can be answered. Comparison is on the encoded JSON rather than the maps: `encoding/json` sorts map keys, so two maps holding the same configuration always encode identically, making the comparison exact and order-independent. An unencodable column is reported as differing, because a column the engine cannot compare is one it cannot promise is unchanged. An absent column and an empty one compare equal — both mean "nothing stored, run the defaults".

**The destination must be the credential's own environment.** Publishing into live requires a `sk_live_` key. Without that guard a test key could overwrite a live configuration, which is the one thing the split exists to prevent. Reading the source across the boundary is safe by comparison: same tenant, and a publish that could not read test could not publish anything.

**Publishing an environment onto itself is refused.** It would report success while stamping `published_at` on settings that were never published, making the audit trail claim a promotion that did not happen.

---

## 4. Validation Bounds & Limits

| Attribute | Validation / Limit Bound |
| :--- | :--- |
| **Environment** | `test` or `live`. Never read from a request body or query on the settings endpoints; taken from the credential. |
| **`from` / `to`** | Each `test` or `live`, and must differ. `to` must equal the credential's environment. Omitted body means `test` → `live`. |
| **`cookie_same_site`** | `lax` or `none`; anything unrecognised is stored as `lax`. `none` is honoured only when the cookie will also carry `Secure` — over plaintext HTTP the cookie is written `Lax` instead. |
| **`access_token_ttl_minutes`** | `15`, `30` or `60`. Zero inherits the deployment default. Anything else is refused with `422` — a fixed menu has no nearest legal value worth guessing, and a caller handed one would not know it had been. |
| **`refresh_token_ttl_days`** | 1–365. Zero inherits the deployment default. Out-of-range values are clamped. Governs the stored session and its refresh cookie together, so shortening it binds a holder of the raw token and not only a browser. |
| **Settings rows per tenant** | Exactly one per environment, enforced by a unique index. |
| **Secrets in responses** | Each social provider's client secret is replaced by a `client_secret_set` boolean on every read, diff and publish response. |
| **Test users per tenant** | `TEST_MAX_USERS`, default 500. Test credentials only. A create past it answers `403 test_quota_exceeded`. |
| **Test organizations per tenant** | `TEST_MAX_ORGANIZATIONS`, default 25, counted per environment. Test credentials only, so live workspaces neither count nor are refused. |
| **Organization slug** | Unique per `(tenant, environment)`, so the same slug is claimable once in test and once in live. |
| **Test API keys per tenant** | `TEST_MAX_API_KEYS`, default 20, including the publishable/secret pair provisioning installs — so the room for keys issued through the API is this minus two. |
| **Test access token lifetime** | `TEST_ACCESS_TOKEN_TTL`, default 15m. Replaces `ACCESS_TOKEN_TTL` and any longer `access_token_ttl_minutes` a tenant stored, for test credentials only. Lowers, never raises. |
| **Test session lifetime** | `TEST_SESSION_TTL`, default 24h. Bounds the session row, its refresh cookie and so how long its refresh token keeps minting. Must stay longer than `TEST_ACCESS_TOKEN_TTL`; the boot refuses otherwise, because a session exists to outlive the tokens it mints. |
| **Test account retention** | `TEST_USER_RETENTION`, default 720h past the last sign-in, or past registration for an account that never signed in. Live accounts are never swept at any setting. |

Each ceiling must be positive; zero fails the boot rather than quietly lifting a limit somebody meant to set. None of the volume ones is a rate: the refusal is `403`, not `429`, because waiting does not help. Room is made by deleting rows, by waiting out `TEST_USER_RETENTION`, or by moving to live. The lifetime ceilings refuse nothing at all — they shorten what a caller asked for, which is why a harness sees no error and simply gets a credential that expires sooner.

---

## 5. API Endpoints

### Per-Environment Policy Endpoints
*Requires Secret Key `sk_...` or console admin JWT. The key selects the environment.*
- `GET` / `PUT` `/v1/tenant/password-policy`
- `GET` / `PUT` `/v1/tenant/security-policy`
- `GET` / `PUT` `/v1/tenant/recovery-policy`
- `GET` / `PUT` `/v1/tenant/session-policy`
- `GET` / `PUT` `/v1/tenant/branding`
- `GET` / `PUT` / `DELETE` `/v1/tenant/social-providers/:provider`

### Settings Endpoints
- `GET /v1/tenant/settings` — every policy column of the credential's environment, as stored, with secrets redacted.
- `GET /v1/tenant/settings/diff` — both environments plus the names of the columns that differ. Readable with either key.
- `POST /v1/tenant/settings/publish` — promote one environment's settings onto the other. `403` when the key does not govern the destination.

See [`docs/endpoints/tenant-settings.md`](../endpoints/tenant-settings.md).

### Live-Key Endpoints
*Refused a test credential with `403 live_key_required`.*
- `POST` / `PUT` / `DELETE` `/v1/admin/webhooks/endpoints[/:id]`, plus `/:id/ping`, `/:id/rotate-secret` and `/v1/admin/webhooks/deliveries/:id/redeliver` — a write may name the live environment, or `all`, whichever key made it. Reads are open to either key.
- `POST` / `PATCH` / `DELETE` `/v1/tenant/organizations/:orgId/saml` and `/v1/client/organizations/:orgId/saml` — when the connection sits in `live`, or when the request moves it there. A create omitting `environment` counts, because the schema default is `live`.

---

## 6. Webhooks & Audit Events

- `tenant.settings.published` — carries `from`, `to`, `changed_columns` and `actor_id`, attributed to a console user where one can be identified and to the API key otherwise.

The audit row is best-effort: the promotion is already durable by the time it is written, so a failure to record is logged rather than returned. Reporting a completed publish as failed would invite an operator to publish a second time.

---

## 7. Scope Boundaries

- **Organizations** carry an `environment` and are confined to it, so a rehearsal workspace never appears in a live listing and a slug can be claimed once per environment. A SAML connection attached to one is the exception below.
- **SAML connections** carry their own `environment`, supplied in the request body rather than derived from the key, because an organization has at most one connection and that record has to be able to move from a trial into production. A `live` target — named, or defaulted by omission — still requires a live credential. See [`16-enterprise-saml-sso.md`](16-enterprise-saml-sso.md).
- **Webhook endpoints** carry an `environment` of `test`, `live` or `all`, supplied at registration rather than derived from the key, because one integration may want both streams on a single receiver. Dispatch routes an event only to the endpoints matching where it originated, plus the `all` ones. The value is caller-chosen, so writing the list still requires a live credential. See [`14-real-time-webhooks.md`](14-real-time-webhooks.md).
- **`role_policy`** is stored, diffed and published with the other columns, but no endpoint writes it yet.
- **Outbound email and SMS** are not governed by a settings column. The test environment captures them into an inbox instead of delivering, which is a property of the environment rather than a policy a tenant configures. See [`18-sandbox-message-inbox.md`](18-sandbox-message-inbox.md).
- **Credential lifetimes** are the one setting a tenant may configure and not have honoured in full: `access_token_ttl_minutes` and `refresh_token_ttl_days` are single values across both environments, so the test ceilings shorten them there and leave live alone. Nothing reports the clamp — the caller receives a working credential that simply expires sooner. Verified live: a tenant storing `60` receives 3600-second tokens with `TEST_ACCESS_TOKEN_TTL` raised to `60m` and 900-second ones at its `15m` default, its stored `60` unchanged either way; and a tenant storing `refresh_token_ttl_days: 90` receives a 24-hour session row at the default `TEST_SESSION_TTL`.
- **The idle sweep reaches only `user` and its eleven dependent tables.** A test environment's applications, keys, organizations and settings are configuration a developer chose and are not swept at all; they are bounded by the volume ceilings instead.

---

## 8. Verification

```bash
go test ./internal/policy/... ./internal/quota/... ./internal/org/... ./internal/saml/... ./internal/config/... ./internal/auth/...
go test -tags integration ./test/ -run 'Ceiling|Quota|Workspace|Environment|Slug|TestKey'
```

`publish_test.go` covers the split itself — that a policy written in test does not govern live, that publishing promotes the whole configuration and reports what it changed, that a repeat publish reports no change and encodes that as `[]` rather than `null`, that publishing onto itself or into an unknown environment is refused, that the promotion reaches the audit trail, and that a settings read cannot cross tenants.

`org_test.go` pins the two branches only a unit test reaches. A scoped create lands in the caller's environment, and a bypass context — provisioning, seeding, a migration — leaves the field to its schema default rather than guessing, so a seeded workspace lands in test and never silently in live. It also pins the service's slug check against the unique index behind it: under a scoped context the interceptor narrows that check for free, under a bypass it narrows nothing, and the two have to bound the same set or seeding a test workspace fails because production already holds the name.

`quota_test.go` covers the ceilings at the ORM: that a create is refused at the limit and not before, that the count is per tenant and per environment, that a bypass context and an unscoped one are both exempt, that an update at the ceiling still passes, that an unlisted entity is unaffected, that a zero limit leaves its kind uncapped, that a tenant's live workspaces do not consume its test room, and that a slug is claimable once per environment and once per tenant. It also pins the lifetime clamp the same hook applies: a week-long test session is pulled back to the ceiling, one already under it is left exactly as asked, a live session of a month is untouched, and an unset `SessionTTL` bounds nothing.

`internal/config/config_test.go` pins the clamp's direction, which is the property everything else depends on: test is lowered, live is returned untouched, a shorter lifetime is kept rather than raised to the ceiling, an empty environment is not the test one, and an unset ceiling bounds nothing.

`internal/auth/retention_test.go` drives the idle sweep against a database with foreign keys enabled, because what it has to get right is the delete order — with the keys off the test would pass while the shipped sweep failed on every row. It covers that an idle test account goes and a live account idle by the same measure stays, that a recent sign-in and a fresh registration both survive, that sessions, session activity and second factors go with the account, that a backlog larger than one batch is drained in full, and that a non-positive batch size is refused rather than turning the batch into the whole table.

`test_ttl_ceiling_test.go` drives the lifetime ceilings through a real sign-in, where the four artifacts that have to agree are all observable at once: the signed token's `exp`, the stored session row's `expires_at`, the refresh cookie's `Expires` and the `expires_in` a client schedules from. It repeats the four across a refresh, since that is the path a long-running harness spends its life on and a clamp applied only at sign-in would let a session walk past the ceiling one rotation at a time. A control boots the same engine with no ceilings and confirms every lifetime is the deployment default, so the clamped assertions are measuring the clamp rather than a figure the harness was always going to produce.

`test_quota_test.go` drives the same ceilings over HTTP, which is where the parts meet: that the refusal arrives as `403 test_quota_exceeded` rather than a `500`, that its body carries none of the ORM wrapping it was raised beneath, that the row count is unchanged afterwards so the status is a refusal to write rather than a code in front of a completed one, that a live credential is unbounded, and that no ceiling is in force unless a deployment sets one.

`org_environment_test.go` drives the organization boundary itself: that the environment comes from the credential and is echoed in the response, that neither listing shows the other environment's workspaces, that a cross-environment read or delete is `404` and leaves the row intact, and that the same slug is claimable in both environments but not twice in one.

`internal/saml/live_key_test.go` pins the connection rule where the stored row is reachable: that a test-scoped caller can neither name `live`, omit `environment` into it, edit a live connection, promote its own trial nor delete one; that each refusal is followed by a re-read proving nothing was written behind it; that its own test connection is unaffected; that a live key promotes; and that a bypass and an unscoped context are both exempt.

`test/live_key_test.go` drives both surfaces over HTTP, which is the only place either is fully observable — the webhook rule is a middleware no service test reaches, and the SAML rule turns on the credential the request arrived with rather than on any argument a service receives. It covers all seven gated webhook routes, re-reads the endpoint with the live key to confirm no refused write landed, confirms the three reads stay open to a test key, and repeats the SAML create, default and promotion cases through the tenant tier.
