# App Bootstrap Configuration API (`GET /v1/client/app-config`)

> **Last Verified**: `2026-08-18` — verified by `apps/auth-engine/test/app_config_test.go` (integration) and `internal/appconfig/*_test.go` (unit).

## Overview
One request a sign-in page makes before it renders anything, answering the three questions a login UI cannot answer for itself: how should it look, which sign-in options should it offer, and what may it accept as a password.

It exists as a single call rather than three because a page that made three would render three times, and because two of the three are policies the client must agree with the server about. A form that enforces a weaker password rule than the engine does produces a field that accepts input the API then refuses — which reads to the user as a broken site rather than as a password policy.

Two companion routes configure what it returns:

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/v1/client/app-config` | `X-Authn-Publishable-Key` | The public bootstrap document |
| `GET` | `/v1/tenant/branding` | `X-Authn-Secret-Key` or console JWT | Read the tenant's stored branding |
| `PUT` | `/v1/tenant/branding` | `X-Authn-Secret-Key` or console JWT | Replace the tenant's stored branding |

---

## Authentication & Data Boundary

**The publishable key is the only credential, and that is deliberate.** The document has to answer before anyone has signed in, so no session token exists to demand.

What the key buys is **scope, not trust**. It resolves the tenant, application and environment, so a caller cannot bootstrap a workspace their key does not belong to — and cannot widen the answer by naming one. A request that names a different tenant in a header or query string is answered for the tenant the *key* belongs to.

Because a publishable key ships in browser bundles, **every field in this response is effectively published**. The question asked of each one is not "is the caller authenticated" but "would this be safe printed on the sign-in page". The following are therefore withheld, and the reason is recorded in `internal/appconfig/service.go` next to the code that omits each:

| Withheld | Why |
|----------|-----|
| Recovery lockout schedule, reset window, per-window attempt cap, freeze window, claim-token TTL, trusted-device window, IPv4/IPv6 subnet widths | These are the thresholds an attack is measured against. An attacker who can read them can pace an attempt to stay under every one. A recovery screen needs to know which buttons to draw, not how patient to be. |
| `token_reuse_policy` | Tells the holder of a stolen refresh token whether replaying it is quiet or ends every session. |
| `allowed_cors_origins`, `exact_redirect_uris` | The allowlists an open-redirect or cross-origin attempt is measured against. Publishing them turns guessing a valid redirect target into reading one. |
| Social provider `client_id` and `client_secret_encrypted` | The engine performs the authorization redirect itself, so a browser never needs either. Only enabled provider **names** are returned. |
| `force_upgrade_on_signin` | Governs an existing user with a non-compliant password at their next sign-in. The sign-in response reports it at the moment it applies. |
| `domain_verification_token`, `first_admin_claimed`, `custom_domain` | Tenant internals with no bearing on rendering a sign-in page. |

The tenant's `branding_config` column is a free-form JSON object **shared with settings that are not public** — email templates among them. It is narrowed by unmarshalling into a fixed struct, so a key added to the column for another purpose is structurally incapable of reaching this response. The safety is a property of the type, not of a filter someone has to remember to update.

---

## Caching

```
Cache-Control: private, max-age=60
Vary: X-Authn-Publishable-Key, Origin
```

Both headers are load-bearing rather than conventional. The publishable key travels in a **header**, so every tenant's document lives at the same URL: a shared cache keyed on the URL alone would serve one tenant's branding and enabled providers to the next caller. `private` confines the copy to the browser that fetched it, and `Vary` keeps even that browser from mixing two applications' answers.

A minute is short enough that switching a provider on is effectively immediate, and long enough that a page reloaded mid sign-in does not re-read the tenant row each time.

---

## Endpoint Specification

### Bootstrap Request (`GET /v1/client/app-config`)
* **Headers**: `X-Authn-Publishable-Key: pk_test_...`
* **No body, no query parameters.** Tenant, application and environment come from the key.

### Bootstrap Response (`200 OK`)
```json
{
  "application": {
    "id": "app_00000000000000000000000000000001",
    "name": "Acme Web",
    "environment": "test"
  },
  "tenant": {
    "name": "Acme Corp",
    "slug": "acme"
  },
  "branding": {
    "app_name": "Acme Identity",
    "logo_url": "https://cdn.acme.example/logo.svg",
    "logo_dark_url": "https://cdn.acme.example/logo-dark.svg",
    "favicon_url": "https://cdn.acme.example/favicon.ico",
    "primary_color": "#1a73e8",
    "background_color": "#ffffff",
    "text_color": "#0f172a",
    "button_text_color": "#ffffff",
    "font_family": "Inter, -apple-system, sans-serif",
    "support_url": "https://acme.example/support",
    "terms_url": "https://acme.example/terms",
    "privacy_url": "https://acme.example/privacy",
    "custom_css": ".authn-card { border-radius: 12px }"
  },
  "sign_in_methods": {
    "password": true,
    "magic_link": true,
    "passkey": true,
    "enterprise_sso": false,
    "social_providers": ["github", "google"]
  },
  "second_factors": {
    "totp": true,
    "sms": false,
    "passkey": true,
    "recovery_codes": true,
    "push": false
  },
  "password_rules": {
    "min_length": 8,
    "max_length": 4096,
    "require_uppercase": false,
    "require_lowercase": false,
    "require_numeric": true,
    "require_special": false,
    "enforced": true
  },
  "email_verification": {
    "required": false,
    "mode": "soft"
  },
  "account_recovery": {
    "guardians": true,
    "phone_otp": false,
    "email_otp": true,
    "old_password": true,
    "security_questions": true,
    "min_guardians": 1,
    "max_guardians": 5
  }
}
```

### Missing or Invalid Key (`401 Unauthorized`)
```json
{
  "error": "missing publishable API key in X-Authn-Publishable-Key header",
  "code": "unauthorized"
}
```

A **secret key** offered in the publishable-key header is refused the same way. The two credentials answer different questions — a publishable key says *which app and which environment*, a secret key says *what you may do* — and the guard's type check is what keeps one from standing in for the other.

---

## Field Semantics

### `sign_in_methods`
Several fields are unconditionally `true`. They describe the surface the engine compiles in, and they are **reported rather than assumed** so a client reads every capability from one place instead of splitting the question between what it asks the server and what it hardcodes. A tenant that later adopts an SSO-only mandate then changes what every login page offers without a front-end deploy.

* `password`, `passkey` — always `true`. The engine's base credentials; neither has a switch.
* `magic_link` — follows the deployment's `FEATURE_MAGIC_LINK_ENABLED`.
* `enterprise_sso` — `true` when the tenant has at least one SAML connection, which is what makes a "Sign in with SSO" button worth showing. **Which** connection serves a given user is resolved per email domain by [`POST /v1/client/auth/domain-lookup`](domain-lookup.md); that is not answered here, because it depends on an address the user has not typed yet.
* `social_providers` — names of enabled providers, **sorted**. The order is stable because the response is cacheable; a map's iteration order would make each response differ from the last. Always an array, never `null`, so a client can iterate it unconditionally.

### `second_factors`
Labels an MFA challenge before the client knows which factor the user enrolled.

* `sms` — requires the deployment to name a real SMS driver. A tenant can enable phone-delivered codes on a deployment with no SMS provider configured; offering the factor there produces a button that sends a code which never arrives, and a user who waits for it instead of trying another method. An **unset** driver counts as undeliverable.
* `push` — follows `FEATURE_PUSH_2FA_ENABLED`.

### `password_rules`
The lengths are the **effective bounds**, not the stored ones. A tenant may store a minimum below the engine's own floor (`policy.MinPasswordLength`), and the engine still enforces the floor. Publishing the stored value would produce a form that accepts a password the API then rejects.

`enforced` collapses the policy's `require` and `notify` modes: a client only needs to know whether to block or to warn, and a three-state enum invites the third state to be mishandled. When `false`, the tenant is in `notify` mode — the password is accepted and the unmet criteria are reported, so a page should warn rather than block.

### `email_verification`
* `mode: "hard"` — an unverified user is refused access; show a blocking screen.
* `mode: "soft"` — an unverified user is admitted with the state flagged on the token; show a dismissible banner. Reported as `soft` when the stored value is empty, since that is both the documented default and the permissive of the two.

### `account_recovery`
Method toggles and guardian counts only. `phone_otp` additionally requires a real SMS driver, for the same reason as `second_factors.sms`. The enrolment screen needs `min_guardians` and `max_guardians` in order to validate before submitting.

---

## Degradation

**This endpoint has no failure path beyond the guard.** A page that cannot bootstrap cannot sign anyone in, so every read behind it degrades rather than propagating:

| Failure | Result |
|---------|--------|
| Tenant row unreadable | Empty branding, no social providers — an unstyled page that still signs users in. Logged, because unlike a policy default an unreadable tenant row is always a fault. |
| Branding column no longer parses | Empty branding rather than a partial one. |
| A policy row missing or unparseable | That policy's documented default, which is the safe rather than the permissive option. |
| SAML table unreadable | `enterprise_sso: false` — hides an SSO button the tenant has rather than offering one it lacks. |
| Application row missing | `application.name` empty; `id` and `environment` still come from the key. |
| One malformed social provider entry | That entry is skipped; the rest still render. |

An unconfigured tenant — the state every tenant starts in — is a fully renderable document of defaults. A sign-in page that could not bootstrap until an administrator had uploaded a logo would leave every new tenant unable to sign anyone in.

---

## Branding Administration

### Read (`GET /v1/tenant/branding`)
* **Headers**: `X-Authn-Secret-Key: sk_test_...` (or `Authorization: Bearer <console JWT>`)
* **Response** (`200 OK`): the `branding` object shown above.

### Write (`PUT /v1/tenant/branding`)
* **Headers**: `X-Authn-Secret-Key: sk_test_...` (or `Authorization: Bearer <console JWT>`)
* **Body**: the full `branding` object. The stored column is **replaced, not merged** — branding is edited as a whole form, and a merge would make clearing a logo impossible, since an empty string and an absent key are indistinguishable after a JSON round trip.
* **Response** (`200 OK`): what was stored, after normalization. Values are trimmed, and a scheme-less URL resolves to `https` rather than `http` so a pasted URL is never silently downgraded to cleartext.

**A publishable key is refused here (`401`).** Anyone who loads a sign-in page holds one; if that key could write branding, it could rewrite the stylesheet of every sign-in page the tenant serves.

### Validation (`400 Bad Request`)

Branding is interpolated into a `<style>` element and into individual CSS declarations, so a value that can escape either context is a **stored cross-site script in the one place a user is about to type their password**. Nothing is clamped into range: a colour or a URL cannot be corrected into a valid one, and silently dropping a logo an administrator believes they set is worse than refusing the write. The error names the offending field.

| Field | Rule |
|-------|------|
| `app_name` | Sanitized, ≤ 100 characters. Markup is refused. |
| `logo_url`, `logo_dark_url`, `favicon_url`, `support_url`, `terms_url`, `privacy_url` | `http(s)` only. `javascript:` and `data:` are refused. |
| `primary_color`, `background_color`, `text_color`, `button_text_color` | Hex only — `#rgb`, `#rrggbb` or `#rrggbbaa`. Constrained to this grammar rather than accepting any CSS colour, because a free-form value can carry a whole declaration (`red; behavior: url(…)`). |
| `font_family` | ≤ 200 characters; `;` `{` `}` `<` `>` and control characters refused. These are what let a value end one declaration and start another, and no legitimate font list contains one. |
| `custom_css` | ≤ 16 KiB; `<` `>` and control characters refused. `</style><script>` would close the element and execute. The cost is that a `width < 400px` container query must be written in the `max-width` form. |

Every field may be empty. Empty is the documented "inherit the client's own defaults" state, not fourteen missing required fields.

```json
{
  "error": "custom_css must not contain < or >, which would let a payload escape the <style> element",
  "code": "validation_failed"
}
```

An unprovisioned tenant answers `404` — a settings write never creates the tenant it addresses.

---

## Related

* [`POST /v1/client/auth/domain-lookup`](domain-lookup.md) — resolves which SAML connection serves a typed email domain, once `enterprise_sso` is `true`.
* [`GET`/`PUT /v1/tenant/password-policy`](../openapi.yaml) — the administrative view of the policy `password_rules` projects.
* [`GET`/`PUT /v1/tenant/recovery-policy`](../openapi.yaml) — the administrative view of the policy `account_recovery` projects.
