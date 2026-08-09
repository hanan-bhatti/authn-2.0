# Backend Audit — auth-engine

**Date:** 2026-08-07
**Scope:** `apps/auth-engine` — route registration, middleware wiring, authorization enforcement, token handling. Driven by the SDK coverage work; every domain the SDK was meant to wrap got read at the Go source level.
**Method:** static reading of the Go source. Every finding below is anchored to a `file:line` I actually read. No findings are inferred from docs, and none were reproduced against a running server — the exploit paths are code-reading conclusions and should be confirmed with a live request before or after fixing.

---

## Summary

| Severity | Count |
|---|---|
| Critical | 3 |
| High | 8 |
| Medium | 9 |
| Low / Docs | 5 |

The three Critical findings are one exploit chain: **the entire B2B organizations API under `/v1/client` has no user authentication and no authorization checks.** A publishable key is public by design — it ships in your frontend JavaScript bundle. Anyone who reads your page source can currently delete every organization in your tenant.

The High findings cluster into two themes: **secrets that are supposed to travel by email are returned in HTTP response bodies instead** (which silently converts "verify your new email address" into "no verification at all"), and **security middleware that only inspects the `Authorization` header while the auth layer also accepts cookies** (so a cookie-based session skips the guard).

---

## CRITICAL

### C1 — The client organizations API has no user authentication

`internal/org/handler.go:35`
```go
clientGroup := app.Group("/v1/client", pkMiddleware)
```

The comment directly above it says *"requires Publishable Key & User Identity."* It does not require user identity. Compare the wiring in `cmd/server/main.go`:

```go
main.go:289   userHandler.RegisterRoutes(app, clientAuthMiddleware, pkMiddleware)   // ← gets client auth
main.go:298   orgHandler.RegisterRoutes(app, pkMiddleware, adminMiddleware)         // ← does not
```

`org.RegisterRoutes` has signature `(app, pkMiddleware, adminMiddleware)` — there is no parameter for `clientAuthMiddleware`, so it was never possible to pass it. This is not a call-site typo; the handler was written without the slot.

The consequence flows through the identity helper. `org/handler.go:75-77`:
```go
func getUserID(c *fiber.Ctx) string { return rbac.ExtractUserID(c) }
```

`rbac.ExtractUserID` (`internal/rbac/middleware.go:21-33`) reads only Fiber locals `userID`, `user_id`, `console_user_id`. The two middlewares that actually run on this group set none of them:

- `RequirePublishableKey` (`internal/middleware/publishable_key.go:56-58`) sets `tenant_id`, `application_id`, `environment` — no user.
- `PreventImpersonatedMutations` (`internal/middleware/impersonation_guard.go:22-55`) sets no locals at all.

So **`getUserID(c)` returns `""` on every request to every client organization route.** And not one of the eleven handlers checks for it — verified at every call site: lines 83, 120, 138, 162, 202, 226, 251, 272, 317. Each passes the empty string straight into the service layer.

**Affected routes** (`org/handler.go:38-53`) — all reachable with nothing but a publishable key:
```
POST   /v1/client/organizations
GET    /v1/client/organizations
GET    /v1/client/organizations/:orgId
PATCH  /v1/client/organizations/:orgId
DELETE /v1/client/organizations/:orgId
GET    /v1/client/organizations/:orgId/members
POST   /v1/client/organizations/:orgId/members
PATCH  /v1/client/organizations/:orgId/members/:userId
DELETE /v1/client/organizations/:orgId/members/:userId
POST   /v1/client/organizations/:orgId/invitations
GET    /v1/client/organizations/:orgId/invitations
DELETE /v1/client/organizations/:orgId/invitations/:invitationId
POST   /v1/client/invitations/accept
```

---

### C2 — The organization service performs no authorization checks

C1 would be survivable if the service layer re-checked. It does not. I read every mutator in `internal/org/service.go` and grepped for any authorization construct (`requireOrgAdmin`, `isOrgAdmin`, `checkMember`, `ErrForbidden`, `ErrNotAuthorized`, `ErrInsufficient`) — **there are none in the file.**

`actorID` is threaded through every mutator and used *only* for audit logging and provenance columns:

| Function | Line | What `actorID` is used for |
|---|---|---|
| `CreateOrganization` | 87 | membership row (138-144), audit (153) |
| `GetOrganization` | 172 | **does not accept an actor at all** |
| `UpdateOrganization` | 248 | audit only (295) |
| `DeleteOrganization` | 311 | audit only (333) |
| `AddMember` | 383 | `SetAssignedByUserID` (422-423), audit (432) |
| `UpdateMemberRole` | 450 | `SetUpdatedByUserID` (473-474), audit (482) |
| `RemoveMember` | 492 | audit only (510) |

`DeleteOrganization` at `service.go:311-341` looks the organization up by tenant + ID, then:
```go
service.go:325   _, _ = client.OrgMember.Delete().Where(orgmember.OrganizationID(orgID)).Exec(ctx)
service.go:326   _, _ = client.OrgInvitation.Delete().Where(orginvitation.OrganizationID(orgID)).Exec(ctx)
service.go:328   if err := client.Organization.DeleteOne(o).Exec(ctx); err != nil {
```

No membership check, no role check, no ownership check. The two cascade deletes also discard their errors.

**Failure scenario.** An attacker views source on your marketing site, copies `pk_live_...`, and enumerates org IDs from any endpoint that returns them (`GET /v1/client/organizations/:orgId` is itself unauthenticated, so IDs harvested from an invitation email or a support screenshot are enough):

```
curl -X DELETE https://api.example.com/v1/client/organizations/org_a1b2c3d4e5f6 \
     -H "X-Authn-Publishable-Key: pk_live_..."
```

Every member row and every pending invitation for that organization is destroyed, then the organization itself. The audit log records the actor as the empty string.

The same key also grants `POST .../members` (add yourself, or anyone, to any org — `AddMemberRequest` takes a raw `user_id`, `org/types.go`), `PATCH .../members/:userId` (escalate any member's role), and `PATCH /organizations/:orgId` (rewrite any org's name/slug/metadata).

`ListUserOrganizations` is the accidental exception: with `userID == ""` it queries `orgmember.UserID("")` (`service.go:200`), which matches nothing. It leaks no data, but it also means the endpoint is simply broken for legitimate callers.

---

### C3 — Invitation acceptance trusts an attacker-supplied user ID

`internal/org/handler.go:337-343`
```go
userID := getUserID(c)
if userID == "" {
    userID = c.Query("user_id") // Fallback query param if anonymous acceptance
}
if userID == "" {
    userID = "usr_accepted_guest"
}
```

Because of C1, `getUserID(c)` is *always* `""` here, so the fallback is not an edge case — it is the only path. The user ID that gets written as the new organization member is read verbatim from the query string.

**Failure scenario.** Anyone holding an invitation token — forwarded email, leaked link, or a token they minted themselves via the equally-unauthenticated `POST /organizations/:orgId/invitations` — can bind that invitation to an arbitrary account:

```
POST /v1/client/invitations/accept?user_id=usr_victim_account
```

If no `user_id` is supplied, every anonymous acceptance across the entire deployment collapses onto the single shared literal `"usr_accepted_guest"`, which is not a real user. That row will satisfy membership queries for a principal that does not exist.

---

## HIGH

### H1 — Three divergent implementations of permission matching, one of which grants `users:*` to everyone

There are three separate copies of the wildcard-matching logic, and they do not agree.

**1. `internal/rbac/middleware.go:102-116` — the real request gate.**
```go
func hasPermission(granted, required string) bool {
    if granted == "*" || granted == required { return true }
    if strings.HasSuffix(granted, ":*") {
        prefix := strings.TrimSuffix(granted, "*")
        return strings.HasPrefix(required, prefix)
    }
    if strings.HasPrefix(granted, "*:") {
        suffix := strings.TrimPrefix(granted, "*")
        return strings.HasSuffix(required, suffix)
    }
    return false
}
```

**2. `internal/rbac/policy.go:61-76` — `isPermissionMatch`, structurally identical to the above.** Duplicated rather than shared, so the two can drift.

**3. `internal/rbac/service.go:162-179` — the outlier.**
```go
for _, p := range perms {
    if p == "*" || p == requiredPerm || p == "users:*" || p == "impersonate:*" {
        return true, nil
    }
}
```

Read the third one carefully: the comparisons against `"users:*"` and `"impersonate:*"` are on `p` — the permission the subject *holds* — not on `requiredPerm`. It does not mean "a holder of `users:*` passes a `users:read` check." It means **any subject holding `users:*` or `impersonate:*` passes _every_ permission check**, including `billing:delete`, `apikeys:manage`, or anything else. It is a universal grant.

It also implements no wildcard logic whatsoever, so a subject holding `billing:*` fails a `billing:read` check here while passing it in the middleware.

Which one runs depends on the call path. Anywhere `Service.HasPermission` is consulted instead of the `RequirePermission` middleware, the broken one is authoritative. This needs to be one function.

Related, in the same file: `RequirePermission` (`middleware.go:34`) bypasses on roles `tenant_admin`, `admin`, `super_admin`; `RequireRole` (`middleware.go:72`) bypasses on only `tenant_admin` and `super_admin` — `admin` is omitted. One of the two lists is wrong.

**Note for the SDK:** the client-side `hasPermission` in `usePermissions()` should replicate `middleware.go:102-116` plus the admin-role bypass, *not* `service.go`. Client-side checks are UI affordance only and must never be the enforcement boundary, but they should at least agree with the gate that actually runs.

---

### H2 — Email-change verification tokens are returned in the API response body

`internal/user/handler.go:161`
```go
"verification_token": tokenStr,
```
and again at `internal/user/handler.go:215` for the recovery email flow.

The purpose of emailing a verification token is to prove the caller controls the target mailbox. Returning that token in the HTTP response to the caller who requested the change removes the proof entirely — the requester can read the token from their own response and immediately POST it back.

**Failure scenario.** An attacker with a hijacked session (XSS, a borrowed device, a stolen access token) calls `POST /v1/client/user/email` with `new_email: attacker@evil.com`, reads `verification_token` out of the JSON response, and calls `GET /v1/client/user/email/verify?token=...`. The account's email is now the attacker's, with no access to the victim's inbox at any point. Password reset then belongs to the attacker.

The same applies to the recovery email at line 215, which is worse: the recovery address is the fallback used when the primary is lost.

This looks like a debug affordance for testing. It needs to be gated behind a non-production environment check at minimum, and ideally removed.

---

### H3 — Account-recovery cancellation tokens are returned to the party initiating recovery

`internal/auth/recovery_service.go:63`
```go
CancellationToken string `json:"cancellation_token,omitempty"`
```
populated at `recovery_service.go:178` from `cancelTokenHex`, and consumed by `POST /v1/client/auth/recovery/cancel/token` (`auth/handler.go:1550-1564`).

The cancellation token exists so the *legitimate owner*, on receiving an unexpected "someone is trying to recover your account" email, can halt the recovery. Returning it in the response to `InitiateRecovery` hands it to whoever started the recovery.

**Failure scenario.** An attacker initiates recovery against a victim's account and captures the cancellation token from the response. The victim receives the alert email and clicks cancel. Meanwhile the attacker holds the same token — and depending on single-use semantics, either the attacker cancels first to suppress the victim's own alert-driven cancellation, or the token is simply no longer a control the victim uniquely possesses. Either way the one mechanism designed to let an owner veto an account takeover is now shared with the adversary.

---

### H4 — Refresh-token cookies are set with `Secure: false`

```
internal/auth/handler.go:397    Secure: false
internal/auth/handler.go:525    Secure: false
internal/auth/handler.go:786    Secure: false     (VerifyTOTP)
internal/auth/handler.go:1080   Secure: false     (FinishWebAuthnLogin)
internal/auth/handler.go:1512   Secure: true      (authn_td_token, ClaimAccount)
```

Four of five long-lived-credential cookies omit the `Secure` attribute; the fifth sets it. The inconsistency suggests the four were not deliberate.

Without `Secure`, the browser will attach the refresh token to a plaintext `http://` request to the same host. An attacker on a shared network who can inject any resource reference over HTTP (or force a navigation to `http://your-domain/anything`) harvests a refresh token, which is the longest-lived credential in the system. HSTS mitigates this but only after the first successful HTTPS visit, and only for hosts already in the preload list or with a live HSTS entry.

The two MFA-completion paths (786, 1080) are the most damaging, because a token issued after a successful second factor is the one that represents a fully elevated session.

---

### H5 — The OAuth callback places the access token in a redirect URL query string

`internal/social/handler.go:98`
```go
redirectURL := postCallbackRedirect + "?access_token=" + accessToken
return c.Redirect(redirectURL, fiber.StatusFound)
```

Two distinct problems.

**Token in the query string.** URLs land in browser history, server access logs, proxy logs, and the `Referer` header of any subsequent cross-origin subresource request from the landing page. An access token in a query parameter should be assumed logged in several places you do not control. The URL fragment (`#access_token=`) is the conventional alternative because fragments are not sent to servers; a short-lived one-time code exchanged from the client is better still.

**Naive concatenation.** The `?` is appended unconditionally and neither component is escaped. If `postCallbackRedirect` already contains a query string — `https://app.example.com/cb?tenant=acme` — the result is `...?tenant=acme?access_token=...`, and the second `?` is parsed as part of the `tenant` value. The token silently fails to arrive and login appears to hang. Use `net/url` to parse and set the parameter.

Worth separately confirming that `postCallbackRedirect` is validated against a registered allowlist before being used as a redirect target; if it is caller-influenced, this is also an open redirect that forwards a live access token to an attacker-chosen host. I did not trace its origin in `HandleCallback` — flagging it for follow-up rather than asserting it.

---

### H6 — The impersonation guard reads only the `Authorization` header, but the auth layer also accepts cookies

`internal/middleware/impersonation_guard.go:24-27`
```go
authHeader := c.Get("Authorization")
if !strings.HasPrefix(authHeader, "Bearer ") {
    return c.Next()
}
```

`internal/middleware/client_auth.go:26-34` accepts a token from **three** sources, in this order:
```go
if tok := c.Cookies("authn_access_token"); tok != "" { tokenStr = tok }
else if tok := c.Cookies("access_token"); tok != "" { tokenStr = tok }
else { /* Authorization: Bearer */ }
```

Cookies take priority. So a session authenticated by cookie — which is the default for the web client type — presents no `Authorization` header, the guard returns `c.Next()` at line 26, and `IsImpersonated` is never evaluated.

**Failure scenario.** A support engineer starts an impersonation session in a browser-based console. The impersonated access token is set as a cookie. Every "destructive account mutation" the guard was written to block — deleting the account, changing the password, disabling 2FA — proceeds normally, and the audit trail shows it performed under the impersonated user's identity.

The guard must extract the token using the same precedence as `RequireClientAuth`. Best fixed by extracting a single shared `extractAccessToken(c)` helper used by both.

---

### H7 — `POST /2fa/totp/disable` is not covered by the impersonation guard's path matching

`internal/middleware/impersonation_guard.go:39-43`
```go
isDestructiveMutation := (method == "DELETE" && strings.Contains(path, "/account")) ||
    (method == "PUT"    && strings.Contains(path, "/password")) ||
    (method == "POST"   && strings.Contains(path, "/password")) ||
    (method == "DELETE" && strings.Contains(path, "/2fa")) ||
    (method == "POST"   && strings.Contains(path, "/2fa/disable"))
```

Checked against the real route table (`auth/handler.go:148-171`, `user/handler.go:72-80`):

| Route | Method | Matched? |
|---|---|---|
| `/v1/client/user/account` | DELETE | yes (`/account`) |
| `/v1/client/user/password` | POST | yes (`/password`) |
| `/v1/client/2fa/sms/disable` | DELETE | yes (DELETE + `/2fa`) |
| `/v1/client/2fa/webauthn/credentials/:id` | DELETE | yes (DELETE + `/2fa`) |
| **`/v1/client/2fa/totp/disable`** | **POST** | **no** |

The last clause looks for the literal substring `/2fa/disable`, but the actual path is `/2fa/totp/disable`. `strings.Contains("/v1/client/2fa/totp/disable", "/2fa/disable")` is `false`, and the DELETE-based clause does not apply because the route is registered as `POST` (`auth/handler.go:152`).

**Failure scenario.** An impersonating operator disables the target user's TOTP — the highest-value destructive action in the list, since it strips the second factor guarding everything else — and the guard permits it.

Substring matching over paths is the underlying fragility here; every new route silently opts out of the guard by default. Prefer an explicit route-to-policy table, or enforce at the handler.

---

### H8 — `errorsIs` compares error strings instead of using `errors.Is`

`internal/auth/handler.go:663-665`
```go
func errorsIs(err error, target error) bool {
    return err != nil && err.Error() == target.Error()
}
```

This breaks in both directions.

**False negatives.** Any error the service layer wraps with `fmt.Errorf("...: %w", err)` has a different `.Error()` string and will not match, even though `errors.Is` would unwrap it correctly. The handler falls through to its generic branch and returns 500 where it should return 401/404/409. This is exactly the pattern used elsewhere in the codebase — `internal/org/handler.go:167` uses real `errors.Is(err, ErrOrgNotFound)` — so the two halves of the codebase behave differently on wrapped errors.

**False positives.** Two distinct sentinels with identical message text become interchangeable, so an error can be routed to the wrong branch and produce the wrong status and the wrong client-facing message.

The fix is to delete this function and call `errors.Is` directly. Worth doing before the SDK maps status codes to `AuthnErrorCode`, because right now a wrapped credential error surfaces to the client as an opaque 500 and the SDK cannot classify it.

---

## MEDIUM

### M1 — Roughly ten handlers re-implement JWT verification inline

`internal/auth/handler.go` registers every route on `api := app.Group("/v1/client")` with only the publishable-key middleware and a shared rate limiter (`handler.go:137-197`). Authenticated handlers therefore each do their own `extractBearerToken` + `jwtpkg.VerifyAccessToken`. The 2FA enroll/confirm/disable handlers, the WebAuthn registration handlers, the recovery-code handlers and others all carry their own copy.

`middleware.RequireClientAuth` exists and does this correctly, including cookie fallback. Ten hand-rolled copies means ten places to get the error envelope, the status code, or the cookie precedence subtly different — and H6 is a direct consequence of exactly this kind of divergence.

### M2 — The session handler implements its own auth layer

`internal/session/handler.go:35` registers `/v1/client/sessions` with `pkMiddleware` only, and `getUserIDAndSessionID` (`session/handler.go:50-85`) parses and verifies the bearer token itself.

The token *is* signature-verified (`jwtpkg.VerifyAccessToken`, line 71), so this is not a bypass. But it accepts identity from locals `user_id` / `userID` / `console_user_id` and `session_id` / `sessionID` **before** falling back to verifying a token — and on this route group, nothing sets those locals. The precedence is inverted relative to a defense-in-depth design, and it will misbehave the moment any upstream middleware starts setting them.

Additionally it reads no cookie, so a cookie-authenticated web session cannot list or revoke its own sessions.

### M3 — Silent `tnt_default` tenant fallback

`internal/org/handler.go` `getTenantID` falls back to the literal `"tnt_default"` when no tenant is resolvable. A misconfigured or unauthenticated request does not fail — it silently operates against a real tenant. Combined with C1/C2 this widens the blast radius; independently it turns configuration errors into cross-tenant data operations. Fail closed instead.

### M4 — `pkMiddleware` executes twice on every protected user route

`internal/user/handler.go:54-70` creates two Fiber groups on the *same* prefix `/v1/client/user`:
```go
pubGroup := app.Group("/v1/client/user")
if pkMw != nil { pubGroup.Use(pkMw) }        // registration #1
pubGroup.Get("/email/verify", ...)
pubGroup.Get("/recovery-email/verify", ...)

group := app.Group("/v1/client/user")
if pkMw != nil { group.Use(pkMw) }           // registration #2 — same prefix
if clientAuthMw != nil { group.Use(clientAuthMw) }
```

Fiber matches its stack in registration order, so the public verify routes (registered before `clientAuthMw`) correctly stay unauthenticated. But every protected route runs `pkMw` **twice**, and `RequirePublishableKey` performs a database `ValidateKey` lookup (`publishable_key.go:43`) — two DB round-trips per request instead of one, on the hottest path in the user API.

More importantly this is order-dependent security. Moving the `pubGroup` route registrations below line 69 would silently place them behind `clientAuthMw`; moving the protected routes above it would silently expose them. Nothing in the code signals that the ordering is load-bearing. Use distinct prefixes or attach middleware per-route.

### M5 — Login and 2FA verification share one rate-limit bucket

All routes in `auth/handler.go` are built from the same `mws` handler slice (`handler.go:130-171`), so `/login` and `/2fa/totp/verify` draw from a single limiter. Password guessing and TOTP brute-forcing need very different budgets — a TOTP code is six digits and needs a *much* tighter limit, tracked per-user rather than per-IP. Sharing the bucket also means normal login volume can exhaust the allowance protecting the second factor.

### M6 — Publishable keys are accepted from query parameters

`internal/middleware/publishable_key.go:29-32`
```go
rawKey = c.Query("publishable_key")
if rawKey == "" { rawKey = c.Query("pk") }
```

Publishable keys are low-sensitivity by design, so this is not a credential leak in the usual sense. It does put the key into access logs and `Referer` headers, and it makes the key trivially harvestable for the C1/C2 attack above without even viewing page source. Prefer header-only, with the query fallback restricted to the specific redirect-based flows that genuinely cannot set a header.

### M7 — `RequireRole` and `RequirePermission` disagree on the admin bypass list

`internal/rbac/middleware.go:34` (`RequirePermission`) bypasses for `tenant_admin`, `admin`, `super_admin`.
`internal/rbac/middleware.go:72` (`RequireRole`) bypasses for `tenant_admin`, `super_admin` only.

A subject with role `admin` passes permission gates but fails role gates. Whichever is intended, the lists should be one shared constant.

### M8 — `PreventImpersonatedMutations` fails open on token verification errors

`internal/middleware/impersonation_guard.go:31-33`
```go
if err != nil || claims == nil {
    return c.Next()
}
```

Defensible — real authentication happens downstream, so an invalid token will be rejected there. But combined with H6 (cookie sessions skip the guard entirely) the guard has two independent ways to not run, and neither is logged. At minimum, emit a warning when a token fails to parse here.

### M9 — Inconsistent error envelopes and status codes

Some handlers return `{"error": "..."}`, others `{"error": "...", "code": "..."}` (e.g. `social/handler.go:87-88`, `impersonation_guard.go:47-48`). Several return `500` with `err.Error()` passed straight through to the client (`social/handler.go:94`), which leaks internal error text — including, potentially, wrapped database errors.

This directly affects the SDK: `AuthnError.fromResponse` reads `body.message` then `body.error`, and `mapHttpStatusToCode` substring-matches on `code` + `message`. Without a stable machine-readable `code` on every error, the SDK cannot reliably classify failures and consumers are left string-matching on human-readable prose. **A consistent `{ error, code }` envelope across all handlers is a prerequisite for good SDK error typing.**

---

## LOW / DOCUMENTATION

### D1 — Six real routes are absent from `docs/endpoints/`

Confirmed present in `auth/handler.go:148-171` but undocumented:

```
POST   /v1/client/2fa/totp/verify
POST   /v1/client/auth/2fa/verify          (alias of the above — handler.go:154)
POST   /v1/client/2fa/sms/confirm
DELETE /v1/client/2fa/sms/disable
POST   /v1/client/2fa/webauthn/login/begin
POST   /v1/client/2fa/webauthn/login/finish
```

### D2 — The `mfa_required` login response is undocumented

`AuthResponse` (`auth/handler.go:49-58`) carries `mfa_required`, `mfa_token`, and `methods`. None appear in the endpoint docs, so an integrator has no way to learn that a successful-looking `200` from `/login` may not contain a session. This is the single most important gap for SDK consumers.

### D3 — `verify_totp` uses `mfa_token`, not a bearer token

`POST /2fa/totp/verify` authenticates with the `mfa_token` from the login response rather than `Authorization: Bearer`. Undocumented, and it is a different auth context from every other route in the file.

### D4 — WebAuthn finish endpoints read parameters from the query string

`register/finish` and `login/finish` read `session_id` / `mfa_token` via `c.Query` with a body fallback, then re-wrap `c.Body()` for the `go-webauthn` library, which requires the raw credential JSON as the entire body. Undocumented, and it means these two endpoints cannot use the normal "merge params into the JSON body" convention every other endpoint follows.

### D5 — `CancelRecoveryAuth` reads `c.Locals("userID")` on an unauthenticated route group

`auth/handler.go:1351-1570`. `POST /v1/client/auth/recovery/cancel` is registered on the `api` group, which has no client auth middleware, yet the handler reads `c.Locals("userID")`. That local is never set, so the authenticated cancellation path is dead code — only the token-based variant at `/cancel/token` can function. Same root cause as C1.

---

## Recommended order of work

1. **C1 + C2 + C3 together.** Add a `clientAuthMw` parameter to `org.RegisterRoutes`, pass `clientAuthMiddleware` from `main.go:298`, reject empty `userID` in every handler, delete the `user_id` query fallback and the `usr_accepted_guest` sentinel, and add membership/role checks in `org/service.go` for every mutator. These are not independently useful — the middleware alone still leaves the service unauthorized, and the service checks alone have no identity to check.
2. **H2 + H3.** Remove the tokens from the response bodies, or gate them behind a non-production environment flag. One-line changes, very large impact.
3. **H6 + H7.** Extract a shared `extractAccessToken(c)` used by both `RequireClientAuth` and the impersonation guard; replace substring path matching with an explicit route policy table.
4. **H4.** Set `Secure: true` on the four refresh-token cookies, driven by config so local HTTP development still works.
5. **H1.** Collapse the three permission matchers into one exported function and delete the `users:*` / `impersonate:*` universal grant in `service.go`.
6. **H8 + M9.** Replace `errorsIs` with `errors.Is`, and standardize on a `{ error, code }` envelope. Both are prerequisites for the SDK error-typing work.
7. **H5, M1–M8, D1–D5** as follow-up.

---

## Impact on the SDK work

Three findings change what the SDK should be built against, so they are worth resolving — or at least deciding on — before Domain 2 and Domain 7:

- **C1/C2 (organizations).** Domain 7 wraps thirteen endpoints that currently take no user identity. If the fix adds `clientAuthMiddleware`, the SDK methods are unchanged in shape but will start receiving `401` where they previously received `200` — so the tests should be written against the *fixed* contract, not the current one. Building Domain 7 against today's behavior would bake the vulnerability into the client's expectations.
- **H2 (`verification_token` in the body).** `requestEmailChange` and `setRecoveryEmail` currently return a token. The SDK should **not** expose it in the return type — surfacing it would make the leak part of the public API contract and turn a server fix into an SDK breaking change.
- **M9 (error envelopes).** `AuthnError` classification quality is capped by how consistently the backend emits a machine-readable `code`.

Everything else can be wrapped as-is.

---

## Resolution — 2026-08-10

All 25 findings are closed. Verified by re-reading the source against each
finding, not from commit messages. Build, vet and gofmt clean; 23 unit packages
and the integration suite pass.

| Finding | Resolution |
|---|---|
| C1 | `org.RegisterRoutes` takes `clientAuthMw`; `main.go` passes it |
| C2 | `authzCheckMember` / `authzRequireOrgAdmin` on every mutator |
| C3 | `user_id` query fallback and `usr_accepted_guest` deleted |
| H1 | One matcher pair in `rbac/matcher.go`; universal grant deleted |
| H2 | `verification_token` no longer in any response body |
| H3 | Handler blanks `CancellationToken` before serialising |
| H4 | All cookies use `cfg.CookieSecure()`, derived from `APP_BASE_URL` |
| H5 | Token moved to the URL fragment, built with `net/url`; redirect target validated against the application's registered URIs |
| H6 | Guard uses the shared `ExtractAccessToken` (cookie-then-header) |
| H7 | Explicit deny list replaces substring matching |
| H8 | `errorsIs` deleted; 117 `errors.Is` call sites, 0 string comparisons |
| M1 | Routes moved behind `RequireClientAuth`; 7 documented exceptions remain where the route cannot sit behind it |
| M2 | Session handler uses the shared extractor; cookie sessions work |
| M3 | `tnt_default` fallback replaced by `requireTenantID`, fails closed |
| M4 | One group on `/v1/client/user`, auth attached per route |
| M5 | Second-factor verification keys its bucket on the hashed challenge token, so IP rotation cannot escape it |
| M6 | Query fallback restricted to a closed allowlist of redirect landings |
| M7 | `IsPrivilegedRole` / `HasPrivilegedRole` is the single list |
| M8 | Fail-open path logs a categorised reason, without token material |
| M9 | 411 `httperr` call sites; 0 leaked `err.Error()` in any body |
| D1–D5 | Documented in `docs/endpoints/client-2fa-verification.md` and `client-login.md`; D5's dead path now verifies its own bearer token |

### Found during the work, not in this audit

- **SAML assertions were never verified.** `ProcessACS` parsed the XML, read the
  `NameID` and provisioned the user with `email_verified=true`, checking no
  signature, expiry, status, issuer or audience — on an unauthenticated
  endpoint. Pre-authentication account takeover for every SSO tenant. Now
  verified with `goxmldsig` in that order, plus single-use replay protection.
- **CORS reflected any origin with credentials enabled**, so any site a
  signed-in user visited could call this API with their cookies and read the
  replies. Now an exact-match allowlist; startup refuses wildcard + credentials.
- **Email-verification tokens never expired** — a permanent takeover primitive.
- **`expires_in` contradicted the signed `exp`**: the signer hardcoded 15
  minutes while callers advertised the configured lifetime.
- Organization metadata size was unenforced; `cmd/migrate` opened every database
  with the Postgres driver; `cmd/seed` assigned a non-existent role and
  swallowed the error.
