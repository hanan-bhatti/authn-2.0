# Integration tests

End-to-end tests for the auth engine. Each one boots the real handlers against
a private in-memory SQLite database and drives them through Fiber's in-process
test transport, so a test exercises the same routing, middleware and handler
stack the server runs — without binding a port.

These live outside `internal/` because they cross package boundaries: a single
test may touch auth, policy, session, oauth and email together. Package-local
behaviour belongs in a unit test next to the code it covers, not here.

## Running

The tests are behind a build tag, so the default suite stays fast:

```sh
# Unit tests only — does not compile or run anything in this directory.
go test ./...

# Integration tests.
go test -tags=integration ./test/...

# One test, with progress output.
go test -tags=integration -run TestRefreshTokenGraceWindow -v ./test/...
```

Without `-tags=integration` these files are excluded from the build entirely.
That is deliberate: `go test ./...` is the command run on every change, and it
should not be paying for full request round trips.

## Infrastructure

None. Every test runs self-contained.

| Dependency | How it is satisfied |
|---|---|
| Database | In-memory SQLite, one private database per test, schema created at setup |
| SMTP | Captured in-process — no mail server, no Mailpit |
| Redis | Not used; limiter tests configure the limiter directly |

Email is captured rather than delivered, which is what lets the verification and
magic-link tests complete a real token round trip: the harness reads the token
out of the message the engine actually sent, so a link that renders correctly
but carries no usable token fails here.

Redis-backed rate limiting is covered where it belongs, in
`internal/ratelimit/limiter_test.go`. `TestLimiter_RedisExponentialBackoff`
talks to a real Redis and skips itself when none is reachable.

If a future test does need external infrastructure, it must call `t.Skip` when
that infrastructure is absent. A test suite that fails on a laptop because a
container is not running gets ignored, and an ignored suite catches nothing.

## What is covered

| File | Covers |
|---|---|
| `harness_test.go` | Shared setup: engine wiring, email and SMS capture, request helpers, per-suite ceilings |
| `refresh_token_test.go` | Rotation on use, grace window, reuse detection and session revocation, native-client body path, unknown tokens |
| `email_verification_test.go` | Verification round trip, expired token rejection, the disabled/soft/hard policy modes, and unblocking a hard-mode account |
| `magic_link_test.go` | Auto-provisioning, session issuance, single-use enforcement, unknown tokens |
| `ratelimit_test.go` | Resend-verification budget, fail-closed 503 and fail-open pass-through |
| `account_status_test.go` | Restricted accounts refused at sign-in, a restriction ending a live session, an unspent magic link, a soft-deleted address staying reserved |
| `logout_test.go` | Revocation from token and from cookie alone, cookie clearing, logout-all, and the admin session routes staying unmounted without a guard |
| `admin_users_test.go` | The administrative directory: credential tier, tenant confinement, every restriction and its lifting, force-logout, paging and filtering, and the audit trail |
| `audit_logs_test.go` | Page-size cap, event-type filter, and the admin credential the listing requires |
| `app_config_test.go` | The public bootstrap document: key-derived tenant, what branding may expose, provider names without secrets, and the write path's tier |
| `platform_tenants_test.go` | Control-plane provisioning: a usable tenant, verified-email requirement, ownership records, slug rules, and caller-scoped listing |
| `tenant_isolation_test.go` | Routes ignoring a tenant supplied in a query or body, and stored session policy driving the refresh cookie |
| `privacy_write_boundary_test.go` | Writes confined to the caller's tenant, not only reads |
| `session_app_activity_test.go` | One row per session and application, both parents required, cascade on either parent's delete |
| `session_activity_writer_test.go` | Activity recorded at the request's application and carried across a refresh |
| `webhook_cascade_test.go` | An endpoint's delete taking its delivery events with it |
| `sandbox_test.go` | Test-environment message capture, inbox filtering and paging, tenant confinement, purge, and provider verification over both channels |
| `org_environment_test.go` | A workspace taking its environment from the credential, invisibility across the boundary, and a slug claimable once per environment |
| `test_quota_test.go` | The volume ceilings over HTTP: `403 test_quota_exceeded` rather than `500`, an unchanged row count behind the refusal, a live key unbounded, and no ceiling by default |
| `test_ttl_ceiling_test.go` | The lifetime ceilings over HTTP: the signed `exp`, the session row, the refresh cookie and `expires_in` all bounded at sign-in and again across a refresh, with an unbounded engine as the control |
| `live_key_test.go` | The live-key rule on webhook configuration and on SAML connections in live, with reads left open to a test key |

`refresh_token_test.go` is the only coverage of `internal/session`, which has no
unit tests of its own.

## Conventions

- Package `integration_test`; `//go:build integration` on the first line.
- Assert, do not narrate. No `fmt.Println` progress output and no `os.Exit` —
  `t.Fatalf` for a failure that makes the rest of the test meaningless,
  `t.Errorf` for one where later assertions still carry information.
- A failure message states what was expected, what happened, and why it matters.
  `got status %d, want 401` beats `assertion failed`.
- Build state through the public HTTP surface where a real client would. Reach
  for a repository directly only to set up a state no endpoint can produce, such
  as the already-expired token in `TestEmailVerificationRejectsExpiredToken`.
- Give each test its own `newTestEnv`. Databases are numbered per environment,
  so tests neither share rows nor depend on execution order.
