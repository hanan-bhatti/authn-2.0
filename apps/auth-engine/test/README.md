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
| `harness_test.go` | Shared setup: engine wiring, email capture, request helpers |
| `refresh_token_test.go` | Rotation on use, grace window, reuse detection and session revocation, native-client body path, unknown tokens |
| `email_verification_test.go` | Verification round trip, expired token rejection, the disabled/soft/hard policy modes, and unblocking a hard-mode account |
| `magic_link_test.go` | Auto-provisioning, session issuance, single-use enforcement, unknown tokens |
| `ratelimit_test.go` | Resend-verification budget, fail-closed 503 and fail-open pass-through |

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
