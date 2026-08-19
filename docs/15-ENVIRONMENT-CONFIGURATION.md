# Environment Variables & Runtime Configuration Specification

**Document Version**: 1.0.0  
**Date**: 2026-08-09  
**Status**: Approved Specification (Production Ready)  
**Author**: Authn Core Team  

---

## 1. Overview & Architectural Principles

The **Authn Engine** (`apps/auth-engine`) implements a fail-fast, zero-silent-fallback configuration architecture governed by two foundational principles:

1. **Environmental Decoupling**: No deployment-varying parameter (ports, URLs, origins, secret keys, token TTLs, or driver credentials) is hardcoded in Go source code. The exact same binary artifact runs unmodified across `development`, `test`, and `production`.
2. **Fail-Fast Pre-flight Validation**: Configuration errors are caught **once at process startup**, never mid-flight during request handling. If any variable is missing, malformed, or violates security rules for the target environment, the server aborts startup immediately with a clear error listing every offending variable.

---

## 2. Server vs. Client Variable Distinction

> [!IMPORTANT]
> **Summary of Backend Server Impact**:
> - **Sections 1 through 15b** (Variables 1–53): Loaded by `apps/auth-engine/internal/config/load.go` and directly control the Go backend server runtime, database pools, Fiber HTTP engine, rate limiters, crypto engines, and notification dispatchers.
> - **Section 16** (`NEXT_PUBLIC_AUTHN_API_URL` & `NEXT_PUBLIC_AUTHN_PUBLISHABLE_KEY`): **DO NOT affect the Go backend server**. They are built into client-side JavaScript bundles (Next.js web console and `@authn/js` browser SDK).

---

## 3. Environment Variable Master Matrix

| Section | Variable Name | Default (Dev/Fallback) | Production Rule | Go Server Impact |
| :--- | :--- | :--- | :--- | :--- |
| **1. Mode** | `APP_ENV` | `development` | Optional (`development`/`test`/`production`) | Controls validation strictness & defaults |
| **2. Server** | `HOST` | `0.0.0.0` | Optional | TCP network interface binding |
| | `PORT` | `8080` | Optional | TCP socket port listener |
| | `SERVER_READ_TIMEOUT` | `15s` | Optional | HTTP request header/body read limit |
| | `SERVER_WRITE_TIMEOUT` | `15s` | Optional | HTTP response write timeout |
| | `SERVER_IDLE_TIMEOUT` | `60s` | Optional | Keep-alive socket idle timeout |
| | `SERVER_SHUTDOWN_TIMEOUT` | `30s` | Optional | In-flight request drain limit on SIGTERM |
| | `SERVER_BODY_LIMIT_BYTES` | `4194304` (4 MiB) | Optional | Max payload size (413 Payload Too Large) |
| | `SERVER_TRUST_PROXY_HEADERS` | `false` | Optional | Reads client IP from `X-Forwarded-For` |
| **3. Public Identity** | `AUTHN_APP_NAME` | `Authn Platform` | Optional | TOTP issuer label, email headers, server banner |
| | `AUTHN_APP_VERSION` | `0.1.0` | Optional | `/v1/health` and `/healthz` response payload |
| | `APP_BASE_URL` | `http://localhost:8080` | **MANDATORY HTTPS** | Base URL for email links, OAuth callbacks, cookies |
| | `ISSUER_URL` | `http://localhost:8080` | **MANDATORY HTTPS** | OIDC `iss` claim and discovery endpoint |
| **4. CORS** | `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` | No Wildcards (`*`) | Browser cross-origin fetch allowlist |
| | `CORS_ALLOWED_METHODS` | `GET,POST,PUT,...` | Optional | `Access-Control-Allow-Methods` header |
| | `CORS_ALLOWED_HEADERS` | Default Header List | Optional | `Access-Control-Allow-Headers` header |
| | `CORS_ALLOW_CREDENTIALS` | `true` | Refuses `*` origins | `Access-Control-Allow-Credentials` header |
| | `CORS_MAX_AGE` | `12h` | Optional | `Access-Control-Max-Age` preflight cache TTL |
| **5. Database** | `DATABASE_URL` | `sqlite://file:authn.db...` | **MANDATORY** | Database driver (Postgres/MySQL/SQLite) |
| | `DATABASE_MAX_OPEN_CONNS` | `25` | Optional | SQL connection pool max open count |
| | `DATABASE_MAX_IDLE_CONNS` | `5` | Optional | SQL connection pool max idle count |
| | `DATABASE_CONN_MAX_LIFETIME` | `30m` | Optional | SQL connection pool max socket age |
| | `DATABASE_AUTO_MIGRATE` | `true` | **MUST BE FALSE** | Auto Ent schema migrations on boot |
| **6. Redis** | `REDIS_URL` | `redis://localhost:6379` | **MANDATORY** | Redis connection URI |
| | `REDIS_REQUIRED` | `false` | Default `true` in Prod | Startup failure on Redis connection error |
| **7. Secrets** | `AUTHN_ENCRYPTION_KEY` | `""` | **MANDATORY** ($\ge 32$ chars) | AES-256-GCM encryption key for secrets |
| | `AUTHN_API_KEY_PEPPER` | `""` | **MANDATORY** ($\ge 32$ chars) | HMAC pepper for API key hashes |
| | `JWT_KEY_ID` | `key_v1` | Optional | JWKS key identifier (`kid` header) |
| | `JWT_SIGNING_KEY_PATH` | `.keys/rsa_private.pem` | **MANDATORY File** | RSA private key file path for OIDC tokens |
| **8. Lifetimes** | `ACCESS_TOKEN_TTL` | `15m` | `< REFRESH_TOKEN_TTL` | Short-lived access JWT lifetime |
| | `REFRESH_TOKEN_TTL` | `720h` (30 days) | `> ACCESS_TOKEN_TTL` | Long-lived refresh token session lifetime |
| | `SESSION_GRACE_PERIOD` | `10s` | `< ACCESS_TOKEN_TTL` | Rotation concurrency grace window |
| | `EMAIL_VERIFICATION_TTL` | `24h` | Optional | Email verification token expiration |
| | `MAGIC_LINK_TTL` | `15m` | Optional | Passwordless magic link token expiration |
| | `MFA_CHALLENGE_TTL` | `5m` | Optional | 2FA step-up challenge expiration |
| | `SOCIAL_AUTH_STATE_TTL` | `10m` | Optional | OAuth2 state parameter expiration |
| | `OAUTH_CODE_TTL` | `10m` | Max `10m` (RFC 6749) | OAuth2 authorization code expiration |
| | `ID_TOKEN_TTL` | `1h` | Optional | OpenID Connect ID token expiration |
| | `RECOVERY_TOKEN_TTL` | `1h` | Optional | Account recovery token expiration |
| | `INVITATION_TTL` | `168h` (7 days) | Optional | Org member invitation link expiration |
| **8b. Retention** | `RETENTION_SWEEP_INTERVAL` | `15m` | Optional | Background sweep frequency and per-pass budget |
| | `SUPERSEDED_SESSION_RETENTION` | `72h` | Optional | Width of the refresh-token theft-detection window |
| | `TERMINAL_SESSION_RETENTION` | `720h` (30 days) | Keep `>= REFRESH_TOKEN_TTL` | How long sign-in history is readable |
| | `SANDBOX_MESSAGE_RETENTION` | `24h` | Optional | Lifetime of a captured test-environment message |
| | `TEST_USER_RETENTION` | `720h` | Optional | Idle window before a test account is deleted |
| | `RETENTION_BATCH_SIZE` | `1000` | Optional | Rows deleted per sweep statement |
| **9. Rate Limit** | `RATELIMIT_ENABLED` | `true` | Optional | Enables/disables IP & user rate limiting |
| | `RATELIMIT_MAX_ATTEMPTS` | `5` | Optional | Account attempt budget per window |
| | `RATELIMIT_WINDOW` | `15m` | Optional | Rate limit budget reset window |
| | `RATELIMIT_IP_BUDGET_MULTIPLIER` | `10` | Optional | IP-level budget multiplier ($5 \times 10 = 50$) |
| | `RATELIMIT_BACKOFF_SCHEDULE` | `15m,1h,6h,24h` | Optional | Escalating lockout durations |
| | `RATELIMIT_VIOLATION_RESET_DAYS` | `7` | Optional | Days clean before lockout tier drops |
| | `RATELIMIT_FAIL_CLOSED` | `false` | Default `true` in Prod | Block traffic if Redis is unreachable |
| | `RESEND_RATELIMIT_ENABLED` | `true` | Optional | Enables email resend rate limiter |
| | `RESEND_RATELIMIT_MAX_ATTEMPTS` | `3` | Optional | Max email resends allowed per window |
| | `RESEND_RATELIMIT_WINDOW` | `1h` | Optional | Email resend rate limit window |
| **10. Email** | `EMAIL_DRIVER` | `noop` | `smtp/resend/sendgrid/...` | Outbound email provider selection |
| | `EMAIL_FROM_ADDRESS` | `noreply@authn.local` | Valid email | Email `From:` header address |
| | `EMAIL_FROM_NAME` | `Authn` | Optional | Email `From:` display name |
| | `SMTP_HOST` | `localhost` | Required if `smtp` | SMTP server hostname |
| | `SMTP_PORT` | `1025` | Required if `smtp` | SMTP server port |
| | `SMTP_USER` | `""` | Optional | SMTP authentication username |
| | `SMTP_PASSWORD` | `""` | Optional | SMTP authentication password |
| | `RESEND_API_KEY` | `""` | Required if `resend` | Resend API key |
| | `SENDGRID_API_KEY` | `""` | Required if `sendgrid` | SendGrid API key |
| | `POSTMARK_SERVER_TOKEN` | `""` | Required if `postmark` | Postmark Server Token |
| | `AWS_ACCESS_KEY_ID` | `""` | Required if `aws_ses` | AWS Access Key ID for SES |
| | `AWS_SECRET_ACCESS_KEY` | `""` | Required if `aws_ses` | AWS Secret Access Key for SES |
| | `AWS_REGION` | `us-east-1` | Required if `aws_ses` | AWS Region for SES |
| **11. SMS** | `SMS_DRIVER` | `noop` | `twilio/messagebird/...` | Outbound SMS provider selection |
| | `TWILIO_ACCOUNT_SID` | `""` | Required if `twilio` | Twilio Account SID |
| | `TWILIO_AUTH_TOKEN` | `""` | Required if `twilio` | Twilio Auth Token |
| | `TWILIO_FROM_NUMBER` | `""` | Required if `twilio` | Twilio E.164 From phone number |
| | `MESSAGEBIRD_ACCESS_KEY` | `""` | Required if `messagebird` | MessageBird Access Key |
| | `MESSAGEBIRD_ORIGINATOR` | `Authn` | Required if `messagebird` | MessageBird sender ID |
| **12. WebAuthn** | `WEBAUTHN_RP_ID` | `localhost` | **MUST NOT be localhost** | Passkey Relying Party domain |
| | `WEBAUTHN_RP_ORIGINS` | `http://localhost:8080,...` | Origins match RP ID | Allowed passkey ceremony origins |
| | `WEBAUTHN_RP_DISPLAY_NAME` | `Authn Platform` | Optional | Passkey prompt display title |
| **13. SAML** | `SAML_ACS_PATH` | `/v1/saml/acs` | Optional | Endpoint path for IdP POST assertions |
| | `SAML_SP_ENTITY_ID_PREFIX` | `https://authn.com/saml/sp/` | Optional | URI namespace prefix for SP Entity IDs |
| **14. Orgs** | `ORG_METADATA_MAX_BYTES` | `10240` (10 KiB) | Optional | Max bytes for organization JSON metadata |
| **14b. Test Ceilings** | `TEST_MAX_USERS` | `500` | Must be positive | Test users one tenant may hold |
| | `TEST_MAX_ORGANIZATIONS` | `25` | Must be positive | Workspaces one tenant may hold in test |
| | `TEST_MAX_API_KEYS` | `20` | Must be positive | Test API keys one tenant may hold |
| | `TEST_ACCESS_TOKEN_TTL` | `15m` | Must be positive, `< TEST_SESSION_TTL` | Ceiling on a test access token's lifetime |
| | `TEST_SESSION_TTL` | `24h` | Must be positive | Ceiling on a test session and its refresh cookie |
| **15. Flags** | `FEATURE_PUSH_2FA_ENABLED` | `true` | Optional | Enables/disables Push 2FA features |
| | `FEATURE_MAGIC_LINK_ENABLED` | `true` | Optional | Enables/disables Passwordless Magic Links |
| | `FEATURE_WEBHOOKS_ENABLED` | `true` | Optional | Enables/disables Webhook Dispatcher |
| | `FEATURE_RBAC_ENABLED` | `true` | Optional | Enables/disables Role-Based Access Control |
| | `FEATURE_IMPERSONATION_ENABLED` | `true` | Optional | Enables/disables Admin User Impersonation |
| **15b. Workers**| `WEBHOOK_WORKER_COUNT` | `5` | Optional | Concurrent webhook dispatch goroutines |
| | `DEGRADED_MODE_CHECK_INTERVAL` | `1s` | Optional | Redis health check probe frequency |
| **16. SDK/Console**| `NEXT_PUBLIC_AUTHN_API_URL` | `http://localhost:8080` | Client build var | **Frontend Only** (Target API URL) |
| | `NEXT_PUBLIC_AUTHN_PUBLISHABLE_KEY` | `pk_test_...` | Client build var | **Frontend Only** (Publishable Key) |

---

## 4. Deep-Dive Section Specifications

### Section 1: Deployment Tier (`APP_ENV`)
- **Go Loader**: [`load.go:L45`](/apps/auth-engine/internal/config/load.go#L45)
- **Validation**: Evaluated via `r.oneOf("APP_ENV", "development", "development", "test", "production")`.
- **Server Impact**: Dictates defaults for auto-migrations, Redis requirement, fail-closed rate limiting, and strict secret presence checks.

### Section 2: Server Binding & Connection Tuning
- **Go Loader**: [`load.go:L50-L57`](/apps/auth-engine/internal/config/load.go#L50-L57)
- **Server Actions**:
  - `HOST` & `PORT`: Passed to `app.Listen(addr)` in [`cmd/server/main.go:L404`](/apps/auth-engine/cmd/server/main.go#L404).
  - `SERVER_READ_TIMEOUT`, `SERVER_WRITE_TIMEOUT`, `SERVER_IDLE_TIMEOUT`, `SERVER_BODY_LIMIT_BYTES`: Passed directly into `fiber.Config` in [`cmd/server/main.go:L208-L222`](/apps/auth-engine/cmd/server/main.go#L208-L222).
  - `SERVER_SHUTDOWN_TIMEOUT`: Governs the maximum drain window when receiving `SIGINT`/`SIGTERM` in [`cmd/server/main.go:L411`](/apps/auth-engine/cmd/server/main.go#L411).
  - `SERVER_TRUST_PROXY_HEADERS`: Sets `fiber.Config.ProxyHeader = "X-Forwarded-For"`. When enabled, Fiber's `c.IP()` reads client IP from proxy headers. Affects rate limiting ([`ratelimit/limiter.go:L391`](/apps/auth-engine/internal/ratelimit/limiter.go#L391)) and audit logs.

### Section 3: Public Identity
- **Go Loader**: [`load.go:L59-L63`](/apps/auth-engine/internal/config/load.go#L59-L63)
- **Server Actions**:
  - `AUTHN_APP_NAME`: Displays in Fiber startup banner, TOTP authenticator URI issuer parameter, and email templates (`{{.AppName}}`).
  - `AUTHN_APP_VERSION`: Returned in JSON response on `/v1/health` and `/healthz`.
  - `APP_BASE_URL`: Must use `https://` in production ([`validate.go:L173`](/apps/auth-engine/internal/config/validate.go#L173)). Controls `CookieSecure()` attribute on session cookies ([`config.go:L354`](/apps/auth-engine/internal/config/config.go#L354)) and builds outbound email verification, magic link, and social OAuth callback URIs.
  - `ISSUER_URL`: Must use `https://` in production ([`validate.go:L177`](/apps/auth-engine/internal/config/validate.go#L177)). Published in OIDC discovery document (`.well-known/openid-configuration`) and embedded as `iss` claim in access JWTs.

### Section 4: Cross-Origin Requests (CORS)
- **Go Loader**: [`load.go:L65-L69`](/apps/auth-engine/internal/config/load.go#L65-L69)
- **Middleware**: Mounted globally via `app.Use(middleware.CORS(cfg))` in [`cmd/server/main.go:L279`](/apps/auth-engine/cmd/server/main.go#L279).
- **Validation**: Wildcard (`*`) is **strictly forbidden** if `CORS_ALLOW_CREDENTIALS=true` or if `APP_ENV=production` ([`validate.go:L80`](/apps/auth-engine/internal/config/validate.go#L80)).

### Section 5: Database Connection & Pool
- **Go Loader**: [`load.go:L71-L74, L152, L157`](/apps/auth-engine/internal/config/load.go#L71-L74)
- **Server Actions**:
  - `DATABASE_URL`: In production, mandatory. Scheme selects driver (PostgreSQL, MySQL, SQLite) in [`clientfactory/factory.go`](/apps/auth-engine/internal/database/clientfactory/factory.go).
  - Pool limits (`DATABASE_MAX_OPEN_CONNS`, `DATABASE_MAX_IDLE_CONNS`, `DATABASE_CONN_MAX_LIFETIME`): Configures SQL connection pool.
  - `DATABASE_AUTO_MIGRATE`: Defaults to `true` in development, `false` in production. **Must be `false` in production**, or process halts ([`validate.go:L186`](/apps/auth-engine/internal/config/validate.go#L186)).

### Section 6: Redis Cache & Shared State
- **Go Loader**: [`load.go:L76, L153, L158`](/apps/auth-engine/internal/config/load.go#L76)
- **Server Actions**:
  - `REDIS_URL`: Mandatory in production. Connects Redis client for rate limiting and degraded mode detection.
  - `REDIS_REQUIRED`: Defaults to `true` in production. If `true` and Redis is unreachable, engine halts at boot ([`cmd/server/main.go:L204`](/apps/auth-engine/cmd/server/main.go#L204)).

### Section 7: Cryptographic Secrets & JWT Keys
- **Go Loader**: [`load.go:L78-L79, L154-L155, L159-L160`](/apps/auth-engine/internal/config/load.go#L78-L79)
- **Server Actions**:
  - `AUTHN_ENCRYPTION_KEY`: AES-256-GCM master key for encrypting secrets (TOTP seeds, webhook secrets, SAML private keys) at rest. Mandatory in production, minimum 32 characters ([`validate.go:L162`](/apps/auth-engine/internal/config/validate.go#L162)).
  - `AUTHN_API_KEY_PEPPER`: HMAC pepper for API keys. Mandatory in production, minimum 32 characters. **Must be different from `AUTHN_ENCRYPTION_KEY`** ([`validate.go:L183`](/apps/auth-engine/internal/config/validate.go#L183)).
  - `JWT_KEY_ID`: Value for `kid` header in JWT tokens and JWKS endpoint.
  - `JWT_SIGNING_KEY_PATH`: File path to RSA private key (`.pem`) used to sign access and ID tokens.

### Section 8: Token & Session Lifetimes
- **Go Loader**: [`load.go:L81-L91`](/apps/auth-engine/internal/config/load.go#L81-L91)
- **Validation Rules ([`validate.go:L193-L211`](/apps/auth-engine/internal/config/validate.go#L193-L211))**:
  - `ACCESS_TOKEN_TTL` must be strictly less than `REFRESH_TOKEN_TTL`.
  - `SESSION_GRACE_PERIOD` must be strictly less than `ACCESS_TOKEN_TTL`.
  - `OAUTH_CODE_TTL` must not exceed `10m` (RFC 6749 section 4.1.2 compliance).

### Section 8b: Data Retention Sweeps
- **Go Loader**: [`load.go:L93-L97`](/apps/auth-engine/internal/config/load.go#L93-L97)
- **Validation**: Every duration here is read with `r.duration`, which rejects a zero or negative value at boot. A retention window cannot be set to `0` to disable a sweep.
- **Server Actions**: Registered as sweeper tasks in [`cmd/server/wiring.go`](/apps/auth-engine/cmd/server/wiring.go).
  - `RETENTION_SWEEP_INTERVAL`: How often the sweeper runs, and the ceiling on how long one pass may take, so a large backlog is cleared over several passes rather than one long transaction.
  - `SUPERSEDED_SESSION_RETENTION`: How long a session row replaced by a refresh is kept. Until it is deleted a replay of the old refresh token is recognised as token theft, so this is the width of the theft-detection window.
  - `TERMINAL_SESSION_RETENTION`: How long expired and revoked session rows stay readable as the user's sign-in history. Set it at or above `REFRESH_TOKEN_TTL`, or sessions that could still have been refreshed are deleted.
  - `SANDBOX_MESSAGE_RETENTION`: How long a message captured by the test-environment sandbox is kept ([`docs/features/18-sandbox-message-inbox.md`](/docs/features/18-sandbox-message-inbox.md)). Captured bodies hold verification links and one-time codes in plain text, so a long window is an accumulating store of working credentials.
  - `TEST_USER_RETENTION`: How long a test-environment account is kept past its last sign-in — or past registration, when it never signed in — before `auth.Repository.PurgeIdleTestUsers` deletes it and its eleven dependent tables. This is what keeps `TEST_MAX_USERS` from becoming a wall: suites create accounts by the thousand and abandon them. Live accounts are never swept at any setting, by predicate rather than by the cutoff, so a misconfigured window cannot reach a customer's account.
  - `RETENTION_BATCH_SIZE`: Rows deleted per statement, shared by every sweep. Larger clears a backlog in fewer passes; smaller holds locks for less time on each one.

### Section 9: Rate Limiting & Escalating Lockout
- **Go Loader**: [`load.go:L103-L113`](/apps/auth-engine/internal/config/load.go#L103-L113)
- **Server Actions**: Configures [`internal/ratelimit/limiter.go`](/apps/auth-engine/internal/ratelimit/limiter.go).
  - `RATELIMIT_IP_BUDGET_MULTIPLIER`: Multiplies per-account budget for IP budget (e.g. $5 \times 10 = 50$ attempts/window per IP).
  - `RATELIMIT_BACKOFF_SCHEDULE`: Escalating lockouts on repeat offences (`15m,1h,6h,24h`).
  - `RATELIMIT_FAIL_CLOSED`: If `true`, rejects requests when Redis is offline instead of failing open. Defaults to `true` in production.

### Section 10: Email Delivery Drivers
- **Go Loader**: [`load.go:L115-L130`](/apps/auth-engine/internal/config/load.go#L115-L130)
- **Validation ([`validate.go:L119-L141`](/apps/auth-engine/internal/config/validate.go#L119-L141))**:
  - Supported drivers: `noop`, `smtp`, `resend`, `sendgrid`, `postmark`, `aws_ses`.
  - Selected driver credentials are **checked at startup**. If `EMAIL_DRIVER=resend` and `RESEND_API_KEY` is missing, the engine refuses to start.

### Section 11: SMS Delivery Drivers
- **Go Loader**: [`load.go:L132-L138`](/apps/auth-engine/internal/config/load.go#L132-L138)
- **Validation ([`validate.go:L143-L153`](/apps/auth-engine/internal/config/validate.go#L143-L153))**:
  - Supported drivers: `noop`, `twilio`, `messagebird`, `aws_sns`.
  - Required credentials (e.g. `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER`) are validated at startup.

### Section 12: WebAuthn & Passkey Ceremonies
- **Go Loader**: [`load.go:L140-L142`](/apps/auth-engine/internal/config/load.go#L140-L142)
- **Validation ([`validate.go:L92-L114`](/apps/auth-engine/internal/config/validate.go#L92-L114))**:
  - `WEBAUTHN_RP_ID` must be a bare hostname without scheme or port. Cannot be `"localhost"` in production.
  - Every entry in `WEBAUTHN_RP_ORIGINS` **must belong to `WEBAUTHN_RP_ID`** or a subdomain of it. Misconfiguration halts startup.

### Section 13: SAML Integration
- **Go Loader**: [`load.go:L144-L145`](/apps/auth-engine/internal/config/load.go#L144-L145)
- **Server Actions**:
  - `SAML_ACS_PATH` (Default: `/v1/saml/acs`): Combined with `APP_BASE_URL` in `cfg.SAMLAssertionConsumerURL()` ([`config.go:L463`](/apps/auth-engine/internal/config/config.go#L463)) to publish Service Provider ACS metadata.
  - `SAML_SP_ENTITY_ID_PREFIX` (Default: `https://authn.com/saml/sp/`): URI prefix used to generate unique SAML Service Provider Entity IDs per tenant organization (`cfg.SAMLSPEntityID(orgID)` $\rightarrow$ `https://authn.com/saml/sp/org_12345`). Published in SP Metadata XML and checked against an incoming assertion's `AudienceRestriction` tags during SAML Enterprise SSO.

### Section 14: B2B Organizations
- **Go Loader**: [`load.go:L150`](/apps/auth-engine/internal/config/load.go#L150) (Default: `10240` bytes / 10 KiB).
- **Server Action**: Limits max body payload size for organization custom JSON metadata blobs during create/update operations in [`internal/org/service.go`](/apps/auth-engine/internal/org/service.go).

### Section 14b: Test-Environment Ceilings
- **Go Loader**: [`load.go:L99-L101`](/apps/auth-engine/internal/config/load.go#L99-L101)
- **Validation**: The three counts are read with `r.positive` and the two durations with `r.duration`, both of which reject zero and negative values at boot. A ceiling cannot be set to `0` to lift it — a deployment that means to be unbounded is one that never sets these at all, and the loader's defaults are what a configured deployment gets. `TEST_ACCESS_TOKEN_TTL` must additionally be shorter than `TEST_SESSION_TTL`, and longer than `SESSION_GRACE_PERIOD`, for the same reasons `ACCESS_TOKEN_TTL` must be.
- **Enforcement**: An Ent mutation hook, [`internal/quota/quota.go`](/apps/auth-engine/internal/quota/quota.go), installed by [`pkg/clientfactory/client_factory.go`](/apps/auth-engine/pkg/clientfactory/client_factory.go) immediately after the privacy interceptors. The hook counts through the client it was handed, so the count is narrowed to the caller's tenant and environment by the same rules every other read is subject to — there is no tenant predicate written in the quota package at all.
  - The check sits at the ORM rather than in the services because five paths create a user (sign-up, magic-link auto-provisioning, social sign-in, SAML provisioning and invitation acceptance), and a ceiling enforced by convention holds only until the sixth is written.
  - It runs on creates only. A tenant sitting at its ceiling still verifies an email, bans an account and rotates a secret.
  - Bypass contexts — migration, seeding, the retention sweeps — are exempt. None of them is a tenant spending an allowance.
- **Server Actions**:
  - `TEST_MAX_USERS` (Default: `500`): Test users one tenant may hold. Counted per tenant and per environment.
  - `TEST_MAX_ORGANIZATIONS` (Default: `25`): Workspaces one tenant may hold in test. `organization` carries an `environment` column of its own, so the count is per environment and a tenant's live workspaces do not consume the room its test ones have — a customer running a full production estate can still rehearse.
  - `TEST_MAX_API_KEYS` (Default: `20`): Test API keys one tenant may hold, counting the publishable/secret pair provisioning installs with each application.
  - `TEST_ACCESS_TOKEN_TTL` (Default: `15m`): Ceiling on a test access token's lifetime, replacing `ACCESS_TOKEN_TTL` and any longer `access_token_ttl_minutes` a tenant stored. Resolved through `cfg.AccessTokenTTLFor(environment)` at every issuance site, and reported by the matching `expires_in` so the advertised lifetime and the signed `exp` cannot disagree.
  - `TEST_SESSION_TTL` (Default: `24h`): Ceiling on a test session row's `expires_at`, its refresh cookie's `Expires`, and so on how long its refresh token keeps minting. Applied at each sign-in path through `cfg.RefreshTokenTTLFor(environment)`, and again in the quota hook as `Limits.SessionTTL` — the session row is the one artifact with no single choke point, two repositories creating it on different signatures.
- **Direction of the lifetime clamp**: it lowers and never raises. A deployment or tenant that asked for something shorter than the ceiling keeps it, and a live credential is returned untouched. A non-positive ceiling bounds nothing, so a zero-valued `Config` — one nobody loaded — leaves lifetimes alone rather than reading zero as "expire immediately".
- **Client Contract**: A refused create answers **403** with code `test_quota_exceeded` ([`internal/httperr/httperr.go`](/apps/auth-engine/internal/httperr/httperr.go)), and the message names what ran out and at what ceiling. It is deliberately not `429`: the ceiling is on stored rows, so waiting does not help and there is no `Retry-After` to give. Room is made by deleting rows, by waiting out `TEST_USER_RETENTION`, or by moving to a live key. The lifetime ceilings refuse nothing — a caller receives a working credential that simply expires sooner, with no field reporting the clamp.
- **Accepted Race**: The count is read immediately before the insert and outside any lock, so two creates arriving together can both find room and leave the tenant one row over its ceiling. This is a spend control, not a security boundary; enforcing it to the exact row would cost a serialized count on every test-environment sign-up.

### Section 15: Dynamic Feature Flags
- **Go Loader**: [`load.go:L152-L156`](/apps/auth-engine/internal/config/load.go#L152-L156) (Defaults: `true`).
- **Server Actions**:
  - `FEATURE_PUSH_2FA_ENABLED`: Toggles Push 2FA challenge endpoints.
  - `FEATURE_MAGIC_LINK_ENABLED`: Toggles passwordless magic link generation.
  - `FEATURE_WEBHOOKS_ENABLED`: Controls background webhook event dispatcher.
  - `FEATURE_RBAC_ENABLED`: Toggles custom role and permission enforcement.
  - `FEATURE_IMPERSONATION_ENABLED`: Toggles admin user impersonation sessions.

### Section 15b: Background Workers & Health Probes
- **Go Loader**: [`load.go:L147-L148`](/apps/auth-engine/internal/config/load.go#L147-L148)
- **Server Actions**:
  - `WEBHOOK_WORKER_COUNT` (Default: `5`): Sets worker pool size for concurrent outbound webhook deliveries ([`internal/webhook/dispatcher.go`](/apps/auth-engine/internal/webhook/dispatcher.go)).
  - `DEGRADED_MODE_CHECK_INTERVAL` (Default: `1s`): Sets polling interval for Redis health probes to update system degraded mode state ([`docs/ARCHITECTURE-DEGRADED-MODE.md`](/docs/ARCHITECTURE-DEGRADED-MODE.md)).

### Section 16: Web Console & SDK Client Variables
- **Definition**: `NEXT_PUBLIC_AUTHN_API_URL` and `NEXT_PUBLIC_AUTHN_PUBLISHABLE_KEY`.
- **Target**: Consumed by Next.js web application (`apps/console`) and `@authn/js` browser package.
- **Server Impact**: **NONE**. The Go backend engine completely ignores these variables.

---

## 5. Verification & Compliance Standard

Every variable documented above has been verified against the Go source code in `apps/auth-engine/internal/config/`. Adding or modifying environment variables in the codebase requires updating:
1. `apps/auth-engine/internal/config/config.go` (Struct definition & comments)
2. `apps/auth-engine/internal/config/load.go` (Default value & type parser)
3. `apps/auth-engine/internal/config/validate.go` (Cross-field validation rules)
4. `.env.example` (Reference configuration template)
5. This specification (`docs/15-ENVIRONMENT-CONFIGURATION.md`)
