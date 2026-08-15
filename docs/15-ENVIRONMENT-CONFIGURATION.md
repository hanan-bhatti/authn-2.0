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

### Section 9: Rate Limiting & Escalating Lockout
- **Go Loader**: [`load.go:L93-L103`](/apps/auth-engine/internal/config/load.go#L93-L103)
- **Server Actions**: Configures [`internal/ratelimit/limiter.go`](/apps/auth-engine/internal/ratelimit/limiter.go).
  - `RATELIMIT_IP_BUDGET_MULTIPLIER`: Multiplies per-account budget for IP budget (e.g. $5 \times 10 = 50$ attempts/window per IP).
  - `RATELIMIT_BACKOFF_SCHEDULE`: Escalating lockouts on repeat offences (`15m,1h,6h,24h`).
  - `RATELIMIT_FAIL_CLOSED`: If `true`, rejects requests when Redis is offline instead of failing open. Defaults to `true` in production.

### Section 10: Email Delivery Drivers
- **Go Loader**: [`load.go:L105-L120`](/apps/auth-engine/internal/config/load.go#L105-L120)
- **Validation ([`validate.go:L119-L141`](/apps/auth-engine/internal/config/validate.go#L119-L141))**:
  - Supported drivers: `noop`, `smtp`, `resend`, `sendgrid`, `postmark`, `aws_ses`.
  - Selected driver credentials are **checked at startup**. If `EMAIL_DRIVER=resend` and `RESEND_API_KEY` is missing, the engine refuses to start.

### Section 11: SMS Delivery Drivers
- **Go Loader**: [`load.go:L122-L128`](/apps/auth-engine/internal/config/load.go#L122-L128)
- **Validation ([`validate.go:L143-L153`](/apps/auth-engine/internal/config/validate.go#L143-L153))**:
  - Supported drivers: `noop`, `twilio`, `messagebird`, `aws_sns`.
  - Required credentials (e.g. `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER`) are validated at startup.

### Section 12: WebAuthn & Passkey Ceremonies
- **Go Loader**: [`load.go:L130-L132`](/apps/auth-engine/internal/config/load.go#L130-L132)
- **Validation ([`validate.go:L92-L114`](/apps/auth-engine/internal/config/validate.go#L92-L114))**:
  - `WEBAUTHN_RP_ID` must be a bare hostname without scheme or port. Cannot be `"localhost"` in production.
  - Every entry in `WEBAUTHN_RP_ORIGINS` **must belong to `WEBAUTHN_RP_ID`** or a subdomain of it. Misconfiguration halts startup.

### Section 13: SAML Integration
- **Go Loader**: [`load.go:L134-L135`](/apps/auth-engine/internal/config/load.go#L134-L135)
- **Server Actions**:
  - `SAML_ACS_PATH` (Default: `/v1/saml/acs`): Combined with `APP_BASE_URL` in `cfg.SAMLAssertionConsumerURL()` ([`config.go:L369`](/apps/auth-engine/internal/config/config.go#L369)) to publish Service Provider ACS metadata.
  - `SAML_SP_ENTITY_ID_PREFIX` (Default: `https://authn.com/saml/sp/`): URI prefix used to generate unique SAML Service Provider Entity IDs per tenant organization (`cfg.SAMLSPEntityID(orgID)` $\rightarrow$ `https://authn.com/saml/sp/org_12345`). Published in SP Metadata XML and checked against an incoming assertion's `AudienceRestriction` tags during SAML Enterprise SSO.

### Section 14: B2B Organizations
- **Go Loader**: [`load.go:L139`](/apps/auth-engine/internal/config/load.go#L139) (Default: `10240` bytes / 10 KiB).
- **Server Action**: Limits max body payload size for organization custom JSON metadata blobs during create/update operations in [`internal/org/service.go`](/apps/auth-engine/internal/org/service.go).

### Section 15: Dynamic Feature Flags
- **Go Loader**: [`load.go:L141-L145`](/apps/auth-engine/internal/config/load.go#L141-L145) (Defaults: `true`).
- **Server Actions**:
  - `FEATURE_PUSH_2FA_ENABLED`: Toggles Push 2FA challenge endpoints.
  - `FEATURE_MAGIC_LINK_ENABLED`: Toggles passwordless magic link generation.
  - `FEATURE_WEBHOOKS_ENABLED`: Controls background webhook event dispatcher.
  - `FEATURE_RBAC_ENABLED`: Toggles custom role and permission enforcement.
  - `FEATURE_IMPERSONATION_ENABLED`: Toggles admin user impersonation sessions.

### Section 15b: Background Workers & Health Probes
- **Go Loader**: [`load.go:L136-L137`](/apps/auth-engine/internal/config/load.go#L136-L137)
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
