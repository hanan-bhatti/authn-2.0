# Authn Platform — Product Requirements Document (PRD)

**Document Version**: 2.0.0  
**Date**: 2026-08-04  
**Status**: Approved Specification (Production Implementation)  
**Author**: Authn Core Team  

---

## 1. Vision Statement & Product Goals

**Authn** is an enterprise-grade, open-source authentication and identity management platform designed to be the world's most versatile, high-performance alternative to Auth0, Firebase Auth, and Keycloak.

### Key Objectives
* **Developer Accessibility**: Provide a Firebase/Supabase-like developer experience where frontend and mobile apps interact directly with the backend using Publishable API Keys (`pk_test_...` for development and `pk_live_...` for production).
* **Peak Performance**: Powered by a Go 1.22+ backend engine with Ent ORM supporting multi-database flexibility (PostgreSQL, MySQL, SQLite) and Redis/Dragonfly in-memory caching.
* **Deep Mobile & Multi-Factor Security**: Provide native Android (Kotlin) and iOS (Swift) clients that support system-level account management, single sign-on (SSO) across apps on the same device, and real-time push 2FA prompts ("Do you trust this login?") with push-fatigue number matching defenses. Native TOTP, SMS OTP, Backup Recovery Codes, FIDO2/WebAuthn Passkeys, and push notification 2FA with push-fatigue defenses.
* **Smart Account Recovery & Fraud Prevention**: Google-level intelligent account recovery using trusted device tokens, IP subnet history, Shamir's Secret Sharing ($GF(2^8)$ 1-to-5 majority threshold) guardian recovery, per-tenant admin `RecoveryPolicy`, mandatory 48-hour freeze window, and 7-day multi-dimensional security cancellation blacklisting.
* **Complete Monorepo Ecosystem**: Housing the backend engine, developer web console, marketing landing page, documentation hub, interactive demo playground, mobile apps, and shared UI/SDK packages in a single Turborepo repository.

---

## 2. Target User Personas

| Persona | Role | Key Pain Points & Needs |
| :--- | :--- | :--- |
| **Web Developer** | Full-Stack / Frontend Eng | Wants simple SDK (`@authn/js`, `@authn/react`), quick drop-in `<SignInButton />`, pre-built login UI, test/prod environment modes, social auth, and magic links. |
| **Mobile Developer** | Android & iOS Eng | Needs seamless native auth, zero-friction on-device SSO between companion apps, and biometric/push 2FA. |
| **DevOps / Self-Hoster** | Infrastructure Eng | Wants single-binary or Docker Compose self-hosting, multi-DB support (Postgres/SQLite), low RAM usage, and zero cloud vendor lock-in. |
| **Security Officer** | DevSecOps / Admin | Requires strict OIDC compliance, Argon2id hashing, JWKS key rotation, audit logging, multi-layered rate limiting, webhooks, per-tenant policies, and tenant boundary isolation. |

---

## 3. Core Functional Requirements (FR)

### FR-1: Environment Modes & Isolation Architecture
- **Environment Modes**: Applications support isolated **Test / Development** (`environment = test`) and **Production** (`environment = live`) modes.
- **Logical Isolation (Default)**: Ent privacy hooks enforce logical environment boundary scoping on `(tenant_id, application_id, environment)` automatically.
- **Physical Isolation (Enterprise Option)**: Ent client initialization uses a `ClientFactory` abstraction, allowing Enterprise self-hosters to route environments to distinct DB connection pools without schema modifications.
- **Publishable Client Keys**:
  - `pk_test_...` (Test/Development mode): Safe for local dev, sandbox testing without sending real emails/SMS.
  - `pk_live_...` (Production mode): Used in live production apps.
- **Secret Admin Keys**:
  - `sk_test_...` (Test Admin Key)
  - `sk_live_...` (Production Admin Key): Used strictly on backend servers for administrative actions (custom claims, user bans, token verification, policy management).

### FR-2: Multi-Layered Rate Limiting Shield & Outage Policy
- Multi-dimensional sliding-window rate limiting executed via a **single Redis Lua script** (1 network hop) to maintain sub-10ms P95 latency.
- **Device Fingerprint Digest**: Client device tokens are hashed into a deterministic HMAC-SHA256 digest in Go prior to passing into the Redis Lua script for opaque string matching.
- **Redis Outage Failure Mode Policy**:
  - **Sensitive Auth Mutations & Token Issuance (`/login`, `/signup`, `/oauth/token`, `/2fa/verify`, `/recovery/initiate`)**: **Fail-Closed** (blocks requests to prevent brute-force attacks during cache outages).
  - **Stateless Read Verification (`/v1/client/user/me`, `/oauth/userinfo` with valid unexpired JWT)**: **Fail-Open** with local Go in-memory JWKS public key validation fallback.

### FR-3: Email & Communication Provider Drivers
- **Email Service Providers**: Pluggable `EmailProvider` Go drivers for SMTP (implemented & verified with Mailpit), Resend, SendGrid, Postmark, AWS SES.
- **SMS / WhatsApp Providers**: Pluggable `SMSProvider` Go drivers for Twilio, MessageBird, AWS SNS.
- **Customizable Templates**: HTML/Text email template rendering system for Email Verification, Password Reset, Magic Links, Security Alerts, and Account Recovery notifications.
- **Tenant Security Policy Enforcement**: Configurable per-tenant verification enforcement (`require_email_verification`) supporting **Disabled**, **Soft Gate** (200 OK + policy notice), and **Hard Block** (`403 Forbidden` with `email_verification_required`).

### FR-4: Comprehensive 2FA Methods & Passkey Support
- Supported 2FA Authentication Methods:
  1. **TOTP Authenticator**: RFC 6238 authenticator app support (Google Authenticator, 1Password, Authy).
  2. **Backup Recovery Codes**: 8-16 single-use cryptographically generated recovery codes. Individual code invalidated upon use.
  3. **WebAuthn / Passkeys**: FIDO2 biometric authentication (FaceID, TouchID, Windows Hello, YubiKeys).
  4. **SMS / WhatsApp OTP**: One-time passcode sent via SMS or WhatsApp with 3 requests / 10 min rate limiting and email fallback.
  5. **Push Notification 2FA**: Real-time FCM (Android) & APNs (iOS) push prompts with **Number Matching Verification** (login screen displays a 2-digit number like `47` that user selects on mobile) + rate limit of 3 push prompts per 5 minutes per device.

### FR-5: Smart Account Recovery & Security Freeze Window
- **Dynamic Identity Proof Resolution**: Resolves available identity proof methods per account in strict priority order:
  1. Guardians (if pre-enrolled)
  2. Recovery Phone OTP (if verified)
  3. Recovery Email OTP (if verified)
  4. Old Password (unlocked ONLY when trusted device token + IP subnet match)
  5. Security Questions (fallback when higher-tier methods are empty/exhausted)
- **Shamir's Secret Sharing ($GF(2^8)$)**: Pre-enrolled 1-to-5 guardian recovery with majority threshold $k = \lfloor N/2 \rfloor + 1$. Zero-knowledge share distribution via URL fragment (`#token=...`), DB stores SHA-256 share hashes only.
- **Telemetry Trust Engine**: HMAC-SHA256 device cookies (`authn_td_token`) + `/24` IPv4 / `/48` IPv6 subnet parsing with sliding window expiration and background auto-purge.
- **Mandatory 48-Hour Freeze Window & 15-Minute Claim Token**: State machine: `INITIATED` $\to$ `AWAITING_PROOF` $\to$ `PROOF_VERIFIED` $\to$ `FREEZE_ACTIVE` (48h) $\to$ `READY_FOR_CLAIM` (15m single-use token) $\to$ `COMPLETED`.
- **Per-Tenant Admin `RecoveryPolicy`**: Configurable per tenant via `GET/PUT /v1/tenant/recovery-policy` with 9 strict validation bounds.
- **Multi-Channel Security Cancellation & 7-Day Blacklisting**:
  - Authenticated session cancellation (`POST /v1/client/auth/recovery/cancel`).
  - Public signed link cancellation (`POST /v1/client/auth/recovery/cancel/token`).
  - On cancellation: Request set to `CANCELLED`, 7-day multi-dimensional blacklist created (`ip_address`, `subnet`, `fingerprint_hash`), active user sessions revoked, and account flagged for mandatory security review (`security_review_required = true`).

### FR-6: OAuth 2.0 & OpenID Connect (OIDC) Authorization Server
- Full PKCE (Proof Key for Code Exchange) authorization code grant flow for web and mobile.
- Public JWKS endpoint (`/v1/oauth/jwks` & `/.well-known/openid-configuration`) with RS256 signed ID tokens.
- Strict exact-string matching for `redirect_uri` parameters (no wildcards) per OAuth 2.0 BCP.

### FR-7: Pluggable Social Identity Drivers [Completed & Verified]
- Pluggable Go `IdentityProvider` driver interface allowing admins to enable social login providers by entering client keys in the console:
  - Google, Apple, X (Twitter), Facebook, GitHub, Microsoft, Discord, LinkedIn, and generic OIDC providers.

### FR-8: Session Management & SHA-256 Refresh Token Hashing [Completed & Verified]
- 64-byte high-entropy opaque refresh tokens stored strictly as SHA-256 hashes in the database.
- Refresh token rotation on every exchange with a 10-second grace window to allow concurrent network requests.
- Active session listing by device, browser, IP, and location with single-click remote session revocation.

## 4. Execution Roadmap & Feature Order

### Phase 1: Backend Core Engines (Current Target)
- **FR-12: Role-Based Access Control (RBAC) & Fine-Grained Permissions [Completed & Verified]**
  - Roles (`tenant_admin`, `org_admin`, `editor`, `viewer`) & granular permissions (`users:read`, `orgs:write`).
  - Permission evaluation middleware & role/permission claims in JWT tokens.
- **FR-13: Outgoing Real-Time Event Webhooks**
  - Event triggers (`user.signup`, `user.login`, `session.revoked`, `2fa.enabled`, `password.changed`).
  - Worker pool with exponential backoff retries and HMAC-SHA256 signature (`X-Authn-Signature`).
- **FR-14: Admin User Impersonation ("Log in as User") [Completed & Verified]**
  - Endpoint `POST /v1/admin/users/:userId/impersonate` generating short-lived (1-60 min) impersonation JWT with `impersonator_id` & `is_impersonated: true` claims.
  - Mandatory admin step-up authentication (Passkey, 2FA, or Password), email transparency notifications, real-time webhooks (`user.impersonated`), and read-only mutation guard (`PreventImpersonatedMutations`).
- **FR-15: B2B Organizations & Team Member Invitations [Completed & Verified]**
  - Multi-tenant Organization hierarchy (`tnt_...` $\to$ `org_...`), member invites with 7-day cryptographically signed tokens, org-scoped roles, audit logs, real-time webhooks, and live test proof (`org-proof.html`).
- **FR-16: Enterprise SAML 2.0 & Native SSO [Completed & Verified]**
  - Native SAML 2.0 Identity Provider (IdP) & Service Provider (SP) integration for Okta, Azure AD / Entra ID, Ping, JIT user provisioning, domain SSO enforcement, XML ACS assertion processing, audit logs, and real-time webhooks.

### Phase 2: Client SDKs
- **JS SDK (`packages/js`)**: Core JavaScript/TypeScript client library.
- **React SDK (`packages/react`)**: React hooks & context providers (`AuthProvider`, `useAuth`, `useUser`, `useSession`).

### Phase 3: Developer Console & Operations
- **FR-10: Developer Console (`apps/web-console`)**: Web admin panel for tenant settings, API keys, provider credentials, sessions, and audit logs.

### Phase 4: Public Docs & Interactive Demo
- **FR-11: Public Documentation & Interactive Demo (`apps/web-docs` & `apps/web-demo`)**: Interactive docs hub and live playground.

### Phase 5: Native Mobile Integrations
- **FR-9: Native Android & iOS Account Manager (Device-Level SSO)**: Android `AccountManager` & iOS Shared Keychain Secure Enclave SSO.

---

## 5. Non-Functional Requirements (NFR)

- **Latency**: Sub-10ms P95 latency for token validation and session checks (including Redis Lua-scripted rate limits).
- **Security**: RFC 9106 Argon2id password hashing ($t=3, m=64\text{MB}, p=4$), automated 30-day JWKS key rotation with 7-day grace window, zero-knowledge secret handling, 7-day security cancellation blacklisting.
- **Multi-Tenancy**: Ent privacy hooks enforcing tenant and environment boundary isolation automatically on every query (Logical default with Enterprise physical DB pool routing option via `ClientFactory`).
- **Portability**: Single-binary compilation mode for lightweight SQLite self-hosting and containerized deployment.
