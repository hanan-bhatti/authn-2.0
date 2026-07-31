# Authn Platform — Product Requirements Document (PRD)

**Document Version**: 1.0.0  
**Date**: 2026-08-01  
**Status**: Approved Specification (Execution Ready)  
**Author**: Authn Core Team  

---

## 1. Vision Statement & Product Goals

**Authn** is an enterprise-grade, open-source authentication and identity management platform designed to be the world's most versatile, high-performance alternative to Auth0, Firebase Auth, and Keycloak.

### Key Objectives
* **Developer Accessibility**: Provide a Firebase/Supabase-like developer experience where frontend and mobile apps interact directly with the backend using Publishable API Keys (`pk_test_...` for development and `pk_live_...` for production).
* **Peak Performance**: Powered by a Go 1.22+ backend engine with Ent ORM supporting multi-database flexibility (PostgreSQL, MySQL, SQLite) and Redis/Dragonfly in-memory caching.
* **Deep Mobile Integration**: Provide native Android (Kotlin) and iOS (Swift) clients that support system-level account management, single sign-on (SSO) across apps on the same device, and real-time push 2FA prompts ("Do you trust this login?") with push-fatigue number matching defenses.
* **Smart Account Recovery & Fraud Prevention**: Google-level intelligent account recovery using trusted device tokens, IP subnet history, Shamir's Secret Sharing guardian recovery, and multi-layered rate limiting.
* **Complete Monorepo Ecosystem**: Housing the backend engine, developer web console, marketing landing page, documentation hub, interactive demo playground, mobile apps, and shared UI/SDK packages in a single Turborepo repository.

---

## 2. Target User Personas

| Persona | Role | Key Pain Points & Needs |
| :--- | :--- | :--- |
| **Web Developer** | Full-Stack / Frontend Eng | Wants simple SDK (`@authn/js`, `@authn/react`), quick drop-in `<SignInButton />`, pre-built login UI, test/prod environment modes, social auth, and magic links. |
| **Mobile Developer** | Android & iOS Eng | Needs seamless native auth, zero-friction on-device SSO between companion apps, and biometric/push 2FA. |
| **DevOps / Self-Hoster** | Infrastructure Eng | Wants single-binary or Docker Compose self-hosting, multi-DB support (Postgres/SQLite), low RAM usage, and zero cloud vendor lock-in. |
| **Security Officer** | DevSecOps / Admin | Requires strict OIDC compliance, Argon2id hashing, JWKS key rotation, audit logging, multi-layered rate limiting, webhooks, and tenant boundary isolation. |

---

## 3. Core Functional Requirements (FR)

### FR-1: Environment Modes & Isolation Architecture
- **Environment Modes**: Applications support isolated **Test / Development** (`environment = test`) and **Production** (`environment = live`) modes.
- **Logical Isolation (Default)**: Ent privacy hooks enforce logical environment boundary scoping on `(tenant_id, application_id, environment)` automatically.
- **Physical Isolation (Enterprise Option)**: Ent client initialization uses a `ClientFactory` abstraction from Milestone 1.1, allowing Enterprise self-hosters to route environments to distinct DB connection pools without schema modifications.
- **Publishable Client Keys**:
  - `pk_test_...` (Test/Development mode): Safe for local dev, sandbox testing without sending real emails/SMS.
  - `pk_live_...` (Production mode): Used in live production apps.
- **Secret Admin Keys**:
  - `sk_test_...` (Test Admin Key)
  - `sk_live_...` (Production Admin Key): Used strictly on backend servers for administrative actions (custom claims, user bans, token verification).

### FR-2: Multi-Layered Rate Limiting Shield & Outage Policy
- Multi-dimensional sliding-window rate limiting executed via a **single Redis Lua script** (1 network hop) to maintain sub-10ms P95 latency.
- **Device Fingerprint Digest**: Client device tokens are hashed into a deterministic HMAC-SHA256 digest in Go prior to passing into the Redis Lua script for opaque string matching (zero in-Lua decryption overhead).
- **Redis Outage Failure Mode Policy**:
  - **Sensitive Auth Mutations & Token Issuance (`/login`, `/signup`, `/oauth/token`, `/2fa/verify`, `/password-reset`)**: **Fail-Closed** (blocks requests to prevent brute-force attacks during cache outages).
  - **Stateless Read Verification (`/v1/client/user/me`, `/oauth/userinfo` with valid unexpired JWT)**: **Fail-Open** with local Go in-memory JWKS public key validation fallback.

### FR-3: Email & Communication Provider Drivers
- **Email Service Providers**: Pluggable `EmailProvider` Go drivers for SMTP, Resend, SendGrid, Postmark, AWS SES.
- **SMS / WhatsApp Providers**: Pluggable `SMSProvider` Go drivers for Twilio, MessageBird, AWS SNS.
- **Customizable Templates**: Rich HTML/Text email template editor in the console for Email Verification, Password Reset, Magic Links, Security Alerts, and Account Recovery notifications.

### FR-4: Comprehensive 2FA Methods & Push Fatigue Defense
- Supported 2FA Authentication Methods:
  1. **Push Notification 2FA**: Real-time FCM (Android) & APNs (iOS) push prompts with **Number Matching Verification** (login screen displays a 2-digit number like `47` that user selects on mobile) + rate limit of 3 push prompts per 5 minutes per device.
  2. **WebAuthn / Passkeys**: FIDO2 biometric authentication (FaceID, TouchID, Windows Hello, YubiKeys).
  3. **TOTP Authenticator**: RFC 6238 authenticator app support (Google Authenticator, 1Password, Authy).
  4. **SMS / WhatsApp OTP**: One-time passcode sent via SMS or WhatsApp.
  5. **Backup Recovery Codes**: 16 single-use cryptographically generated recovery codes. Individual code invalidated upon use.

### FR-5: Smart Account Recovery & 48-Hour Freeze Window
- **48-Hour Security Delay Freeze Window**: **ALL** non-primary account recovery requests (both Trusted Device Token Recovery and Guardian Recovery) trigger a mandatory 48-hour security hold with push/email alerts sent to all active sessions. No recovery path bypasses this delay.
- **Trusted Device Token & IP Subnet Verification**: Evaluates recovery attempts against cryptographically signed device token cookies and historic IP subnet ranges. IP subnet telemetry and device fingerprint logs are retained for a maximum **90-day sliding window** and purged automatically or upon user deletion request per GDPR Right to be Forgotten.
- **Pre-Enrolled Guardian Recovery (Shamir's Secret Sharing)**: Option for users to pre-enroll and cryptographically verify 2-3 trusted recovery contacts while authenticated. Uses 2-of-3 threshold key splitting out-of-band so no single guardian can compromise an account.

### FR-6: OAuth 2.0 & OpenID Connect (OIDC) Authorization Server
- Full PKCE (Proof Key for Code Exchange) authorization code grant flow for web and mobile.
- Public JWKS endpoint (`/.well-known/jwks.json`) with RS256/ES256 signed ID tokens.
- Strict exact-string matching for `redirect_uri` parameters (no wildcards) per OAuth 2.0 BCP.

### FR-7: Pluggable Social Identity Drivers
- Pluggable Go `IdentityProvider` driver interface allowing admins to enable social login providers by entering client keys in the console:
  - Google, Apple, X (Twitter), Facebook, GitHub, Microsoft, Discord, LinkedIn, and generic OIDC providers.

### FR-8: Session Management & SHA-256 Refresh Token Hashing
- 64-byte high-entropy opaque refresh tokens stored strictly as SHA-256 hashes in the database.
- Refresh token rotation on every exchange with a 10-second grace window to allow concurrent network requests.
- Active session listing by device, browser, IP, and location with single-click remote session revocation.

### FR-9: Native Android & iOS Account Manager (Device-Level SSO)
- **Android (`AccountManager`)**: Registers Authn as an Android System Account Type for silent cross-app token exchange.
- **iOS (`ASWebAuthenticationSession` & Shared Keychain)**: Uses Secure Enclave and Shared Keychain Groups for silent cross-app SSO on iOS devices.

### FR-10: Developer Console & Tenant Management (`console.authn.com`)
- Tenant management, environment toggling (Test vs Prod), API key generation, provider secrets, email/SMS provider settings, rate limit rules, audit logs, and user management.

### FR-11: Public Documentation & Interactive Demo (`docs.authn.com` & `demo.authn.com`)
- Interactive docs hub with SDK quickstarts (`docs.authn.com`) and live playground (`demo.authn.com`).

### FR-12: Role-Based Access Control (RBAC) & Fine-Grained Permissions
- Support for Roles (e.g., `admin`, `editor`, `viewer`) and granular Permissions (`posts:create`, `users:delete`).
- Global tenant roles and per-organization roles included in JWT claims.

### FR-13: Outgoing Real-Time Event Webhooks
- Signed webhook notifications sent to configured developer URLs on key security events (`user.created`, `user.deleted`, `session.revoked`, `2fa.enabled`, `password.changed`).
- HMAC-SHA256 signature header (`X-Authn-Signature`) sent with every payload for developer verification.

### FR-14: Admin User Impersonation ("Log in as User")
- Secure admin API endpoint (`POST /v1/admin/users/:userId/impersonate`) allowing admins to issue a short-lived impersonation session for customer support and troubleshooting.
- All impersonation sessions carry an explicit `impersonator_id` claim in JWT and generate security audit logs.

### FR-15: Passwordless Magic Links & Email/SMS OTP
- Passwordless authentication flow: `POST /v1/client/auth/magic-link` sends a single-use 15-minute signed magic login URL to the user's email.

### FR-16: B2B Organizations & Team Member Invitations
- Support for Organizations within tenants.
- Team member invitations with cryptographically signed 7-day expiration tokens (`invitationToken`) and per-org role assignment.

---

## 4. Non-Functional Requirements (NFR)

- **Latency**: Sub-10ms P95 latency for token validation and session checks (including Redis Lua-scripted pipelined rate limits).
- **Security**: Argon2id password hashing, automated 30-day JWKS key rotation with 7-day grace window, multi-layered rate limiting (IP + User-Agent + HMAC Device Token + API Key).
- **Multi-Tenancy**: Ent privacy hooks enforcing tenant and environment boundary isolation automatically on every query (Logical default with Enterprise physical DB pool routing option via `ClientFactory`).
- **Portability**: Single-binary compilation mode for lightweight SQLite self-hosting.

---

## 5. Milestone & Release Roadmap

- **Phase 1 MVP**:
  - **Milestone 1.1**: Monorepo setup, Go Auth Engine, Ent schemas with RBAC & Webhook entities, Test/Prod environment keys, Refresh Token SHA-256 rotation.
  - **Milestone 1.2**: OIDC PKCE server, Dual API Key system, `EmailProvider` & `SMSProvider` drivers, Passwordless Magic Links, Redis Lua rate-limiting.
  - **Milestone 1.3**: SDKs (`@authn/js`, `@authn/react`), Next.js Web Console (RBAC, Webhooks, Impersonation, Org Invites), Landing, Docs, and Demo apps.
- **Phase 2 Mobile & Trusted Device Recovery**:
  - **Milestone 2.1**: Native Android & iOS client apps, FCM/APNs Push 2FA with number matching.
  - **Milestone 2.2**: Android `AccountManager` & iOS Shared Keychain SSO, Trusted Device token recovery with mandatory 48-hour freeze window & 90-day GDPR data retention.
- **Phase 3 Enterprise & Guardian Recovery**:
  - **Milestone 3.1**: Pre-enrolled Guardian Recovery with Shamir's Secret Sharing (2-of-3 threshold) and 48-hour freeze window.
  - **Milestone 3.2**: Enterprise SAML 2.0 & SCIM 2.0 support, physical DB connection pool isolation, self-hosting Helm charts, and custom domain SSL management.
