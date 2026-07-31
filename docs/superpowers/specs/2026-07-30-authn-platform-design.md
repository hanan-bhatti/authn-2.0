# Authn Platform Architecture & Technical Design Specification

**Date**: 2026-07-30  
**Project**: Authn (Open-Source Authentication & Identity Platform)  
**Status**: Approved Specification (Updated with Architectural Decision Records)  

---

## 1. Executive Summary

**Authn** is an enterprise-grade, open-source authentication and identity management platform designed to be a developer-friendly alternative to Auth0, Firebase Auth, and Keycloak. 

Key highlights of the platform architecture:
- **Go Engine**: Low-latency, high-concurrency Go backend using Ent ORM with multi-database support (PostgreSQL, MySQL, SQLite, CockroachDB) and Redis/Dragonfly caching.
- **Monorepo Structure**: Turborepo-managed monorepo isolating backend services, Next.js web applications, mobile clients, and shared SDK npm packages.
- **Pluggable Identity Providers**: First-class support for Social Auth (Google, Apple, X, Facebook, GitHub, Microsoft, Discord, LinkedIn) and custom OpenID Connect (OIDC).
- **Firebase-Style Client Direct Access**: Dual API key model (`pk_live_...` publishable client keys and `sk_live_...` secret admin keys) enabling direct SDK calls from web and mobile frontends.
- **Native Mobile Account Manager & Push 2FA**: Dedicated Android and iOS client applications supporting real-time push notifications ("Is this you logging in? [Approve] / [Deny]") with number-matching push fatigue defense, and system-level cross-app SSO via Android `AccountManager` and iOS `ASWebAuthenticationSession`.

---

## 2. Monorepo & System Architecture

### 2.1 Repository Structure (`pnpm` + `Turborepo`)

```
authn/
├── apps/
│   ├── auth-engine/          # Go Backend Engine (Ent ORM, Fiber HTTP, OIDC Provider, 2FA Engine)
│   ├── web-console/          # Next.js (console.authn.com - Developer & Tenant Management Portal)
│   ├── web-landing/          # Next.js (authn.com - Platform Landing Page & Cloud SaaS Signup)
│   ├── web-docs/             # Next.js / Fumadocs (docs.authn.com - Documentation & Quickstarts)
│   ├── web-demo/             # Next.js (demo.authn.com - Live "Sign in with Authn" interactive demo)
│   ├── mobile-android/       # Android Application (Kotlin - System AccountManager + Push 2FA)
│   └── mobile-ios/           # iOS Application (Swift - ASWebAuthenticationSession + Push 2FA)
├── packages/
│   ├── ui/                   # Shared React UI Component Library (TailwindCSS + shadcn/ui)
│   ├── sdk-js/               # Core JavaScript / TypeScript Client SDK (@authn/js)
│   ├── sdk-react/            # React Components & Hooks (@authn/react)
│   ├── config-eslint/        # Shared ESLint configurations
│   └── config-typescript/    # Shared TypeScript configuration bases
├── docs/
│   └── superpowers/specs/    # Architecture & Design Specifications
├── docker/                   # Self-hosting Docker Compose & Helm Charts
├── turbo.json
└── pnpm-workspace.yaml
```

### 2.2 Protocol Scope & API Boundaries
- **External Interfaces**: REST / HTTP API + WebSockets for client SDKs and public OIDC endpoints.
- **Internal RPCs**: gRPC used strictly for high-throughput service-to-service communication between the Auth Engine and background push notification bridge workers.
- **SAML 2.0 Scope**: Deferred to Phase 3 Enterprise Roadmap to keep Phase 1 focused strictly on OAuth 2.0, OIDC, and Social Identity Providers.

---

## 3. Backend Engine Architecture (`apps/auth-engine`)

### 3.1 Core Stack
- **Language**: Go 1.22+
- **HTTP / Internal RPC**: Fiber + gRPC
- **Database Abstraction**: Ent ORM (`entgo.io`)
- **Supported Databases**: PostgreSQL, MySQL, SQLite, CockroachDB
- **Cache & Pub/Sub Queue**: Redis / Dragonfly

### 3.2 Authentication & Protocol Support
- **OAuth 2.0 & OpenID Connect (OIDC)**: PKCE (Proof Key for Code Exchange) authorization flow, JWT ID tokens, encrypted opaque refresh tokens, and public JWKS endpoint (`/.well-known/jwks.json`).
- **Exact-Match URI Security**: Enforces exact string matching for OAuth2 `redirect_uri` parameters (no wildcards permitted) in accordance with OAuth 2.0 Security Best Current Practice (BCP).
- **Pluggable Social Identity Providers**: Unified `IdentityProvider` Go interface supporting Google, Apple, X (Twitter), Facebook, GitHub, Microsoft, Discord, LinkedIn, and custom OIDC providers.
- **Refresh Token Storage & Rotation**:
  - Refresh tokens are 64-byte high-entropy opaque strings.
  - The server stores the **SHA-256 hash** of the refresh token in the `Session` entity.
  - Each refresh invocation rotates the token and invalidates the previous hash, with a 10-second grace window to handle concurrent requests gracefully.
- **Multi-Factor Authentication (2FA)**:
  - Push Notification Prompt: Real-time FCM/APNs push notification to mobile client apps. Includes **Number Matching** (displaying a 2-digit code on web that user selects on mobile) to defend against Push Fatigue attacks, plus a rate limit of 3 push prompts per 5 minutes per device.
  - WebAuthn / Passkeys: FIDO2 biometric authentication (FaceID, TouchID, Windows Hello, YubiKeys).
  - TOTP: RFC 6238 time-based one-time password generation.
  - Email Recovery: Secure single-use fallback codes & signed magic links.

### 3.3 Database Schema Entities (`Ent ORM`)
- `Tenant`: Multi-tenant boundary containing configuration, custom branding, and rate limits.
- `Application`: Registered client application containing CORS origins, exact redirect URIs, and API key records.
- `ApiKey`: Client publishable (`pk_...`) and secret admin (`sk_...`) key records.
- `User`: Core user account profile, password hash (Argon2id), status, and metadata.
- `Identity`: Linked social/federated provider identities (provider, provider_user_id, tokens).
- `Session`: Active user session records (refresh token hash, device fingerprint, IP, user-agent, expires_at).
- `TwoFactorMethod`: Enabled 2FA configurations (TOTP secret, WebAuthn credentials).
- `PushDevice`: Registered FCM/APNs push notification tokens for mobile 2FA.
- `AuditLog`: Security event telemetry (login attempts, 2FA failures, key rotations).

---

## 4. Frontend Applications & Shared Packages

### 4.1 Applications (`apps/`)
- **`web-console` (`console.authn.com`)**: Tenant dashboard for managing API keys, configuring social provider secrets, user administration, auditing security logs, and setting up custom login branding.
- **`web-landing` (`authn.com`)**: Marketing site featuring product showcase, live code preview widgets, security docs, and SaaS pricing tiers.
- **`web-docs` (`docs.authn.com`)**: Comprehensive documentation site with quickstarts, SDK references, and self-hosting guides.
- **`web-demo` (`demo.authn.com`)**: Interactive playground allowing developers to test "Sign in with Authn", experiment with 2FA prompts, and inspect JWT tokens.
- **Hosted Auth UI**: Custom-branded, accessible login, signup, 2FA prompt, and password reset flows.

### 4.2 Shared Packages (`packages/`)
- **`packages/ui`**: Design system tokens and shared React components powered by TailwindCSS and shadcn/ui.
- **`packages/sdk-js`**: Framework-agnostic JavaScript client library providing direct API access (`signUp`, `signInWithPassword`, `signInWithProvider`, `verify2FA`, `signOut`, `onAuthStateChanged`).
- **`packages/sdk-react`**: React components (`<AuthnProvider />`, `<SignInButton />`) and React hooks (`useAuthn`, `useUser`, `useSession`).

---

## 5. Mobile Ecosystem (Android & iOS Clients)

### 5.1 Push 2FA Authenticator App
- Native Android (Kotlin) and iOS (Swift) mobile apps.
- Receives FCM / APNs high-priority push notifications when a login attempt occurs.
- Displays request metadata: App Name, Browser/Device, IP Address, Geolocation, Timestamp.
- Requires **Number Matching verification** (user matches the 2-digit code displayed on the login screen) before signing the response with the local device private key.

### 5.2 On-Device Single Sign-On (SSO)
- **Android**: Custom `AccountManager` service registration. Apps built with `@authn/android-sdk` can query the local system account service for silent token exchange without redirecting to a browser.
- **iOS**: Uses `ASWebAuthenticationSession`, Shared Keychain Groups, and Credential Provider Extension for silent cross-app token sharing.

---

## 6. Security Architecture & Quality Assurance

### 6.1 Cryptographic & Operational Security
- **Password Hashing**: Argon2id with memory-hard parameters.
- **JWKS Key Rotation**: RSA-2048 / ECDSA-P256 asymmetric keypairs rotated automatically every 30 days. Includes a **7-day overlapping grace period** where old public keys remain published in JWKS (`/.well-known/jwks.json`) to prevent validation failures on active tokens.
- **CORS & Rate Limiting**: Strict origin validation on publishable API key routes; Redis sliding window rate-limiter by IP and Client API key.
- **Multi-Tenancy**: Ent privacy interceptors enforcing tenant boundary checks on every database query automatically.

### 6.2 Testing Strategy
- **Go Unit & Integration Tests**: In-memory SQLite for fast unit tests; `testcontainers-go` for PostgreSQL & Redis integration testing.
- **Frontend & E2E Tests**: Component unit testing and Playwright E2E coverage for complete OAuth2 PKCE and 2FA authentication flows.
