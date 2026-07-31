# Authn 2.0 — Enterprise Open-Source Authentication & Identity Platform

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4+-3178C6?style=flat&logo=typescript)](https://www.typescriptlang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-15+-000000?style=flat&logo=next.js)](https://nextjs.org/)
[![Turborepo](https://img.shields.io/badge/Turborepo-2.0+-EF4444?style=flat&logo=turborepo)](https://turbo.build/)

> **Authn** is an enterprise-grade, high-performance, open-source authentication and identity management platform. Designed as a modern, self-hostable alternative to Auth0, Firebase Auth, and Keycloak with native Android/iOS account integration and push-fatigue 2FA defense.

---

## ✨ Key Features

* **⚡ Ultra-Low Latency Go Engine**: Sub-10ms P95 latency powered by Go 1.22+ and Fiber, backed by **Ent ORM** supporting PostgreSQL, MySQL, SQLite, and CockroachDB.
* **🔐 Dual API Key Architecture**: Firebase-style publishable keys (`pk_live_...`) for direct frontend SDK calls, and secret keys (`sk_live_...`) for backend admin tasks.
* **📱 Native Mobile SSO**: Android `AccountManager` system integration and iOS Shared Keychain Groups for silent cross-app single sign-on across companion mobile apps.
* **🛡️ Push 2FA with Number-Matching Defense**: FCM (Android) & APNs (iOS) real-time push prompts. Displays a 2-digit code on the web login screen while insulating the push payload (the phone never receives the correct answer), neutralizing push fatigue malware attacks.
* **🔑 OpenID Connect & OAuth 2.0 Server**: Full PKCE authorization flow, asymmetric RS256/ES256 signed ID tokens, automated 30-day JWKS key rotation, and strict exact-match `redirect_uri` validation.
* **👑 Role-Based Access Control (RBAC)**: Define custom tenant roles and permissions included directly in JWT claims.
* **🔔 Real-Time Event Webhooks**: Developer-configured HTTP webhooks signed with HMAC-SHA256 headers (`X-Authn-Signature`) on key security events.
* **🎭 Admin User Impersonation**: Secure, audited admin API (`/v1/admin/users/:userId/impersonate`) for customer support and troubleshooting.
* **✉️ Passwordless Magic Links & 2FA**: One-click 15-minute magic email login links, TOTP authenticators, WebAuthn Passkeys, and SMS OTP.
* **🏢 B2B Organizations & Team Invites**: Multi-tenant workspace organizations and cryptographically signed team member invitation flows.
* **🆘 Smart Device Recovery**: Google-style account recovery using cryptographically signed device tokens, IP subnet telemetry, universal 48-hour freeze windows, and pre-enrolled 2-of-3 Shamir's Secret Sharing (SSS) guardians.

---

## 🏗️ Monorepo Directory Architecture

```
authn-2.0/
├── apps/
│   ├── auth-engine/          # Go 1.22+ Backend Service (Ent ORM, Fiber HTTP/gRPC, OIDC Server)
│   ├── web-console/          # Next.js 15 Developer & Tenant Portal (console.authn.com)
│   ├── web-landing/          # Next.js 15 Platform Landing Page (authn.com)
│   ├── web-docs/             # Next.js / Fumadocs Documentation Hub (docs.authn.com)
│   ├── web-demo/             # Next.js 15 Interactive "Sign in with Authn" Demo (demo.authn.com)
│   ├── mobile-android/       # Native Android Kotlin Client (AccountManager SSO & Push 2FA)
│   └── mobile-ios/           # Native iOS Swift Client (ASWebAuthenticationSession SSO & Push 2FA)
├── packages/
│   ├── ui/                   # Shared React UI Component Library (TailwindCSS + shadcn/ui)
│   ├── sdk-js/               # Core Framework-Agnostic JavaScript/TypeScript Client SDK (@authn/js)
│   ├── sdk-react/            # React Auth Hooks & UI Components (@authn/react)
│   ├── config-eslint/        # Shared ESLint Flat Configuration
│   └── config-typescript/    # Shared TypeScript Base TSConfig Bases
├── docs/                     # Full 8-Document Technical Specification Suite
├── docker/                   # Self-Hosting Docker Compose & Kubernetes Configs
├── turbo.json
└── pnpm-workspace.yaml
```

---

## 📚 Technical Documentation Suite (`docs/`)

Explore our comprehensive technical specifications:

1. 📄 **[docs/01-PRD.md](file:///home/hanan-bhatti/authn/docs/01-PRD.md)** — Product Requirements Document (PRD v1.0.0)
2. 📄 **[docs/02-DATABASE-SCHEMA.md](file:///home/hanan-bhatti/authn/docs/02-DATABASE-SCHEMA.md)** — Database Schema & Ent ORM Specification
3. 📄 **[docs/03-API-SPECIFICATION.md](file:///home/hanan-bhatti/authn/docs/03-API-SPECIFICATION.md)** — REST & OpenID Connect API Specification
4. 📄 **[docs/04-MOBILE-ARCHITECTURE.md](file:///home/hanan-bhatti/authn/docs/04-MOBILE-ARCHITECTURE.md)** — Android & iOS SSO & Push 2FA Specification
5. 📄 **[docs/05-SECURITY-THREAT-MODEL.md](file:///home/hanan-bhatti/authn/docs/05-SECURITY-THREAT-MODEL.md)** — OWASP Threat Matrix & Cryptography Spec
6. 📄 **[docs/06-SDK-SPECIFICATION.md](file:///home/hanan-bhatti/authn/docs/06-SDK-SPECIFICATION.md)** — `@authn/js` & `@authn/react` Client SDK Specification
7. 📄 **[docs/07-CODE-QUALITY-AND-TESTING-STANDARDS.md](file:///home/hanan-bhatti/authn/docs/07-CODE-QUALITY-AND-TESTING-STANDARDS.md)** — Linting, Formatting & Testing Standards
8. 📄 **[docs/08-DEPLOYMENT-AND-CICD-SPECIFICATION.md](file:///home/hanan-bhatti/authn/docs/08-DEPLOYMENT-AND-CICD-SPECIFICATION.md)** — Docker Compose & GitHub Actions CI/CD Pipeline

---

## 🚀 Quickstart & Local Development

### Prerequisites
* **Node.js**: v20.0.0+
* **pnpm**: v9.0.0+
* **Go**: v1.22+
* **Docker Engine**: Optional for local Redis/PostgreSQL containers

### Installation & Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/hanan-bhatti/authn-2.0.git
   cd authn-2.0
   ```

2. **Install Workspace Dependencies**:
   ```bash
   pnpm install
   ```

3. **Run Local Development Servers**:
   ```bash
   pnpm dev
   ```

4. **Self-Hosting via Docker Compose**:
   ```bash
   docker compose up -d
   ```

---

## 📄 License

Distributed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See [`LICENSE`](file:///home/hanan-bhatti/authn/LICENSE) for more information.
