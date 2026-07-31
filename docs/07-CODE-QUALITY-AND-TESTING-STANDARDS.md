# Code Quality, Testing & Formatting Standards

**Document Version**: 1.0.0  
**Date**: 2026-08-01  
**Status**: Approved Specification  
**Author**: Authn Core Team  

---

## 1. Verified Latest Technology Stack & Runtime Versions

| Tool / Technology | Version | Purpose & Description |
| :--- | :--- | :--- |
| **Go** | `v1.23+` | High-performance backend engine & Ent ORM data layer |
| **Kotlin (Android)** | `v2.1.0+` | Native Android client with K2 compiler & AccountManager SSO |
| **Gradle** | `v8.12+` | Android build automation system |
| **Android Gradle Plugin (AGP)** | `v8.8+` | Android Gradle build plugin |
| **Swift (iOS)** | `v6.0+` | Native iOS client with strict concurrency safety & Shared Keychain SSO |
| **TypeScript** | `v5.8+` | Type-safe static analysis for SDKs and web applications |
| **Next.js** | `v16.2+` | React 19 App Router & Cache Components framework |
| **React** | `v19.2+` | User interface library with Server Actions |
| **pnpm** | `v11.18+` | High-performance monorepo package manager |
| **Turborepo** | `v2.10+` | Incremental build & task cache pipeline |

---

## 2. Pre-flight Environment Validation & Zero Hardcoded Config

* **Strict Rule**: Zero hardcoded ports, URLs, timeouts, secret keys, or feature toggles anywhere in code.
* **Boot Validation Manager (`config/env.go`)**: Server startup executes a mandatory pre-flight validation routine. All environment variables must match explicit schema types, minimum string lengths, and valid URL formats.
* **Fail-Fast Behavior**: Missing or invalid required environment variables (e.g. `AUTHN_ENCRYPTION_KEY`, `DATABASE_URL`) cause immediate startup termination with explicit diagnostic logs.
* **Dynamic Feature Flags**: Managed strictly via environment variables (`FEATURE_PUSH_2FA_ENABLED=true`, `FEATURE_MAGIC_LINK_ENABLED=true`, `FEATURE_WEBHOOKS_ENABLED=true`, `FEATURE_RBAC_ENABLED=true`, `FEATURE_IMPERSONATION_ENABLED=true`).

---

## 3. Clean Layered Architecture (Separation of Concerns)

Every single file in the project must belong to one explicit architectural tier:

```
HttpRequest ──► [ Handler / Controller ]   (Parses JSON, validates inputs, formats HTTP responses)
                        │
                        ▼
                 [ Service Layer ]         (Pure business logic, security checks, feature flags)
                        │
                        ▼
               [ Repository Layer ]        (Ent ORM queries, database transactions, Redis cache)
```

1. **Handlers / Controllers (`http/handlers/`)**: Pure HTTP parsing layer. Validates DTOs, extracts headers/cookies, calls services, formats JSON responses. Zero database logic allowed.
2. **Services (`services/`)**: Pure domain logic. Enforces business rules, security policies, Argon2id hashing, feature flag checks, and transaction orchestration.
3. **Repositories (`repository/`)**: Pure persistence layer. Executes Ent ORM queries and Redis Lua scripts.

---

## 4. Mandatory File Headers & Complete Function Docstrings

### 4.1 File Header Banner (Top of Every File)
Every single file must begin with a multi-line comment header:

```go
/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/services/auth_service.go
 * Tier: Domain Logic / Service Layer
 *
 * Description: Core authentication service handling password validation,
 *              Argon2id hashing, 2FA challenge generation, and session issuance.
 *
 * Security Notice:
 *   - Passwords must NEVER be logged in plain text.
 *   - Failed login attempts trigger Redis sliding-window rate limiting.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */
```

### 4.2 Complete Function Docstrings (GoDoc / JSDoc)
Every exported function must include explicit parameters, return types, and failure states:

```go
// ValidatePasswordCredentials authenticates a user using email and password.
//
// Parameters:
//   - ctx: Request context containing tenant and environment scope.
//   - email: The user's registered email address.
//   - rawPassword: Plain text password provided during login.
//
// Returns:
//   - *domain.Session: Active session object if login is successful.
//   - *domain.TwoFactorChallenge: Non-nil if user requires 2FA step-up.
//   - error: ErrInvalidCredentials, ErrRateLimited, or ErrAccountFrozen.
func (s *AuthService) ValidatePasswordCredentials(ctx context.Context, email string, rawPassword string) (*domain.Session, *domain.TwoFactorChallenge, error)
```

---

## 5. Code Quality & Linting Standards

### 5.1 Go Code Quality Standards (`apps/auth-engine`)
* **Linter**: `golangci-lint` configured via `.golangci.yml`.
* **Enabled Linters**: `gofmt`, `govet` (shadowing check), `errcheck` (unhandled error check), `staticcheck`, `revive`, `bodyclose` (closing HTTP response bodies).
* **Forbidden**: Zero `any` or `interface{}` casts in domain logic.

### 5.2 TypeScript & React Code Quality Standards (`packages/*`, `apps/web-*`)
* **Linter**: ESLint configured via `@authn/config-eslint`.
* **Formatter**: Prettier configured via `.prettierrc`.
* **Strict TypeScript**: `strict: true`, `noImplicitAny: true`, `noUnusedLocals: true`, `noUnusedParameters: true`.
* **Forbidden**: `any` type annotations are strictly prohibited.

---

## 6. Testing Architecture & Coverage Requirements

### 6.1 Go Backend Testing Strategy
* **Unit Testing**: Standard Go `testing` package with `stretchr/testify`.
* **Integration Testing**: `testcontainers-go` for running isolated PostgreSQL and Redis instances in CI/CD.
* **Coverage Target**: Minimum **80% code coverage** for authentication, token generation, 2FA, and security modules.

### 6.2 TypeScript & React Testing Strategy
* **Unit & Component Testing**: `Vitest` + `@testing-library/react`.
* **End-to-End (E2E) Testing**: `Playwright` for automated browser authentication testing.

---

## 7. Git Commit & Pre-Commit Policy

* **Conventional Commits**: Commit messages must follow Conventional Commit syntax (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`).
* **Pre-commit Automated Checks**: Every PR must pass `pnpm lint`, `pnpm build`, and `golangci-lint run` prior to merge.
