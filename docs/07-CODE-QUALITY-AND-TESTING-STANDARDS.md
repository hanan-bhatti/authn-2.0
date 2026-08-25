# Code Quality, Testing & Formatting Standards

**Document Version**: 1.0.0  
**Date**: 2026-08-01  
**Status**: Approved Specification  
**Author**: Authn Core Team  

---

## 1. Verified Latest Technology Stack & Runtime Versions

| Tool / Technology | Version | Purpose & Description |
| :--- | :--- | :--- |
| **Go** | `v1.26+` | High-performance backend engine & Ent ORM data layer |
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

## 2. File Naming Conventions (`*.controller.ts`, `*_handler.go`)

To maintain clean separation of concerns and predictable folder structures across the monorepo:

### 2.1 TypeScript & React Naming Conventions (`apps/web-*`, `packages/*`)
* Controllers / Endpoints: `[feature].controller.ts` or `[feature].handler.ts` (e.g. `auth.controller.ts`)
* Domain Services: `[feature].service.ts` (e.g. `auth.service.ts`)
* Database Repositories: `[feature].repository.ts` (e.g. `user.repository.ts`)
* Data Transfer Objects / Schemas: `[feature].dto.ts` (e.g. `auth.dto.ts`)
* Test Specs: `[feature].test.ts` or `[feature].spec.ts`
* UI Components: `[component-name].tsx`

### 2.2 Go Naming Conventions (`apps/auth-engine/internal/*`)
* Handlers / Controllers: `internal/http/handlers/[feature]_handler.go` (e.g. `auth_handler.go`)
* Domain Services: `internal/services/[feature]_service.go` (e.g. `auth_service.go`)
* Database Repositories: `internal/repository/[feature]_repository.go` (e.g. `user_repository.go`)
* Data Transfer Objects: `internal/dto/[feature]_dto.go` (e.g. `auth_dto.go`)
* Unit Tests: `[feature]_test.go` (e.g. `auth_service_test.go`)

---

## 3. OpenAPI / Swag Annotation Standard for HTTP Controllers

All HTTP Handlers / Controllers must be annotated with Swag OpenAPI comments directly above the function definition:

```go
// @Summary      Sign in with email and password
// @Description  Authenticates user credentials against tenant DB and returns session or 2FA step-up challenge token.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request body dto.LoginRequestDTO true "User credentials payload"
// @Success      200 {object} dto.LoginResponseDTO "Successful authentication"
// @Failure      400 {object} dto.ErrorResponseDTO "Invalid JSON payload"
// @Failure      401 {object} dto.ErrorResponseDTO "Invalid email or password"
// @Failure      429 {object} dto.RateLimitErrorDTO "Rate limit exceeded"
// @Router       /v1/client/auth/login [post]
func (h *AuthHandler) Login(c *fiber.Ctx) error
```

---

## 4. File Header Banner & GoDoc / JSDoc Standards

### 4.1 File Header Banner (Top of Every File)
Every file must start with a multi-line comment header:

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

### 4.2 Complete Function Docstrings
Every exported function must specify parameters, return types, and failure states:

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

## 5. Pre-flight Environment Validation & Zero Hardcoded Config

* **Strict Rule**: Zero hardcoded ports, URLs, timeouts, secret keys, or feature toggles anywhere in code.
* **Boot Validation Manager (`config/env.go`)**: Server startup executes a mandatory pre-flight validation routine. Missing or invalid required environment variables cause immediate startup termination.
* **Dynamic Feature Flags**: Managed via env (`FEATURE_PUSH_2FA_ENABLED=true`, `FEATURE_MAGIC_LINK_ENABLED=true`, `FEATURE_WEBHOOKS_ENABLED=true`, `FEATURE_RBAC_ENABLED=true`).

---

## 6. Code Quality & Testing Architecture

* **Go Linters**: `golangci-lint` (`gofmt`, `govet`, `errcheck`, `staticcheck`, `revive`, `bodyclose`).
* **TypeScript Linters**: ESLint + Prettier. Strict TypeScript (`strict: true`, no `any`).
* **Go Tests**: `testing` + `testcontainers-go` (Min 80% coverage).
* **TypeScript Tests**: `Vitest` + `Playwright`.
