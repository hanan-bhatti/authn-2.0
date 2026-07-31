# Code Quality, Testing & Formatting Standards

**Document Version**: 1.0.0  
**Date**: 2026-08-01  
**Status**: Approved Specification  
**Author**: Authn Core Team  

---

## 1. Code Quality & Linting Standards

### 1.1 Go Code Quality Standards (`apps/auth-engine`)
* **Linter**: `golangci-lint` configured via `.golangci.yml`.
* **Rules & Linters Enabled**:
  * `gofmt`: Enforces standard Go formatting.
  * `govet`: Checks for variable shadowing and struct alignment issues.
  * `errcheck`: Ensures all returned `error` values are handled explicitly (no unhandled errors).
  * `staticcheck`: Advanced static code analysis for Go.
  * `revive`: Fast, configurable linter for Go idioms.
  * `bodyclose`: Checks whether HTTP response bodies are closed properly (`defer resp.Body.Close()`).
* **Clean Code Rule**: Zero `any` or `interface{}` casts in domain logic.

### 1.2 TypeScript & React Code Quality Standards (`packages/*`, `apps/web-*`)
* **Linter**: ESLint configured via `@authn/config-eslint`.
* **Formatter**: Prettier configured via `.prettierrc` (2 spaces, 100 print width, double quotes).
* **Strict TypeScript**: `strict: true`, `noImplicitAny: true`, `noUnusedLocals: true`, `noUnusedParameters: true`.
* **Forbidden**: `any` type annotations are strictly prohibited; explicit interfaces/types are required.

---

## 2. Testing Architecture & Coverage Requirements

### 2.1 Go Backend Testing Strategy
* **Unit Testing**: Standard Go `testing` package with `stretchr/testify` for assertions.
* **Integration Testing**: `testcontainers-go` for running isolated PostgreSQL and Redis instances in CI/CD.
* **Database Testing**: In-memory SQLite driver for instant unit test execution.
* **Coverage Target**: Minimum **80% code coverage** for authentication, token generation, 2FA, and security modules.

### 2.2 TypeScript & React Testing Strategy
* **Unit & Component Testing**: `Vitest` + `@testing-library/react` for shared packages and Next.js applications.
* **End-to-End (E2E) Testing**: `Playwright` for automated browser tests covering OAuth2 PKCE login, signup, and 2FA prompt flows.

---

## 3. Git Commit & Code Review Policy

* **Conventional Commits**: Commit messages must follow Conventional Commit syntax (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`).
* **Pre-commit Automated Checks**: Every PR must pass `pnpm lint`, `pnpm build`, and `golangci-lint run` prior to merge.
