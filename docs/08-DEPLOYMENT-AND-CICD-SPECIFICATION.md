# Deployment & CI/CD Specification

**Document Version**: 1.0.0  
**Date**: 2026-08-01  
**Status**: Approved Specification (Execution Ready)  
**Author**: Authn Core Team  

---

## 1. Container & Docker Compose Self-Hosting Architecture

The **Authn Platform** is packaged for instant self-hosting via Docker Compose or Kubernetes Helm charts.

### 1.1 `docker-compose.yml` Architecture

```yaml
version: '3.8'

services:
  auth-engine:
    build:
      context: .
      dockerfile: docker/Dockerfile.auth-engine
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - DATABASE_URL=postgres://authn:secret@postgres:5432/authn?sslmode=disable
      - REDIS_URL=redis:6379
      - AUTHN_ENCRYPTION_KEY=32_byte_random_kms_encryption_key!
      - AUTHN_API_KEY_PEPPER=32_byte_random_api_key_pepper_key!
      - JWT_SIGNING_KEY_PATH=/etc/authn/keys/rsa_private.pem
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: always

  web-console:
    build:
      context: .
      dockerfile: docker/Dockerfile.web-console
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_AUTHN_API_URL=http://localhost:8080
    depends_on:
      - auth-engine
    restart: always

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=authn
      - POSTGRES_PASSWORD=secret
      - POSTGRES_DB=authn
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U authn"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
```

---

## 2. GitHub Actions CI/CD Pipeline (`.github/workflows/ci.yml`)

The platform enforces automated quality, security, and build validation on every Pull Request and main branch push.

### 2.1 CI Workflow Pipeline Stages

```mermaid
graph TD
    A[Git Push / PR] --> B[Job 1: Linting & Code Standards]
    A --> C[Job 2: Backend Go Tests & Testcontainers]
    A --> D[Job 3: Frontend Tests & Next.js Build]
    A --> E[Job 4: Dependency Vulnerability Audit]
    
    B --> F{All Jobs Passed?}
    C --> F
    D --> F
    E --> F
    
    F -- Yes (Main Branch) --> G[Job 5: Docker Build & Push to GHCR]
    F -- No --> H[Fail Pipeline & Notify Devs]
```

### 2.2 GitHub Actions Configuration (`.github/workflows/ci.yml`)

```yaml
name: Authn CI/CD Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  lint:
    name: Lint & Code Quality
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - uses: pnpm/action-setup@v3
        with:
          version: 9
      - uses: golangci/golangci-lint-action@v4
        with:
          version: v1.56.2
          working-directory: apps/auth-engine
      - run: pnpm install
      - run: pnpm lint

  test-backend:
    name: Backend Go Tests (Testcontainers)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Run Go Unit & Integration Tests
        run: |
          cd apps/auth-engine
          go test -v -coverprofile=coverage.out ./...

  test-frontend:
    name: Frontend SDK & Next.js Build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v3
        with:
          version: 9
      - run: pnpm install
      - run: pnpm test
      - run: pnpm build

  security-audit:
    name: Security & Vulnerability Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Run Go Vulnerability Scanner
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          cd apps/auth-engine && govulncheck ./...
      - uses: pnpm/action-setup@v3
        with:
          version: 9
      - run: pnpm audit
```
