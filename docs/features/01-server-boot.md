# Feature 01: Server Boot & Pre-flight Architecture

**Module**: `apps/auth-engine/cmd/server/main.go` & `apps/auth-engine/internal/config`  
**Version**: 1.0.0  
**Status**: Implemented & Verified  

---

## 1. Overview

The **Server Boot & Pre-flight Engine** handles runtime initialization, environment configuration validation, Ent ORM database connection pool startup, Fiber HTTP server setup, and graceful shutdown handling.

---

## 2. Key Components & Implementation

### 2.1 Pre-flight Environment Validation (`internal/config/env_config.go`)
* **Fail-Fast Security Policy**: In production (`ENV=production`), the engine verifies `AUTHN_ENCRYPTION_KEY` (32+ bytes) and `AUTHN_API_KEY_PEPPER` (32+ bytes). Missing keys trigger immediate server boot termination to prevent operating in an insecure state.
* **Development Fallback Mode**: In local development, sensible defaults (`sqlite3`, `8080`) are applied automatically.

### 2.2 Global Middleware Stack (`internal/middleware/`)
1. **`recover.New()`**: Prevents panic crashes from taking down the process.
2. **`logger.New()`**: Structured HTTP request & latency logging.
3. **`DynamicCORS()`**: Allows multi-tenant cross-origin requests (`X-Authn-Api-Key`, `X-Authn-Tenant-Id`, `X-Authn-Environment`).
4. **`DegradedModeHeader()`**: Dynamically injects `X-Authn-Degraded-Mode: true` if a Redis outage is detected.

### 2.3 Health Check API (`GET /v1/health`)
* **Endpoint**: `GET /v1/health`
* **Response**:
  ```json
  {
    "status": "healthy",
    "version": "1.0.0",
    "timestamp": "2026-08-01T16:55:00Z"
  }
  ```

---

## 3. Verification & Testing

* **Build Verification**: `go build -o /tmp/auth-engine ./apps/auth-engine/cmd/server/main.go`
* **Execution**: Executable runs, binds to `:8080`, responds to `GET /v1/health` with `200 OK`.
