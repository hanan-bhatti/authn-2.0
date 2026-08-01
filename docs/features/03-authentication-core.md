# Feature 03: Core Authentication Engine (Signup & Password Login)

**Module**: `apps/auth-engine/internal/auth` & `apps/auth-engine/pkg/jwt`  
**Version**: 1.0.0  
**Status**: Implemented, Production-Ready & Verified  

---

## 1. Overview

The **Core Authentication Engine** processes user registration, RFC 9106 Argon2id password verification, 15-minute signed JWT access token issuance, 64-byte opaque refresh token generation, `HttpOnly` cookie setting, telemetry extraction, and automated security audit logging.

---

## 2. Production Security Features

1. **RFC 9106 Argon2id Hashing**: $t=3, m=64\text{MB}, p=4$ with 16-byte random salt per user.
2. **Dual-Token Architecture**:
   * `access_token`: Short-lived (15-minute) signed JWT returned in JSON payload (`pkg/jwt/signer.go`).
   * `refresh_token`: 64-byte opaque random token returned in JSON AND set as `HttpOnly`, `SameSite=Lax` cookie. Stored in database strictly as a SHA-256 hash.
3. **Telemetry Capture**: Extracts client `IP Address` and `User-Agent` from HTTP request headers and stores them on the `Session` record.
4. **Automated Audit Logging**: Automatically records an `AuditLog` database entry for `user.signed_up` and `user.signed_in`.
5. **Last Sign-In Timestamp**: Automatically updates `last_sign_in_at` on the `User` entity upon successful password login.

---

## 3. Endpoints & Live Verification Payloads

### 3.1 User Signup (`POST /v1/client/signup`)
* **Request**:
  ```bash
  curl -i -X POST http://localhost:8080/v1/client/signup \
    -H "Content-Type: application/json" \
    -d '{
      "tenant_id": "tnt_prod",
      "environment": "test",
      "email": "sarah@example.com",
      "password": "SuperSecretPassword123!",
      "name": "Sarah Connor"
    }'
  ```
* **HTTP Response Headers & Payload (201 Created)**:
  ```http
  HTTP/1.1 201 Created
  Content-Type: application/json
  Set-Cookie: authn_refresh_token=38e1f95f...; path=/v1/client; HttpOnly; SameSite=Lax

  {
    "user": {
      "id": "usr_908d6d37-e78",
      "email": "sarah@example.com",
      "name": "Sarah Connor",
      "status": "active",
      "created_at": "2026-08-01T17:32:42Z"
    },
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "38e1f95fbb77af9becb7e8665412999158c2effe698984b7c6606e974e837e68"
  }
  ```

### 3.2 User Login (`POST /v1/client/login`)
* **Request**:
  ```bash
  curl -i -X POST http://localhost:8080/v1/client/login \
    -H "Content-Type: application/json" \
    -d '{
      "tenant_id": "tnt_prod",
      "environment": "test",
      "email": "sarah@example.com",
      "password": "SuperSecretPassword123!"
    }'
  ```
* **HTTP Response Headers & Payload (200 OK)**:
  ```http
  HTTP/1.1 200 OK
  Content-Type: application/json
  Set-Cookie: authn_refresh_token=d8a562a8...; path=/v1/client; HttpOnly; SameSite=Lax

  {
    "user": {
      "id": "usr_908d6d37-e78",
      "email": "sarah@example.com",
      "name": "Sarah Connor",
      "status": "active",
      "created_at": "2026-08-01T17:32:42Z"
    },
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "d8a562a85a2ce102ae321453591d893146fa6174fc57f5693613aacfc60ad56a"
  }
  ```

---

## 4. How to Test Locally

1. **Run Unit Tests**:
   ```bash
   cd apps/auth-engine && go test -v ./internal/auth/...
   ```
2. **Run HTTP Server**:
   ```bash
   cd apps/auth-engine && go run ./cmd/server/main.go
   ```
3. **Execute Signup & Login via Curl**:
   * Signup: Use command in Section 3.1.
   * Login: Use command in Section 3.2.
