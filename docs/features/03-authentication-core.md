# Feature 03: Core Authentication Engine (Signup & Password Login)

**Module**: `apps/auth-engine/internal/auth`  
**Version**: 1.0.0  
**Status**: Implemented & Verified  

---

## 1. Overview

The **Core Authentication Engine** processes user registration, Argon2id password verification, opaque refresh token generation, and login session creation.

---

## 2. API Endpoints

### 2.1 User Signup (`POST /v1/client/signup`)
* **Request Payload**:
  ```json
  {
    "tenant_id": "tnt_demo123",
    "environment": "test",
    "email": "user@example.com",
    "password": "SuperSecretPassword123!",
    "name": "Alex Smith"
  }
  ```
* **Response (201 Created)**:
  ```json
  {
    "user": {
      "id": "usr_1a2b3c4d5e6f",
      "email": "user@example.com",
      "name": "Alex Smith",
      "status": "active",
      "created_at": "2026-08-01T12:00:00Z"
    },
    "refresh_token": "a1b2c3d4e5f6..."
  }
  ```

### 2.2 User Password Login (`POST /v1/client/login`)
* **Request Payload**:
  ```json
  {
    "tenant_id": "tnt_demo123",
    "environment": "test",
    "email": "user@example.com",
    "password": "SuperSecretPassword123!"
  }
  ```
* **Response (200 OK)**:
  ```json
  {
    "user": {
      "id": "usr_1a2b3c4d5e6f",
      "email": "user@example.com",
      "name": "Alex Smith",
      "status": "active",
      "created_at": "2026-08-01T12:00:00Z"
    },
    "refresh_token": "a1b2c3d4e5f6..."
  }
  ```

---

## 3. Security Guarantee

* **Argon2id Baseline**: $t=3, m=64\text{MB}, p=4$ with 16-byte cryptographically secure random salt per user.
* **Opaque Refresh Tokens**: 64-byte random byte tokens. Stored in database strictly as SHA-256 hashes.
