# Feature 03: Core Authentication Engine (Signup & Password Login)

**Module**: `apps/auth-engine/internal/auth` & `apps/auth-engine/pkg/jwt`  
**Version**: 1.1.0 (XSS Token Protection Upgrade)  
**Status**: Implemented, Production-Ready & Verified  

---

## 1. Overview

The **Core Authentication Engine** processes user registration, RFC 9106 Argon2id password verification, 15-minute signed JWT access token issuance, 64-byte opaque refresh token generation, client-type XSS protection, telemetry extraction, and automated security audit logging.

---

## 2. Client-Type XSS Token Security Architecture

To prevent **Cross-Site Scripting (XSS)** token theft vulnerabilities in web applications while maintaining full support for native mobile apps and CLI SDKs:

### A. Web Browsers (Default / `X-Authn-Client-Type: web`)
* **HttpOnly Cookie**: The 64-byte `refresh_token` is sent **EXCLUSIVELY** via a secure `Set-Cookie: authn_refresh_token=...; Path=/v1/client; HttpOnly; SameSite=Lax`.
* **JSON Body Hardening**: `refresh_token` is **100% OMITTED** from the JSON response body. Even if an XSS vulnerability exists on a web application, malicious scripts cannot read the refresh token from `response.json()`.

### B. Native Mobile & CLI SDKs (`X-Authn-Client-Type: native` or `mobile`)
* **JSON Body Delivery**: Mobile OS webviews (Android KeyStore / iOS Keychain) cannot consume `Set-Cookie` headers across app boundaries. Native clients receive `refresh_token` in the JSON response body.

---

## 3. Live Verified Payloads

### 3.1 Web Browser Response (`POST /v1/client/login`)
```bash
curl -i -X POST http://localhost:8080/v1/client/login \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"tnt_prod","environment":"test","email":"sarah@example.com","password":"SuperSecretPassword123!"}'
```
**HTTP Response (200 OK)**:
```http
HTTP/1.1 200 OK
Set-Cookie: authn_refresh_token=eef8114e...; path=/v1/client; HttpOnly; SameSite=Lax

{
  "user": {
    "id": "usr_908d6d37-e78",
    "email": "sarah@example.com",
    "name": "Sarah Connor",
    "status": "active",
    "created_at": "2026-08-01T17:32:42Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```
*(Notice: `refresh_token` is completely absent from the JSON body!)*

---

### 3.2 Native Mobile Response (`POST /v1/client/login` + `X-Authn-Client-Type: native`)
```bash
curl -i -X POST http://localhost:8080/v1/client/login \
  -H "Content-Type: application/json" \
  -H "X-Authn-Client-Type: native" \
  -d '{"tenant_id":"tnt_prod","environment":"test","email":"sarah@example.com","password":"SuperSecretPassword123!"}'
```
**HTTP Response (200 OK)**:
```http
HTTP/1.1 200 OK

{
  "user": {
    "id": "usr_908d6d37-e78",
    "email": "sarah@example.com",
    "name": "Sarah Connor",
    "status": "active",
    "created_at": "2026-08-01T17:32:42Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "ebe5a048a9741b2cb2450c67011453fb886a8f9ab2166c4516e8de6be6caae4c"
}
```
