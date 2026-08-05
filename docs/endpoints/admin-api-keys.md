# Endpoint Specification: Admin API Keys Management (`POST /v1/admin/keys/`, `GET /v1/admin/keys/`, `POST /v1/admin/keys/:id/revoke`)

## Overview
* **Routes**:
  * `POST /v1/admin/keys/` — Issue new publishable (`pk_...`) or secret (`sk_...`) API key
  * `GET /v1/admin/keys/` — List all active and revoked API keys for the caller's application
  * `POST /v1/admin/keys/:id/revoke` — Instantly revoke an API key by ID
* **HTTP Methods**: `POST`, `GET`
* **Purpose**: Production Admin API Key lifecycle engine. Enforces strict environment isolation (`test` keys cannot manage `live` keys), cryptographically hashes keys at rest (SHA-256), returns raw key string ONCE upon issuance, and supports immediate soft-revocation.

---

## Authentication & Access Control
* **Protected By**: `RequireSecretKey` middleware (`X-Authn-Secret-Key: sk_<env>_<hash>`).
* **Environment Isolation**: A `test`-mode admin key (`sk_test_...`) can only issue/list/revoke `test`-mode keys. A `live`-mode admin key (`sk_live_...`) can only manage `live`-mode keys. Attempting cross-environment key management returns `400 Bad Request`.

---

## Key Structure & Prefixes
* **Publishable Key (`pk_...`)**: `pk_<env>_<32-byte-hex-random>`
* **Secret Key (`sk_...`)**: `sk_<env>_<32-byte-hex-random>`
* **Storage Security**: Only `SHA-256(raw_key)` is stored in the database. `raw_key` is returned in response ONCE at creation.

---

## Request & Response Examples

### 1. Issue Secret API Key (`POST /v1/admin/keys/`)
```json
{
  "name": "Stripe Webhook Handler",
  "type": "secret",
  "environment": "test",
  "expires_in_days": 30
}
```
**Response (201 Created)**:
```json
{
  "key": {
    "id": "key_1e3d11488ab3",
    "application_id": "app_test123",
    "name": "Stripe Webhook Handler",
    "type": "secret",
    "key_prefix": "sk_test_",
    "environment": "test",
    "created_at": "2026-08-06T03:16:31Z",
    "expires_at": "2026-09-05T03:16:31Z"
  },
  "raw_key": "sk_test_3a22900c15f9f6cb3250ac9d78edca11a56273bcd40cd1fe32a81e3d11488ab3"
}
```

### 2. Revoke API Key (`POST /v1/admin/keys/:id/revoke`)
```bash
$ curl -i -X POST -H "X-Authn-Secret-Key: sk_test_..." \
  http://localhost:8080/v1/admin/keys/key_1e3d11488ab3/revoke
```
**Response (200 OK)**:
```json
{
  "id": "key_1e3d11488ab3",
  "status": "revoked"
}
```

### 3. Attempt API Call with Revoked Key
```bash
$ curl -i -H "X-Authn-Secret-Key: sk_test_3a22900c..." \
  http://localhost:8080/v1/admin/keys/
```
**Response (401 Unauthorized)**:
```json
{
  "error": "invalid, expired, or revoked secret key"
}
```

---

## Security Audit & Attack Mitigation Log

| Attack Vector / Test | Payload / Input | Response Status | Security Defense Execution |
| :--- | :--- | :--- | :--- |
| **Unauthenticated Request** | `POST /v1/admin/keys/` (No `sk_`) | `401 Unauthorized` | Blocked by secret key middleware |
| **Cross-Environment Attack** | `test` key attempting to create `live` key | `400 Bad Request` | Environment isolation check enforced |
| **Invalid Key Type** | `"type":"super_admin_exploit"` | `400 Bad Request` | Key type validation (`publishable` or `secret`) |
| **Secret Key Issuance** | `POST /v1/admin/keys/` | `201 Created` | SHA-256 hash stored in DB, `raw_key` returned once |
| **Revoked Key Access** | Request with revoked `sk_test_3a22...` | `401 Unauthorized` | Key status check rejected revoked key |

*Last Verified*: `2026-08-06` — live `curl` attack suite against running server.
