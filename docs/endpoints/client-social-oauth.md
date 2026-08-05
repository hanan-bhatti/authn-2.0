# Endpoint Specification: Social Identity Providers (`/v1/tenant/social-providers` & `/v1/client/auth/social/*`)

## Overview
* **Routes**:
  * `GET /v1/client/auth/social/:provider/authorize` — Initiate social OAuth authorization flow
  * `GET /v1/client/auth/social/:provider/callback` — OAuth authorization code callback handler
  * `GET /v1/tenant/social-providers` — Admin list all supported providers & setup guides
  * `GET /v1/tenant/social-providers/:provider` — Admin get specific provider configuration
  * `PUT /v1/tenant/social-providers/:provider` — Admin configure/enable social provider
  * `DELETE /v1/tenant/social-providers/:provider` — Admin remove social provider config
* **Supported Providers**: `google`, `github`, `discord`, `microsoft`, `apple`, `facebook`, `x`, `linkedin`
* **HTTP Methods**: `GET`, `PUT`, `DELETE`
* **Purpose**: Full OAuth 2.0 / OIDC Social Login Suite. Handles high-entropy CSRF state token generation/consumption, provider configuration encryption, pre-account takeover account linking checks, and provider setup guide generation.

---

## Authentication & Access Control
* **Client Endpoints (`/v1/client/auth/social/*`)**: Public or Publishable Key authenticated (`X-Authn-Publishable-Key`).
* **Admin Endpoints (`/v1/tenant/social-providers/*`)**: Requires Secret Key (`X-Authn-Secret-Key: sk_<env>_<hash>`) or Console Admin JWT.

---

## Request Payloads & Responses

### 1. Admin Configure Provider (`PUT /v1/tenant/social-providers/:provider`)
```json
{
  "enabled": true,
  "client_id": "demo_google_client_id_123.apps.googleusercontent.com",
  "client_secret": "demo_google_secret_xyz"
}
```
**Response (200 OK)**:
```json
{
  "message": "provider configured successfully",
  "provider": "google"
}
```

### 2. Initiate Authorize (`GET /v1/client/auth/social/:provider/authorize`)
* **Query Parameters**:
  * `redirect_uri` (Required): `http://localhost:3000/callback`
  * `post_callback_redirect` (Optional): Final client application URL to receive issued JWT access token.

**Response (302 Found Redirect)**:
```http
HTTP/1.1 302 Found
Location: https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&client_id=demo_google_client_id_123.apps.googleusercontent.com&prompt=consent&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fv1%2Fclient%2Fauth%2Fsocial%2Fgoogle%2Fcallback&response_type=code&scope=openid+email+profile&state=bceb5c5bb75bea309b1aff15df6195a5
```

### 3. Callback Handler (`GET /v1/client/auth/social/:provider/callback`)
* **Query Parameters**:
  * `code`: Provider authorization code.
  * `state`: 32-byte CSRF state token generated in Step 2.

**Response (200 OK — JSON Mode)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer"
}
```

---

## Pentest & Security Verification Log

| Test Case | Request | Observed Status | Defense Verification |
| :--- | :--- | :--- | :--- |
| **Unconfigured Provider** | `GET /authorize` for disabled provider | `400 Bad Request` | `social provider not enabled for this tenant` |
| **Admin Configuration** | `PUT /v1/tenant/social-providers/google` (`sk_...`) | `200 OK` | Encrypted persistence of client secrets |
| **Missing Parameter** | `GET /authorize` without `redirect_uri` | `400 Bad Request` | `redirect_uri query parameter is required` |
| **CSRF Token Generation** | `GET /authorize` with `redirect_uri` | `302 Found` | 32-byte hex state token generated & saved in Redis (10m TTL) |
| **Missing Callback Params** | `GET /callback` without `code` or `state` | `400 Bad Request` | Required query validation |
| **Forged/Replayed State** | `GET /callback` with fake state | `400 Bad Request` | Single-use Redis consumption & validity check |
| **Email Collision Check** | Social signup when email exists as password user | `409 Conflict` | Pre-account takeover defense (`email_exists_social_account`) |
| **Admin Setup Guides** | `GET /v1/tenant/social-providers` | `200 OK` | Returns step-by-step console instructions & URL rules |
| **Admin Provider Delete** | `DELETE /v1/tenant/social-providers/google` | `200 OK` | Config purged from database |

*Last Verified*: `2026-08-06` — live `curl` against running server.
