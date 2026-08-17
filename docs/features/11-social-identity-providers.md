# Feature Spec 11: Social Identity Providers (OAuth2 & OpenID Connect)

**Feature Code**: FR-7  
**Tier**: Core Authentication & Identity Provisioning Layer  
**Status**: Production Implemented & Verified (100% Postman & Integration Test Pass)  

---

## 1. Executive Summary

Authn provides out-of-the-box support for single sign-on (SSO) and social login via **OAuth2** and **OpenID Connect (OIDC)** across 8 built-in drivers: **Google**, **GitHub**, **Discord**, **Microsoft**, **Apple**, **Facebook**, **X (Twitter)**, **LinkedIn**, as well as custom **Generic OIDC** providers (e.g. Okta, Keycloak, Auth0).

Social login enables users to authenticate seamlessly while allowing tenant administrators to configure credentials via an administrative API with automated format validation, secret encryption at rest, and dynamic developer setup guides.

---

## 2. Key Architecture & Security Controls

### 2.1 Dynamic Callback URL Derivation (Zero Hardcoded Domains)
The engine never hardcodes callback URLs. All OAuth callback URLs are computed dynamically at runtime via `cfg.SocialCallbackURL(provider)` using the `APP_BASE_URL` environment variable:
```
{APP_BASE_URL}/v1/client/auth/social/{provider}/callback
```
Example output in setup guides:
- Self-hosted: `https://auth.acme.com/v1/client/auth/social/google/callback`
- Development: `http://localhost:8080/v1/client/auth/social/google/callback`

### 2.2 Ephemeral State Nonces (One-Time CSRF Protection)
To prevent OAuth CSRF and session-hijacking attacks, the server generates a 16-byte cryptographically random token, hex-encoded to 32 characters, and stores it as a `SocialAuthState` row prior to redirecting the user to the provider:
- **Configurable TTL**: `expires_at` set to `now + SOCIAL_AUTH_STATE_TTL`.
- **Atomically Consumed & Hard-Deleted**: `ConsumeSocialAuthState` hard-deletes the state record upon read, before the expiry check, so a replayed callback URL returns `400 Bad Request` whether or not the token had expired.

### 2.3 Account Linking & Credential Injection Defense
- **Existing Social Identity**: Logs the user in by creating a session and issuing an access token bound to it.
- **Email Collision (Existing Password Account)**: Returns `409 Conflict` (`email_exists_social_account`). This prevents malicious attackers from creating a social account with a victim's email address to compromise an existing password account.
- **Authenticated Account Linking**: When an existing authenticated user adds a provider from account settings, the new `Identity` record attaches securely to their `userID`.
- **New Social User**: Automatically provisions a new `User` record (with `password_hash = nil`) and links the `Identity`.

### 2.4 AES-256-GCM Credential Encryption
Provider `client_secret`s are encrypted at rest using AES-256-GCM with `AuthnEncryptionKey`. Secrets are masked and omitted from all tenant GET responses, and decrypted strictly inside the isolated social service layer during token exchange.

### 2.5 Apple Sign In OIDC Support
Since Apple does not provide a standard `/userinfo` endpoint, the `AppleProvider` parses and validates claims (`sub`, `email`) directly from the signed OIDC `id_token` JWT returned during the code exchange step.

---

## 3. Provider Setup & Validation Format Rules

Tenant admins can configure social providers via `PUT /v1/tenant/social-providers/:provider`. Format rules are automatically enforced per provider:

| Provider | `client_id` Validation Rule | `client_secret` Validation Rule |
| :--- | :--- | :--- |
| **Google** | Must end with `.apps.googleusercontent.com` | Non-empty string |
| **GitHub** | 10+ characters (alphanumeric or `Iv1.` prefix) | 20+ hex characters |
| **Discord** | Numeric Snowflake ID | 32-character string |
| **Microsoft** | UUID v4 (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) | Non-empty string |
| **Apple** | Reverse-domain Services ID (e.g., `com.app.auth`) | Signed JWT from `.p8` key |
| **Facebook** | Numeric App ID | 32-character hex string |
| **X (Twitter)** | Non-empty string | Non-empty string |
| **LinkedIn** | Non-empty string | Non-empty string |
| **Generic OIDC**| Non-empty string | Requires valid `issuer_url` |

---

## 4. REST API Endpoint Index

### 4.1 Client Endpoints (Publishable Key `pk_test_...`)
- `GET /v1/client/auth/social/:provider/authorize` — Initiates social login, persists a state row for `SOCIAL_AUTH_STATE_TTL`, returns `302 Found` redirect to provider.
  - Query Params: `redirect_uri` (required), `post_callback_redirect` (optional).
- `GET /v1/client/auth/social/:provider/callback` — Handles OAuth code exchange, user lookup/creation, creates a session and issues a JWT access token bound to it, and sets the HttpOnly refresh cookie.
  - Query Params: `code` (required), `state` (required).

### 4.2 Admin Management Endpoints (Secret Key `sk_test_...`)
- `GET /v1/tenant/social-providers` — Lists all 8 supported social providers with configuration status and step-by-step setup guides.
- `GET /v1/tenant/social-providers/:provider` — Gets setup guide and current config for a single provider (secrets masked).
- `PUT /v1/tenant/social-providers/:provider` — Updates provider status and credentials with strict format validation.
- `DELETE /v1/tenant/social-providers/:provider` — Deletes social provider configuration for the tenant.

---

## 5. Data Model & Schema Reference

### `Tenant.social_providers` (JSON Field)
Stores tenant-level provider credentials:
```json
{
  "google": {
    "enabled": true,
    "client_id": "123456789012-abc.apps.googleusercontent.com",
    "client_secret_encrypted": "base64_AES256GCM_ciphertext=="
  }
}
```

### `SocialAuthState` (Ent Schema Entity)
Ephemeral CSRF state token entity:
- `id` (`string`, PK): the state token itself — 16 random bytes, hex-encoded.
- `tenant_id` (`string`): Scope tenant boundary.
- `application_id` (`string`): Initiating application ID.
- `environment` (`string`): Environment (`test` / `live`).
- `provider` (`string`): Provider identifier (`google`, `github`, etc.).
- `redirect_uri` (`string`): Validated application callback URI.
- `post_callback_redirect` (`string`): Post-login destination URI.
- `expires_at` (`time.Time`): Expiration timestamp (`now + SOCIAL_AUTH_STATE_TTL`).

### `Identity` (Ent Schema Entity)
Maps social profiles to users:
- `id` (`string`, PK): `idn_...` prefixed unique ID.
- `user_id` (`string`): Foreign key link to `User`.
- `provider` (`string`): Provider name.
- `provider_user_id` (`string`): Unique subject ID from provider.
- `email` (`string`): Primary email from provider profile.
- `access_token_encrypted` (`string`): Encrypted provider access token.
- `refresh_token_encrypted` (`string`): Encrypted provider refresh token.
