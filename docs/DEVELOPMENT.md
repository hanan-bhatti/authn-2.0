# Development & Environment Configuration Guide

## Overview

The **Authn Engine** is engineered with strict separation between runtime environment modes (`development`, `test`, `staging`, `production`).

---

## 1. Environment Modes & Pre-flight Validation

The environment mode is configured via `APP_ENV` (or `ENV`).

### Environment Differentiation Matrix

| Requirement / Behavior | `development` / `test` | `production` |
| :--- | :--- | :--- |
| **Strict Pre-flight Fail-Fast** | Disabled (falls back to local defaults) | **ENABLED** (Immediate process exit on missing keys) |
| **`DATABASE_URL`** | Optional (defaults to `file:authn.db?cache=shared&_fk=1`) | **MANDATORY** |
| **`REDIS_URL` / `AUTHN_REDIS_URL`** | Optional (defaults to `redis://localhost:6379`) | **MANDATORY** |
| **`AUTHN_ENCRYPTION_KEY`** | Optional (defaults to 32-byte dev key) | **MANDATORY** ($\ge 32$ chars) |
| **`AUTHN_API_KEY_PEPPER`** | Optional (defaults to 32-byte dev key) | **MANDATORY** ($\ge 32$ chars) |
| **`JWT_SIGNING_KEY_PATH`** | Optional (defaults to `.keys/rsa_private.pem`) | **MANDATORY** |
| **Database Seeding (`cmd/seed`)** | Allowed | **STRICTLY PROHIBITED** (Exits code 1) |
| **Internal Stack Traces in Error API** | Logged | **SUPPRESSED** (Returns clean generic HTTP status) |

---

## 2. Database Seeding Tool (`cmd/seed/main.go`)

To seed local or staging database environments with fixture users, roles, organizations, and API keys:

```bash
go run ./cmd/seed
```

### Seed Command Safety & Behavior
- **Idempotent Upsert Strategy**: Safe to run repeatedly without duplicate record conflicts or database crashes.
- **Production Guard**: Hard-refuses to execute if `APP_ENV=production` or `ENV=production` is detected.

---

## 3. Seeded Fixture Credentials Reference

When `go run ./cmd/seed` completes, the following test fixtures are provisioned:

### API Keys
* **Publishable Key (`pk_...`)**: `pk_test_demo12345678901234567890123456789012`
* **Secret Key (`sk_...`)**: `sk_test_demo12345678901234567890123456789012`

### Organizations
* **Acme Corp**: ID `org_acme`, Slug `acme-corp`

### User Fixtures Table

| Email | Password | Role | Fixture Test Purpose / State |
| :--- | :--- | :--- | :--- |
| `admin@authn.local` | `AdminPass123!` | `tenant_admin` | System Admin & `org_admin` of `org_acme` |
| `user.totp@authn.local` | `UserPass123!` | `viewer` | TOTP 2FA Enrolled (Secret: `JBSWY3DPEHPK3PXP`) |
| `user.unverified@authn.local` | `UserPass123!` | `viewer` | Email Unverified (`email_verified: false`) |
| `user.orgmember@authn.local` | `UserPass123!` | `editor` | Organization Member of `org_acme` |
| `user.guardians@authn.local` | `UserPass123!` | `viewer` | Recovery Guardians Configured (`guardian@authn.local`) |
| `user.vanilla@authn.local` | `UserPass123!` | `viewer` | Standard / Vanilla Active User |
