# Feature 06: Email & Communication Provider Drivers (FR-3)

**Module**: `apps/auth-engine/internal/email`, `apps/auth-engine/internal/policy`  
**Version**: 1.0.0  
**Status**: Implemented, Production-Ready & Verified  

---

## 1. Overview

The **Email & Communication Provider Driver Engine** implements pluggable email delivery architecture for the Authn Platform (FR-3). It features a provider-agnostic `EmailProvider` interface, a standard SMTP driver (compatible with local catchers like Mailpit/MailHog and production SMTP relays), built-in HTML/Text template rendering for email verification, single-use SHA-256 token hashing, fail-closed Redis rate limiting, and configurable tenant security policy enforcement modes (Disabled, Soft Gate, and Hard Block).

---

## 2. Pluggable Architecture & Drivers

### 2.1 `EmailProvider` Interface ([`internal/email/provider.go`](../../apps/auth-engine/internal/email/provider.go))
```go
type EmailProvider interface {
	Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error
}
```

### 2.2 Implemented Drivers & Factory
1. **SMTP Driver ([`internal/email/smtp.go`](../../apps/auth-engine/internal/email/smtp.go))**: Formats RFC 2046 `multipart/alternative` MIME messages (HTML + Plain text fallback) and transmits via standard SMTP over `net/smtp`.
2. **Resend Driver ([`internal/email/resend.go`](../../apps/auth-engine/internal/email/resend.go))**: Integrates with Resend REST API (`https://api.resend.com/emails`) using `RESEND_API_KEY`.
3. **SendGrid Driver ([`internal/email/sendgrid.go`](../../apps/auth-engine/internal/email/sendgrid.go))**: Integrates with SendGrid v3 API (`https://api.sendgrid.com/v3/mail/send`) using `SENDGRID_API_KEY`.
4. **Postmark Driver ([`internal/email/postmark.go`](../../apps/auth-engine/internal/email/postmark.go))**: Integrates with Postmark REST API (`https://api.postmarkapp.com/email`) using `POSTMARK_SERVER_TOKEN`.
5. **AWS SES Driver ([`internal/email/aws_ses.go`](../../apps/auth-engine/internal/email/aws_ses.go))**: Integrates with AWS SES v2 Outbound API using `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION`.
6. **No-op Driver ([`internal/email/noop.go`](../../apps/auth-engine/internal/email/noop.go))**: Fallback logger for unconfigured or test environments.

### 2.3 Factory & Driver Selection ([`internal/email/factory.go`](../../apps/auth-engine/internal/email/factory.go))
The driver is selected seamlessly via `EMAIL_DRIVER` in `.env`:
```bash
EMAIL_DRIVER=smtp # "smtp" | "resend" | "sendgrid" | "postmark" | "aws_ses" | "noop"
```

---

## 3. Template Engine & Verification Tokens

### 3.1 Template Rendering ([`internal/email/template.go`](../../apps/auth-engine/internal/email/template.go))
Uses Go standard library `html/template` and `text/template` to compile dark-themed, responsive HTML emails with plain-text fallback:
* **Dynamic variables**: `UserName`, `VerificationLink`, `AppName`, `ExpiresInHours`.

### 3.2 Security & Token Storage Pattern
* **Generation**: 32 cryptographically random bytes -> 64-character hex raw token.
* **Storage**: Stored strictly as a **SHA-256 hash** (`email_verification_token`) with a 24-hour expiration (`email_verification_expires_at`) on the `User` Ent entity. Raw tokens are never stored in the database.
* **Single-Use Verification**: Once verified, `email_verified` is set to `true`, and token fields are cleared.

---

## 4. Tenant Security Policy & Enforcement Modes

Tenant administrators can configure `security_policy` per tenant (`apps/auth-engine/ent/schema/tenant.go` JSON blob):

| Policy Mode | Attribute | Description |
| :--- | :--- | :--- |
| **Disabled** | `require_email_verification: false` | Default. Verification email is sent on signup, but login is unrestricted. |
| **Soft Gate** | `require_email_verification: true`, `mode: "soft"` | Login succeeds (`HTTP 200 OK`) with session tokens, but returns `policy_warning.requires_email_verification: true`. |
| **Hard Block** | `require_email_verification: true`, `mode: "hard"` | Login is blocked (`HTTP 403 Forbidden`) with `error: "email_verification_required"`. Zero session or access tokens issued. |

---

## 5. API Endpoint Reference

### 5.1 Verify Email Address
* **Endpoint**: `GET /v1/client/auth/verify-email?token=raw_token_string`
* **Response (200 OK)**:
```json
{
  "message": "email successfully verified",
  "email": "user@example.com",
  "email_verified": true
}
```

### 5.2 Resend Verification Email
* **Endpoint**: `POST /v1/client/auth/resend-verification`
* **Rate Limiting**: Fail-closed sliding window (5 attempts per 15 min)
* **Payload**:
```json
{
  "email": "user@example.com",
  "tenant_id": "tnt_00000000000000000000000000000001",
  "environment": "test"
}
```
* **Response (200 OK)**:
```json
{
  "message": "if an account exists with this email address, a verification link has been sent"
}
```

### 5.3 Get Tenant Security Policy (Admin)
* **Endpoint**: `GET /v1/tenant/security-policy?tenant_id=tnt_00000000000000000000000000000001`
* **Response (200 OK)**:
```json
{
  "require_email_verification": true,
  "email_verification_mode": "hard"
}
```

### 5.4 Update Tenant Security Policy (Admin)
* **Endpoint**: `PUT /v1/tenant/security-policy?tenant_id=tnt_00000000000000000000000000000001`
* **Payload**:
```json
{
  "require_email_verification": true,
  "email_verification_mode": "hard"
}
```

---

## 6. Local Development Catcher (Mailpit)

For local development and testing, emails are captured using **Mailpit**:
```bash
docker run -d --name authn-mailpit -p 1025:1025 -p 8025:8025 axllent/mailpit
```
* **SMTP Host**: `localhost:1025`
* **Web UI Inbox**: `http://localhost:8025`
* **REST API**: `http://localhost:8025/api/v1/messages`
