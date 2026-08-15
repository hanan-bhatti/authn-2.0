# FR-14: Admin User Impersonation ("Log in as User") Feature Specification

## 1. Overview
Admin User Impersonation allows customer support representatives and tenant administrators to temporarily access customer accounts to troubleshoot issues, verify UI bugs, and reproduce user support tickets in real-time.

To prevent privilege escalation and unauthorized access, FR-14 enforces:
1. **Mandatory Admin Step-Up Authentication (Sudo Mode)**: Re-verifying Passkey assertion, 2FA TOTP code, or Password before issuing impersonation JWT tokens.
2. **Hierarchy Protection**: Preventing administrators from impersonating other administrators.
3. **Read-Only Security Guard (`PreventImpersonatedMutations`)**: Blocking destructive account mutations (password reset, 2FA removal, account deletion) during active impersonation sessions.
4. **User Transparency Notifications**: Immediate HTML/text email alerts sent to the target user informing them of support access.
5. **Real-Time Event Webhooks**: Emitting `user.impersonated` and `user.impersonation_exited` signed webhooks to external security tools and SIEM systems.

---

## 2. Impersonation Policy Schema
Tenant-wide boundaries are persisted in `tenant.security_policy["impersonation_policy"]`:

```json
{
  "max_duration_minutes": 15,
  "require_reason": true,
  "require_ticket_id": false,
  "require_step_up_auth": true,
  "require_user_opt_in": false,
  "restrict_admin_impersonation": true,
  "email_notification_policy": "IMMEDIATE"
}
```

### Validation Bounds
- `max_duration_minutes`: Hard cap between `1` and `60` minutes (default: `15`).
- `reason`: Mandatory non-empty string between `10` and `500` characters.
- `ticket_id`: Optional unless `require_ticket_id = true` (`3` to `100` characters).
- `email_notification_policy`: `"IMMEDIATE"`, `"POST_SESSION"`, or `"DISABLED"`.

---

## 3. Impersonation Token & JWT Claims
Tokens issued via `jwt.IssueImpersonationToken` contain explicit security claims:

```json
{
  "sub": "usr_target123",
  "tenant_id": "tnt_00000000000000000000000000000001",
  "environment": "live",
  "email": "customer@example.com",
  "impersonator_id": "usr_admin99",
  "is_impersonated": true,
  "iss": "authn-engine",
  "iat": 1785938400,
  "exp": 1785939300
}
```

---

## 4. Security Guards & Middleware Flow

```
[Admin Request] -> POST /v1/admin/users/:user_id/impersonate
                        │
                        ├─▶ Check Admin 2FA Policy (RequireAdminAuth)
                        ├─▶ Check RBAC Permission ('users:impersonate')
                        ├─▶ Check Hierarchy Guard (IsTargetUserAdmin?)
                        ├─▶ Sudo Step-Up Auth (Password / TOTP / Passkey)
                        ├─▶ Dispatch 'user.impersonated' Webhook & Transparency Email
                        └─▶ Issue 15-minute Impersonation JWT Token
```

```
[Client Request] -> PUT /v1/client/user/password (Bearer Token)
                        │
                        ├─▶ Inspect Token Claim 'is_impersonated' == true
                        └─▶ BLOCK: 403 Forbidden ("code": "impersonation_read_only_restricted")
```

---

## 5. API Endpoints

### 5.1 Initiate Impersonation
`POST /v1/admin/users/:user_id/impersonate`

**Headers**:
- `Authorization: Bearer {{consoleAdminToken}}` OR `Bearer {{secretKey}}`

**Request Body**:
```json
{
  "reason": "Investigating customer invoice display issue #8841",
  "duration_minutes": 15,
  "verification_method": "password",
  "admin_password": "AdminSecret123!"
}
```

**Response (`200 OK`)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "impersonated_user": {
    "id": "usr_target123",
    "email": "customer@example.com",
    "status": "active"
  },
  "impersonator_id": "usr_admin99",
  "session_id": "ses_imp_178593849102"
}
```

### 5.2 Exit Impersonation Session
`POST /v1/client/auth/impersonate/exit`

**Headers**:
- `Authorization: Bearer {{impersonationToken}}`

**Response (`200 OK`)**:
```json
{
  "message": "impersonation session exited successfully",
  "impersonated_id": "usr_target123",
  "impersonator_id": "usr_admin99"
}
```

---

## 6. Error & Edge Case Matrix

| Error Code | HTTP Status | Description |
| :--- | :--- | :--- |
| `admin_step_up_required` | `400 Bad Request` | Admin step-up authentication omitted when required by policy. |
| `invalid_admin_password` | `401 Unauthorized` | Invalid password provided for step-up auth. |
| `invalid_admin_2fa_code` | `401 Unauthorized` | Invalid 2FA TOTP code provided for step-up auth. |
| `impersonation_hierarchy_violation` | `403 Forbidden` | Target user holds admin role (`tenant_admin`, `admin`, `super_admin`). |
| `user_opt_in_required` | `403 Forbidden` | Target user has not granted support access permission (`support_access_enabled: false`). |
| `insufficient_permissions` | `403 Forbidden` | Caller lacks `users:impersonate` RBAC permission. |
| `impersonation_read_only_restricted` | `403 Forbidden` | Destructive account mutation attempted during active impersonation session. |
