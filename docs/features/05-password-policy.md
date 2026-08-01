# Feature 05: Enterprise Tenant Password Policy Engine

**Module**: `apps/auth-engine/internal/policy`  
**Version**: 1.0.0  
**Status**: Implemented, Production-Ready & Verified  

---

## 1. Overview

The **Enterprise Tenant Password Policy Engine** allows tenant administrators to configure customizable password complexity requirements and enforcement modes for users registering or logging in via email and password (matching Firebase Console / Okta Enterprise security capabilities).

---

## 2. Configurable Policy Options

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enforcement_mode` | `string` | `"require"` | `"require"` (signup fails with 400) or `"notify"` (signup succeeds with warning payload). |
| `require_uppercase` | `bool` | `false` | Requires at least 1 uppercase letter (`[A-Z]`). |
| `require_lowercase` | `bool` | `false` | Requires at least 1 lowercase letter (`[a-z]`). |
| `require_numeric` | `bool` | `true` | Requires at least 1 numeric digit (`[0-9]`). |
| `require_special` | `bool` | `false` | Requires at least 1 special character (`[!@#$%^&*...]`). |
| `force_upgrade_on_signin` | `bool` | `false` | Flags non-compliant passwords on signin (`requires_password_upgrade: true`). |
| `min_length` | `int` | `6` | Minimum password length requirement (range: 6 to 4096). |
| `max_length` | `int` | `4096` | Maximum password length requirement (range: 6 to 4096). |

---

## 3. Policy Management Endpoints

### 3.1 Get Tenant Policy
* **Endpoint**: `GET /v1/tenant/password-policy?tenant_id=tnt_demo`
* **Response (200 OK)**:
```json
{
  "enforcement_mode": "require",
  "require_uppercase": false,
  "require_lowercase": false,
  "require_numeric": true,
  "require_special": false,
  "force_upgrade_on_signin": false,
  "min_length": 6,
  "max_length": 4096
}
```

### 3.2 Update Tenant Policy
* **Endpoint**: `PUT /v1/tenant/password-policy?tenant_id=tnt_demo`
* **Payload**:
```json
{
  "enforcement_mode": "require",
  "require_uppercase": true,
  "require_lowercase": true,
  "require_numeric": true,
  "require_special": true,
  "force_upgrade_on_signin": true,
  "min_length": 8,
  "max_length": 64
}
```

---

## 4. Enforcement Behaviors

### 4.1 Require Mode Failure (`HTTP 400 Bad Request`)
When `enforcement_mode == "require"`, non-compliant signup attempts are rejected immediately:
```json
{
  "error": "password does not meet policy requirements",
  "missing_criteria": [
    "min_length",
    "require_uppercase",
    "require_numeric",
    "require_special"
  ]
}
```

### 4.2 Notify Mode Warning (`HTTP 201 Created`)
When `enforcement_mode == "notify"`, registration completes but returns a `policy_warning` payload:
```json
{
  "user": { ... },
  "access_token": "...",
  "policy_warning": {
    "missing_criteria": [
      "min_length",
      "require_uppercase",
      "require_special"
    ]
  }
}
```
