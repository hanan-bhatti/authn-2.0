# Endpoint Specification: System Health & Security Policies (`/healthz`, `/readyz`, `/v1/tenant/security-policy`, `/v1/tenant/password-policy`)

## Overview
* **Routes**:
  * `GET /healthz` (or `/v1/health`) — Liveness probe (Returns engine status & UTC timestamp)
  * `GET /readyz` (or `/v1/ready`) — Readiness probe (Checks live database ORM & Redis connectivity)
  * `GET /v1/tenant/security-policy` — Get tenant security policy (Token reuse strategy, Email verification rules)
  * `PUT /v1/tenant/security-policy` — Update tenant security policy
  * `GET /v1/tenant/password-policy` — Get tenant password complexity rules
  * `PUT /v1/tenant/password-policy` — Update tenant password complexity rules
* **HTTP Methods**: `GET`, `PUT`
* **Purpose**: Infrastructure monitoring, Kubernetes probe support, and dynamic security policy management (configuring `global_revoke` vs `session_revoke` token reuse defense and Argon2id complexity parameters).

---

## Authentication & Access Control
* **Probes (`/healthz`, `/readyz`)**: Public unauthenticated probes for load balancers & Kubernetes.
* **Policy Configuration (`/v1/tenant/*-policy`)**: Require Secret Key (`X-Authn-Secret-Key: sk_<env>_<hash>`) or Console Admin JWT with `tenant_admin` role.

---

## Request & Response Examples

### 1. Liveness Probe (`GET /healthz`)
```bash
$ curl -i http://localhost:8080/healthz
```
**Response (200 OK)**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-08-05T22:19:46Z"
}
```

### 2. Readiness Probe (`GET /readyz`)
```bash
$ curl -i http://localhost:8080/readyz
```
**Response (200 OK — Dependencies Healthy)**:
```json
{
  "status": "ready",
  "checks": {
    "database": "ok",
    "redis": "ok"
  }
}
```

### 3. Update Security Policy (`PUT /v1/tenant/security-policy`)
```json
{
  "token_reuse_policy": "session_revoke",
  "require_email_verification": true,
  "email_verification_mode": "strict"
}
```
**Response (200 OK)**:
```json
{
  "require_email_verification": true,
  "email_verification_mode": "strict",
  "token_reuse_policy": "session_revoke"
}
```

---

## Security Audit & Verification Log

| Attack Vector / Test | Payload / Input | Response Status | Security Defense Execution |
| :--- | :--- | :--- | :--- |
| **Liveness Check** | `GET /healthz` | `200 OK` | Engine liveness verified |
| **Readiness Check** | `GET /readyz` | `200 OK` | Database & Redis connectivity verified |
| **Unauthenticated Policy Edit** | `PUT /v1/tenant/security-policy` (No `sk_`) | `401 Unauthorized` | Blocked by admin auth middleware |
| **Update Security Policy** | `token_reuse_policy: "session_revoke"` | `200 OK` | Configures consumer device isolation |
| **Update Password Policy** | `min_length: 12`, `require_special: true` | `200 OK` | Configures Argon2id validation bounds |

*Last Verified*: `2026-08-06` — live `curl` verification against running server.
