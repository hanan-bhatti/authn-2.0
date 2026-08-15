# FR-5 Phase 6: Lockout Engine Specification & Pentest Verification

## Overview
The Authn Platform implements a consolidated, multi-dimensional lockout engine. When an account exceeds the maximum allowed failed password authentication threshold (default: 5 consecutive failures within 900 seconds), an automated security lock is imposed.

During an active lockout:
1. **Exponential Backoff Penalties**: 1st violation triggers a 15-minute lock (`Retry-After: 900`), escalating up to 24 hours on repeat violations.
2. **Correct Password Rejection**: Attempting login with the **CORRECT** password while locked out is strictly rejected with `HTTP 429 Too Many Requests` (or `HTTP 423 Locked`). Password credentials are NOT evaluated, protecting against brute-force attacks.

---

## Live Pentest Evidence

### Failed Attempts 1 to 5 (Wrong Password)
```http
POST /v1/client/auth/login HTTP/1.1
Host: localhost:8080
Content-Type: application/json
X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012

{"email":"lockout_victim_e2e_final@example.com","password":"WrongPassword123!"}
```

```http
HTTP/1.1 401 Unauthorized
Date: Thu, 06 Aug 2026 02:01:57 GMT
Content-Type: application/json
Content-Length: 37

{"error":"invalid email or password"}
```

---

### Attempt 6 (CORRECT PASSWORD while Locked Out)
```http
POST /v1/client/auth/login HTTP/1.1
Host: localhost:8080
Content-Type: application/json
X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012

{"email":"lockout_victim_e2e_final@example.com","password":"Password123!"}
```

### Live Pentest Response Evidence
```http
HTTP/1.1 429 Too Many Requests
Date: Thu, 06 Aug 2026 02:01:57 GMT
Content-Type: application/json
Content-Length: 79
Vary: Origin
X-Authn-Degraded-Mode: false
Retry-After: 900

{"error":"too many attempts, please try again later","code":"rate_limited"}
```
