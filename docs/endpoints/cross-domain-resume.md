# Cross-Domain Resume-to-Destination Specification

## Overview
The Authn Platform guarantees safe, seamless post-authentication redirection to third-party client web applications across distinct domain boundaries (e.g., from `https://auth.company.com` to `https://app.example.com/callback` or `https://dashboard.example.com`).

Supported authentication flows:
1. **OIDC / OAuth 2.0 Authorization Code Flow** (`GET /v1/oauth/authorize`)
2. **SAML 2.0 Assertion Consumer Service Flow** (`POST /v1/saml/acs`)
3. **Social OAuth 2.0 Flow** (`GET /v1/client/auth/social/:provider/authorize`)

---

## 1. OIDC / OAuth 2.0 State & Redirect Preservation

### Request
```http
GET /v1/oauth/authorize?client_id=app_test_crossdomain&redirect_uri=http://localhost:3000/callback&response_type=code&state=xyz_state_123&code_challenge=E9Mel-rnDkhZj6gTI9LBEK123&code_challenge_method=S256 HTTP/1.1
Host: localhost:8080
Authorization: Bearer <session_access_token>
X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012
```

### Live Pentest Response Evidence
```http
HTTP/1.1 302 Found
Date: Thu, 06 Aug 2026 02:01:46 GMT
Content-Length: 0
Vary: Origin
X-Authn-Degraded-Mode: false
Location: http://localhost:3000/callback?code=ac_ddf0a778be20eb1de54eca6c9c921c35e2cfbc9e1d5d8926&state=xyz_state_123
```

---

## 2. Social OAuth 2.0 Cross-Domain Resume

### Request
```http
GET /v1/client/auth/social/google/authorize?redirect_uri=http://localhost:8080/v1/client/auth/social/google/callback&post_callback_redirect=http://localhost:3000/dashboard HTTP/1.1
Host: localhost:8080
X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012
```

### Live Pentest Response Evidence
```http
HTTP/1.1 302 Found
Date: Thu, 06 Aug 2026 02:01:46 GMT
Content-Length: 0
Vary: Origin
X-Authn-Degraded-Mode: false
Location: https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&client_id=123456789.apps.googleusercontent.com&prompt=consent&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fv1%2Fclient%2Fauth%2Fsocial%2Fgoogle%2Fcallback&response_type=code&scope=openid+email+profile&state=fa80058a1b3a91cd3b38672ce3e69be2
```
