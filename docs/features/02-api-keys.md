# Feature 02: API Keys Management

**Module**: `apps/auth-engine/internal/apikey`  
**Version**: 1.0.0  
**Status**: Implemented & Verified  

---

## 1. Overview

The **API Keys Engine** provides scoped API key generation, validation, and revocation for developer applications. API keys use explicit prefixes (`pk_test_...`, `pk_live_...`, `sk_test_...`, `sk_live_...`) and store peppered HMAC-SHA256 hashes in the database.

---

## 2. Key Architecture & Security Rules

1. **Prefix Scoping**:
   * `pk_test_` / `pk_live_`: Publishable client keys (used in `@authn/js` SDK).
   * `sk_test_` / `sk_live_`: Secret server keys (used in backend integrations).
2. **Peppered HMAC Hashing**: Plain-text secret API keys are shown to the user **ONLY ONCE** upon creation. The database stores strictly `HMAC-SHA256(raw_key, AUTHN_API_KEY_PEPPER)`.
3. **Revocation & Expiration**: Revoked or expired keys return `ErrInvalidApiKey` immediately.

---

## 3. Unit Tests & Verification

* **Test Suite**: `apps/auth-engine/internal/apikey/service_test.go`
* **Coverage**: Generation, prefix checks, HMAC calculation, database creation, and hash lookup.
