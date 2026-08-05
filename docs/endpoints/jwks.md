# Endpoint Specification: `GET /v1/oauth/jwks`

## Overview
* **Route**: `GET /v1/oauth/jwks`
* **HTTP Method**: `GET` (also supports `HEAD`)
* **Purpose**: JSON Web Key Set (JWKS) RFC 7517 endpoint. Exposes server public RSA key material (Modulus $N$, Exponent $E$) used by relying parties to verify JWT access tokens and ID tokens issued by the Authn Engine.

---

## Authentication & Access Control
* **Authentication Required**: `None` (Public / Unauthenticated)
* **Security Headers Required**: None. Any passed `Authorization`, `X-Publishable-Key`, or `X-Secret-Key` headers are safely ignored.

---

## Request Parameters
* **Headers**: None
* **Query Parameters**: None
* **Request Body**: None

---

## Responses & Status Codes

### `200 OK` — Public Key Set Payload
Returned with `Cache-Control: public, max-age=3600` header to allow relying parties to cache public keys locally.

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "authn-rsa-key-1",
      "n": "u1P5z2...",
      "e": "AQAB"
    }
  ]
}
```

### `405 Method Not Allowed` — Invalid HTTP Method
Returned when requesting with non-GET verbs (`POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`).

```json
{
  "error": {
    "code": 405,
    "message": "Method Not Allowed"
  }
}
```

---

## Rate Limiting Behavior
* **Exempt from Rate Limiting**: Registered at top-level `app.Get("/v1/oauth/jwks")` before rate-limiting middleware to allow external relying parties and API gateways to fetch public verification keys un-throttled.

---

## Design Notes & Security Audits
* **🔒 Zero Private Key Exposure**: Formally audited for cryptographic safety. The JSON response strictly exposes public parameters `n` (Modulus) and `e` (Exponent). Zero private key exponents (`d`, `p`, `q`, `dp`, `dq`, `qi`) are present.
* **`kid` Alignment**: The `kid` returned in the JWKS array strictly matches the `kid` embedded in the JOSE header of issued JWT tokens (`"kid": "authn-rsa-key-1"`).
* **Known Limitation — Single Active Key**: The endpoint currently exposes 1 active RSA key. Multi-key rotation history arrays (30-day rotation with 7-day overlap grace periods) are a planned future enhancement.

---

## Verification & Pentest History
* **Last Verified Date**: `2026-08-05`
* **Verification Method**: Manual live HTTP pentest + Automated Go Integration Test (`TestJWKSEndpoint`).
