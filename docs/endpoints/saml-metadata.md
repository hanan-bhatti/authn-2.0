# Endpoint Specification: `GET /v1/saml/metadata/:orgId`

## Overview
* **Route**: `GET /v1/saml/metadata/:orgId`
* **HTTP Method**: `GET` (also supports `HEAD`)
* **Purpose**: Service Provider (SP) SAML 2.0 Metadata XML Exporter. Generates standard SAML 2.0 `EntityDescriptor` XML metadata containing the Assertion Consumer Service (ACS) endpoint and Service Provider Entity ID for SAML Identity Provider (IdP) configuration (FR-16).

---

## Authentication & Access Control
* **Authentication Required**: `None` (Public / Unauthenticated)
* **Security Headers Required**: None. Any passed `Authorization`, `X-Publishable-Key`, or `X-Secret-Key` headers are safely ignored.

---

## Request Parameters
* **URL Path Parameters**:
  * `:orgId` (string, required) — Organization ID or slug (e.g. `org_00000000000000000000000000000001`). Must correspond to an existing organization with an active SAML 2.0 connection.
* **Headers**: None
* **Query Parameters**: None
* **Request Body**: None

---

## Responses & Status Codes

### `200 OK` — SAML 2.0 SP Metadata XML Payload
Returned with `Content-Type: application/xml` and `Cache-Control: public, max-age=3600` headers.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="https://authn.com/saml/sp/org_00000000000000000000000000000001" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8080/v1/saml/acs" index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>
```

### `404 Not Found` — Organization or SAML Connection Not Found
Returned when `:orgId` does not exist in the database or has no configured SAML connection. Prevents arbitrary unauthenticated XML metadata generation for invalid organization identifiers.

```json
{
  "error": "SAML connection configuration not found for organization"
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

## Rate Limiting & Degraded Mode Behavior
* **Exempt from Rate Limiting**: Registered at top-level `app.Get("/v1/saml/metadata/:orgId")` before rate-limiting middleware to allow external SAML Identity Providers (Okta, Azure AD, PingFederate) to fetch SP metadata without throttling.
* **Fail-OPEN Read Policy**: If Redis cache is down, this endpoint continues operating normally with `X-Authn-Degraded-Mode: true`. See [`docs/ARCHITECTURE-DEGRADED-MODE.md`](../ARCHITECTURE-DEGRADED-MODE.md) for full degraded mode specification.

---

## Verification & Pentest History
* **Last Verified Date**: `2026-08-06`
* **Verification Method**: Manual live `curl` pentest + Automated Go Integration Test (`TestGetSPMetadataHandler`).
