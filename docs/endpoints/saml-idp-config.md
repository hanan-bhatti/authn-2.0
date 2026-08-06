# SAML 2.0 IdP Configuration CRUD (`/v1/tenant/organizations/:orgId/saml`)

> **Last Verified**: `2026-08-06` — 100% verified via live `curl` pentest suite against running server.

## Overview
The SAML 2.0 IdP Configuration API allows tenant administrators to configure, inspect, patch, and delete SAML Single Sign-On (SSO) settings for B2B organizations.

---

## Authorization & Security Controls
* **Authentication**: Requires Secret Key (`Authorization: Bearer sk_...` or `X-Authn-Secret-Key`) or console admin JWT. Unauthenticated requests are rejected with `401 Unauthorized`.
* **Org Scoping**: Configuration is strictly tied to `organization_id`.
* **Metadata Cache Invalidation**: Deleting a SAML configuration immediately invalidates public Service Provider metadata, causing `GET /v1/saml/metadata/:orgId` to return `404 Not Found` rather than serving stale metadata.

---

## Endpoint Specifications

### 1. Create SAML IdP Configuration (`POST /v1/tenant/organizations/:orgId/saml`)
* **Request**:
```json
{
  "idp_entity_id": "https://idp.acme.com/saml",
  "idp_sso_url": "https://idp.acme.com/sso",
  "idp_certificate": "-----BEGIN CERTIFICATE-----\nMIIE...\n-----END CERTIFICATE-----",
  "allowed_domains": ["acme.com"],
  "enforce_sso": true
}
```
* **Response (`201 Created`)**:
```json
{
  "id": "saml_1307e93e-aa1",
  "organization_id": "org_aac11dae-f5c",
  "idp_entity_id": "https://idp.acme.com/saml",
  "idp_sso_url": "https://idp.acme.com/sso",
  "allowed_domains": ["acme.com"],
  "enforce_sso": true,
  "created_at": "2026-08-06T06:41:59Z"
}
```

### 2. Get SAML IdP Configuration (`GET /v1/tenant/organizations/:orgId/saml`)
* **Headers**: `X-Authn-Secret-Key: sk_test_...`
* **Response (`200 OK`)**: Returns full SAML connection record.

### 3. Update SAML IdP Configuration (`PATCH /v1/tenant/organizations/:orgId/saml`)
* **Request**:
```json
{
  "enforce_sso": false
}
```
* **Response (`200 OK`)**: Returns updated SAML connection record.

### 4. Delete SAML IdP Configuration (`DELETE /v1/tenant/organizations/:orgId/saml`)
* **Headers**: `X-Authn-Secret-Key: sk_test_...`
* **Response (`200 OK`)**:
```json
{
  "message": "SAML connection deleted successfully",
  "org_id": "org_aac11dae-f5c"
}
```

### 5. Service Provider XML Metadata (`GET /v1/saml/metadata/:orgId`)
* **Response (`200 OK` - Active Config)**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="https://authn.com/saml/sp/org_aac11dae-f5c" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8080/v1/saml/acs" index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>
```
* **Response (`404 Not Found` - Deleted / Missing Config)**:
```json
{
  "error": "SAML connection configuration not found for organization"
}
```
