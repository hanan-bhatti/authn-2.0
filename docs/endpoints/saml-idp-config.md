# SAML 2.0 IdP Configuration CRUD (`/v1/tenant/organizations/:orgId/saml`)

> **Last Verified**: `2026-08-06` — 100% verified via live `curl` pentest suite against running server.

## Overview
The SAML 2.0 IdP Configuration API allows tenant administrators to configure, inspect, patch, and delete SAML Single Sign-On (SSO) settings for B2B organizations.

---

## Authorization & Security Controls
* **Authentication**: Requires Secret Key (`Authorization: Bearer sk_...` or `X-Authn-Secret-Key`) or console admin JWT. Unauthenticated requests are rejected with `401 Unauthorized`.
* **Org Scoping**: Configuration is strictly tied to `organization_id`.
* **Live Connections Are Live Configuration**: writing a connection that sits in `live`, or moving one into it, requires the live key. See [Environment](#environment) below for the full rule and the reason it is one-directional.
* **Metadata Cache Invalidation**: Deleting a SAML configuration immediately invalidates public Service Provider metadata, causing `GET /v1/saml/metadata/:orgId` to return `404 Not Found` rather than serving stale metadata.

---

## Environment

An organization has at most one SAML connection, and the connection carries an `environment` of `test` or `live`. It decides which environment the people arriving through the identity provider are provisioned into: a `test` connection mints sandbox accounts, a `live` one mints real ones.

`environment` defaults to **`live`** when omitted, which is the opposite of every other environment default in the engine. A connection only exists once an administrator has pasted a real identity provider's certificate and SSO URL, so the people arriving through it are that organization's actual employees.

Unlike the tenant settings endpoints, this field is supplied in the request body rather than inferred from the secret key. An organization has one connection, so the same record has to be able to move from a trial into production; a key that could only address its own environment could never promote one.

**A live connection takes a live key.** The field being a request field does not make the environment a free choice: creating, changing or deleting a connection that sits in `live` — or moving one into it — requires `sk_live_`, and a `sk_test_` key attempting any of them is answered `403 Forbidden` with code `live_key_required`. Because the default is `live`, naming nothing is the same request as naming `live`. The rule is one-directional: a live key may still edit a connection sitting in `test`, which is what a promotion has to read before it writes. Reads are ungated in both directions.

**Trialling a provider.** Create the connection with `"environment": "test"`, run a few sign-ins, and confirm the assertions map to the people you expect. Then `PATCH` it to `"live"` **with the live key**. From that point every sign-in is provisioned into live.

The promotion changes where subsequent sign-ins land and does **not** migrate the accounts already created. An employee who signed in during the trial keeps their test account and is given a separate live one on their next sign-in — a sandbox account is not a real one, and test data is subject to the test-environment retention rules.

Both the connection's environment and any change to it are recorded in the audit trail (`saml.connection_created`, `saml.connection_updated`), because promoting a connection is the edit that decides whether an identity provider starts minting real accounts.

---

## Endpoint Specifications

### 1. Create SAML IdP Configuration (`POST /v1/tenant/organizations/:orgId/saml`)
* **Headers**: `X-Authn-Secret-Key: sk_live_...` — required for the `"environment": "live"` body below, and for a body that omits `environment`. `sk_test_...` is accepted only for `"environment": "test"`.
* **Request**:
```json
{
  "idp_entity_id": "https://idp.acme.com/saml",
  "idp_sso_url": "https://idp.acme.com/sso",
  "idp_certificate": "-----BEGIN CERTIFICATE-----\nMIIE...\n-----END CERTIFICATE-----",
  "allowed_domains": ["acme.com"],
  "enforce_sso": true,
  "environment": "live"
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
  "environment": "live",
  "created_at": "2026-08-06T06:41:59Z"
}
```
* **Response (`400 Bad Request` — unrecognised environment)**:
```json
{
  "error": "environment must be \"test\" or \"live\""
}
```
* **Response (`403 Forbidden` — a test key filing a live connection, or omitting `environment`)**:
```json
{
  "error": "a live SAML connection can only be created, changed or deleted with a live key",
  "code": "live_key_required"
}
```

### 2. Get SAML IdP Configuration (`GET /v1/tenant/organizations/:orgId/saml`)
* **Headers**: `X-Authn-Secret-Key: sk_test_...`
* **Response (`200 OK`)**: Returns full SAML connection record, including `environment`.

### 3. Update SAML IdP Configuration (`PATCH /v1/tenant/organizations/:orgId/saml`)
* **Headers**: `X-Authn-Secret-Key: sk_live_...` when the stored connection is in `live`, or when the patch moves it there. Editing a connection that stays in `test` accepts either key.
* **Request** — omitted fields keep their stored values:
```json
{
  "enforce_sso": false
}
```
* **Request** — promoting a trialled connection:
```json
{
  "environment": "live"
}
```
* **Response (`200 OK`)**: Returns updated SAML connection record.
* **Response (`403 Forbidden`)**: `live_key_required` — a `sk_test_` key patching a live connection, or promoting a test one. Both are refused before any field is written.

### 4. Delete SAML IdP Configuration (`DELETE /v1/tenant/organizations/:orgId/saml`)
* **Headers**: `X-Authn-Secret-Key: sk_live_...` when the stored connection is in `live`; `sk_test_...` suffices for a test connection.
* **Response (`200 OK`)**:
```json
{
  "message": "SAML connection deleted successfully",
  "org_id": "org_aac11dae-f5c"
}
```
* **Response (`403 Forbidden`)**: `live_key_required` — deleting a live connection locks every employee out of the organization, so it is the same live act as configuring one.

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
