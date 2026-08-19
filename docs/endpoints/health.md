# Endpoint Specification: `GET /v1/health`

## Overview
* **Route**: `GET /v1/health`
* **HTTP Method**: `GET` (also supports `HEAD`)
* **Purpose**: Engine Liveness Probe. Returns current operational liveness status and engine system timestamp to indicate the server process is responsive and receiving traffic.

---

## Authentication & Access Control
* **Authentication Required**: `None` (Public / Unauthenticated)
* **Security Headers Required**: None. Any passed `Authorization`, `X-Authn-Publishable-Key`, or `X-Authn-Secret-Key` headers are safely ignored.

---

## Request Parameters
* **Headers**: None
* **Query Parameters**: None
* **Request Body**: None

---

## Responses & Status Codes

### `200 OK` — Engine Alive
Returned when the engine process is active and functioning properly.

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-08-05T18:11:31Z"
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
* **Exempt from Rate Limiting**: `GET /v1/health` is registered at top-level `app.Get("/v1/health")` before rate-limiting middleware to allow Kubernetes / Cloud Load Balancer liveness probes to execute un-throttled.

---

## Design Notes & Limitations
* **Liveness Probe Only**: By deliberate architectural design, `/v1/health` does **NOT** ping database connections or cache drivers. This ensures database outages do not trigger destructive container restart loops (Liveness/Readiness separation).
* **For Dependency Readiness**: Use `GET /v1/ready` to check database and Redis connectivity.

---

## Verification & Pentest History
* **Last Verified Date**: `2026-08-05`
* **Verification Method**: Manual live HTTP pentest + Automated Go Integration Test (`TestHealthCheckLiveness`).
