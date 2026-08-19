# Endpoint Specification: `GET /v1/ready`

## Overview
* **Route**: `GET /v1/ready`
* **HTTP Method**: `GET` (also supports `HEAD`)
* **Purpose**: Engine Readiness Probe. Validates connectivity to critical infrastructure dependencies (PostgreSQL/SQLite Database and Redis Cache) with a strict 2-second timeout per check.

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

### `200 OK` — All Dependencies Ready
Returned when both Database and Redis connectivity checks pass within the 2-second timeout window.

```json
{
  "status": "ready",
  "checks": {
    "database": "ok",
    "redis": "ok"
  }
}
```

### `503 Service Unavailable` — Dependency Outage / Not Ready
Returned when Database or Redis fails connectivity ping or times out after 2 seconds. Exposes specific broken dependency state without leaking internal stack traces or connection strings.

```json
{
  "status": "not_ready",
  "checks": {
    "database": "ok",
    "redis": "down"
  }
}
```

```json
{
  "status": "not_ready",
  "checks": {
    "database": "down",
    "redis": "down"
  }
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
* **Exempt from Rate Limiting**: `GET /v1/ready` is registered at top-level `app.Get("/v1/ready")` before rate-limiting middleware to allow infrastructure orchestrator probes to execute un-throttled.

---

## Design Notes & Limitations
* **2-Second Timeout Safety**: Each dependency check is bound by `context.WithTimeout(ctx, 2*time.Second)`. If a database or Redis connection hangs, the probe immediately cancels and returns `503 Service Unavailable` rather than hanging the caller.
* **Separation from Liveness**: Dependency outages returned by `/v1/ready` notify load balancers to route traffic away from the node without causing container restarts (which are managed separately by `GET /v1/health`).

---

## Verification & Pentest History
* **Last Verified Date**: `2026-08-05`
* **Verification Method**: Manual live HTTP pentest + Automated Go Integration Test (`TestReadinessProbeSuccessAndFailure`).
