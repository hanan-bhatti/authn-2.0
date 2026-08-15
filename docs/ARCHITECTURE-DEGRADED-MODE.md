# Architecture Specification: Degraded Mode & Outage Resilience

## Executive Overview

The **Authn Engine** implements a dual-tier outage resilience strategy to ensure high availability during cache infrastructure failures (e.g. Redis downtime, network partitioning, or cluster restarts).

During a Redis outage, the engine injects the HTTP response header `X-Authn-Degraded-Mode: true` into every HTTP response. This signals client SDKs and API gateways to adapt their behavior while maintaining system security boundaries.

---

## 1. Detection Architecture (`DegradedModeTracker`)

### Background Ticker vs. Per-Request RTT Decision

| Architecture Option | Per-Request Overhead | Detection Speed | Decision |
| :--- | :--- | :--- | :--- |
| **Live Per-Request Ping** | $+1.5\text{ms}$ to $+3.0\text{ms}$ RTT latency per HTTP request | Immediate | ❌ Rejected (Degrades application throughput) |
| **Background Ticker + Atomic Flag** | **$0.00\text{ms}$** (Atomic memory read) | $\le 1.0\text{s}$ | ✅ **Adopted** (High throughput, zero latency overhead) |

### Implementation Details (`apps/auth-engine/internal/middleware/degraded_mode.go`)
* **Background Health Tracker**: `DegradedModeTracker` runs a background goroutine that executes `redisClient.Ping(ctx)` every 1 second with a 500ms timeout context.
* **Atomic Flag (`isDegraded`)**: Stores the health state as an `int32` atomic value (`0` = Healthy, `1` = Degraded).
* **Zero Restart Recovery**: The tracker retains the underlying `redisClient` handle. When Redis recovers, the tracker automatically detects connectivity and flips `isDegraded` back to `0` (`false`) within 1 second **without requiring a server process restart**.

---

## 2. Endpoint Failure Classifications (Fail-Open vs. Fail-Closed)

Not all endpoints react identically to Redis cache outages. The platform strictly segregates endpoints into two security tiers:

```
                          ┌───────────────────────────┐
                          │    Redis Cache Outage     │
                          └─────────────┬─────────────┘
                                        │
             ┌──────────────────────────┴──────────────────────────┐
             ▼                                                     ▼
┌──────────────────────────┐                             ┌──────────────────────────┐
│  Stateless Read Tier     │                             │  Sensitive Mutation Tier │
│  (FAIL-OPEN)             │                             │  (FAIL-CLOSED)           │
├──────────────────────────┤                             ├──────────────────────────┤
│ • GET /v1/health         │                             │ • POST /v1/client/auth/login  │
│ • GET /v1/ready          │                             │ • POST /v1/client/auth/signup │
│ • GET /.well-known/...   │                             │ • POST /v1/client/auth/* │
│ • GET /v1/oauth/jwks     │                             │ • POST /v1/client/auth/2fa/*  │
│ • GET /v1/saml/metadata  │                             │ • POST /v1/recovery/*    │
├──────────────────────────┤                             ├──────────────────────────┤
│ Returns 200 OK +         │                             │ Returns 503 Service      │
│ X-Authn-Degraded-Mode:   │                             │ Unavailable              │
│ true                     │                             │                          │
└──────────────────────────┘                             └──────────────────────────┘
```

### A. Fail-OPEN Endpoints (Stateless Read Tier)
* **Definition**: Public metadata, health probes, JWKS keys, and stateless read operations that execute local in-memory cryptographic verification or direct database queries.
* **Behavior**: Continue operating normally with `200 OK` while appending `X-Authn-Degraded-Mode: true`.
* **Endpoints**:
  * `GET /v1/health`
  * `GET /v1/ready`
  * `GET /.well-known/openid-configuration`
  * `GET /v1/oauth/jwks`
  * `GET /v1/saml/metadata/:orgId`
  * `GET /v1/client/user/permissions`

### B. Fail-CLOSED Endpoints (Sensitive Mutation & Auth Tier)
* **Definition**: Security-critical authentication, registration, token exchange, and credential mutation endpoints that rely on Redis sliding-window rate limiting to prevent brute-force credential stuffing and password guessing.
* **Behavior**: Strictly **REJECT** incoming requests with `503 Service Unavailable` (`{"error": "rate limit service unavailable"}`) and `X-Authn-Degraded-Mode: true`.
* **Endpoints**:
  * `POST /v1/client/auth/login`
  * `POST /v1/client/auth/signup`
  * `POST /v1/client/auth/refresh`
  * `POST /v1/client/auth/recovery/*`
  * `POST /v1/client/auth/2fa/*`

---

## 3. Canonical Empirical Verification Evidence

The following live `curl` outputs serve as the canonical empirical proof of degraded mode behavior:

### Test Case 1: Baseline Health (Redis UP)
```bash
$ curl -i http://localhost:8080/v1/saml/metadata/org_00000000000000000000000000000001

HTTP/1.1 200 OK
Content-Type: application/xml
X-Authn-Degraded-Mode: false
Cache-Control: public, max-age=3600
```

### Test Case 2: Outage Trigger (`docker stop authn-redis`) — Fail-OPEN Read
```bash
$ curl -i http://localhost:8080/v1/oauth/jwks

HTTP/1.1 200 OK
Content-Type: application/json
X-Authn-Degraded-Mode: true

{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"key_v1", ...}]}
```

### Test Case 3: Outage Trigger (`docker stop authn-redis`) — Fail-CLOSED Auth Guard
```bash
$ curl -i -X POST \
  -H "Content-Type: application/json" \
  -H "X-Authn-Publishable-Key: pk_test_demo12345678901234567890123456789012" \
  -d '{"email":"user.vanilla@authn.local","password":"UserPass123!"}' \
  http://localhost:8080/v1/client/auth/login

HTTP/1.1 503 Service Unavailable
Content-Type: application/json
X-Authn-Degraded-Mode: true

{"error":"rate limit service unavailable"}
```

### Test Case 4: Automatic Recovery (`docker start authn-redis`)
```bash
$ curl -i http://localhost:8080/v1/saml/metadata/org_00000000000000000000000000000001

HTTP/1.1 200 OK
Content-Type: application/xml
X-Authn-Degraded-Mode: false
Cache-Control: public, max-age=3600
```
