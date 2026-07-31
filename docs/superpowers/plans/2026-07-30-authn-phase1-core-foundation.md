# Authn Phase 1 Core Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the complete monorepo skeleton (`pnpm` + `Turborepo`), shared React UI and SDK packages, the Go backend auth engine (`apps/auth-engine`) with Ent ORM schema, SHA-256 refresh token rotation, OIDC PKCE server, pluggable social identity drivers, number-matching push 2FA, and the Next.js developer console (`apps/web-console`).

**Architecture:** Monorepo architecture using `pnpm` workspaces and `Turborepo`. High-performance Go 1.22 backend utilizing `Ent` ORM with multi-database drivers (PostgreSQL, MySQL, SQLite) and Redis/Dragonfly caching for session management and OIDC key rotation.

**Tech Stack:** Go 1.22, Ent ORM (`entgo.io`), Fiber, Redis, Turborepo, Next.js 15, React 19, TypeScript, TailwindCSS v4, shadcn/ui, pnpm.

## Global Constraints

- Backend Language: Go 1.22+
- Database ORM: Ent ORM (`entgo.io`)
- Frontend Framework: Next.js 15 (App Router) + React 19 + TypeScript
- Styling: TailwindCSS + shadcn/ui
- Monorepo Manager: pnpm workspaces + Turborepo
- Redirect URI Security: Exact string matching only (no wildcards)
- Refresh Token Security: SHA-256 hash storage in DB with token rotation and 10s grace window

---

### Task 1: Monorepo Workspace & Turborepo Scaffolding

**Files:**
- Create: `pnpm-workspace.yaml`
- Create: `turbo.json`
- Create: `package.json`
- Create: `.gitignore`
- Create: `packages/config-typescript/tsconfig.base.json`
- Create: `packages/config-eslint/index.js`

**Interfaces:**
- Consumes: N/A (Initial task)
- Produces: Monorepo workspace configuration supporting `apps/*` and `packages/*`

- [ ] **Step 1: Create `pnpm-workspace.yaml`**

```yaml
packages:
  - 'apps/*'
  - 'packages/*'
```

- [ ] **Step 2: Create root `package.json`**

```json
{
  "name": "authn-monorepo",
  "private": true,
  "scripts": {
    "build": "turbo run build",
    "dev": "turbo run dev",
    "lint": "turbo run lint",
    "test": "turbo run test"
  },
  "devDependencies": {
    "turbo": "^2.0.0",
    "typescript": "^5.4.0"
  },
  "packageManager": "pnpm@9.0.0"
}
```

- [ ] **Step 3: Create `turbo.json`**

```json
{
  "$schema": "https://turbo.build/schema.json",
  "pipeline": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": [".next/**", "dist/**"]
    },
    "lint": {},
    "dev": {
      "cache": false,
      "persistent": true
    },
    "test": {
      "dependsOn": ["^build"]
    }
  }
}
```

- [ ] **Step 4: Create `.gitignore`**

```gitignore
node_modules
.next
dist
.turbo
*.log
.env
.env.local
coverage
```

- [ ] **Step 5: Create shared TypeScript configuration `packages/config-typescript/tsconfig.base.json`**

```json
{
  "$schema": "https://json.schemastore.org/tsconfig",
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "jsx": "react-jsx"
  }
}
```

- [ ] **Step 6: Commit Monorepo Scaffolding**

```bash
git add pnpm-workspace.yaml turbo.json package.json .gitignore packages/
git commit -m "feat: initialize monorepo workspace and Turborepo configuration"
```

---

### Task 2: Shared UI Design System Package (`packages/ui`)

**Files:**
- Create: `packages/ui/package.json`
- Create: `packages/ui/tsconfig.json`
- Create: `packages/ui/src/button.tsx`
- Create: `packages/ui/src/card.tsx`
- Create: `packages/ui/src/index.ts`

**Interfaces:**
- Consumes: TailwindCSS, React 19
- Produces: `@authn/ui` exportable React components for Web Console, Landing, Docs, Demo, and Hosted Auth UI

- [ ] **Step 1: Create `packages/ui/package.json`**

```json
{
  "name": "@authn/ui",
  "version": "0.1.0",
  "private": true,
  "main": "./src/index.ts",
  "types": "./src/index.ts",
  "scripts": {
    "lint": "eslint ."
  },
  "dependencies": {
    "clsx": "^2.1.0",
    "tailwind-merge": "^2.2.0"
  },
  "peerDependencies": {
    "react": "^19.0.0",
    "react-dom": "^19.0.0"
  }
}
```

- [ ] **Step 2: Create `packages/ui/src/button.tsx`**

```tsx
import * as React from "react";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "outline" | "ghost";
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "primary", ...props }, ref) => {
    const baseStyles = "inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:opacity-50 disabled:pointer-events-none px-4 py-2";
    const variants = {
      primary: "bg-indigo-600 text-white hover:bg-indigo-700 focus-visible:ring-indigo-500",
      secondary: "bg-slate-800 text-white hover:bg-slate-700 focus-visible:ring-slate-500",
      outline: "border border-slate-700 bg-transparent hover:bg-slate-800 text-slate-100",
      ghost: "hover:bg-slate-800 text-slate-200"
    };

    return (
      <button
        ref={ref}
        className={twMerge(clsx(baseStyles, variants[variant], className))}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";
```

- [ ] **Step 3: Create `packages/ui/src/index.ts`**

```ts
export * from "./button";
```

- [ ] **Step 4: Commit `@authn/ui` Package**

```bash
git add packages/ui/
git commit -m "feat: add @authn/ui shared design system package"
```

---

### Task 3: Core Client JavaScript SDK Package (`packages/sdk-js`)

**Files:**
- Create: `packages/sdk-js/package.json`
- Create: `packages/sdk-js/tsconfig.json`
- Create: `packages/sdk-js/src/client.ts`
- Create: `packages/sdk-js/src/types.ts`
- Create: `packages/sdk-js/src/index.ts`
- Create: `packages/sdk-js/tests/client.test.ts`

**Interfaces:**
- Consumes: Auth Engine HTTP REST API
- Produces: `@authn/js` SDK client for web & mobile frontends (`AuthnClient`)

- [ ] **Step 1: Create `packages/sdk-js/src/types.ts`**

```ts
export interface AuthnConfig {
  publishableKey: string;
  baseUrl?: string;
}

export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  name?: string;
  avatarUrl?: string;
}

export interface Session {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  user: User;
}

export interface AuthResponse {
  session?: Session;
  requires2FA?: boolean;
  twoFactorToken?: string;
  error?: string;
}
```

- [ ] **Step 2: Create `packages/sdk-js/src/client.ts`**

```ts
import { AuthnConfig, AuthResponse, Session } from "./types";

export class AuthnClient {
  private publishableKey: string;
  private baseUrl: string;

  constructor(config: AuthnConfig) {
    this.publishableKey = config.publishableKey;
    this.baseUrl = config.baseUrl || "https://api.authn.com";
  }

  async signInWithPassword(email: string, password: string): Promise<AuthResponse> {
    const response = await fetch(`${this.baseUrl}/v1/client/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Authn-Publishable-Key": this.publishableKey
      },
      body: JSON.stringify({ email, password })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return { error: errorData.message || "Failed to sign in" };
    }

    return response.json();
  }
}
```

- [ ] **Step 3: Commit `@authn/js` Package**

```bash
git add packages/sdk-js/
git commit -m "feat: add @authn/js client SDK library"
```

---

### Task 4: Go Backend Auth Engine Setup (`apps/auth-engine`)

**Files:**
- Create: `apps/auth-engine/go.mod`
- Create: `apps/auth-engine/main.go`
- Create: `apps/auth-engine/config/config.go`
- Test: `apps/auth-engine/main_test.go`

**Interfaces:**
- Consumes: Environment variables, Ent ORM, Fiber
- Produces: Running Go HTTP Server listening on port 8080

- [ ] **Step 1: Initialize `apps/auth-engine/go.mod`**

```bash
mkdir -p apps/auth-engine
cd apps/auth-engine
go mod init github.com/authn/authn/apps/auth-engine
```

- [ ] **Step 2: Create `apps/auth-engine/config/config.go`**

```go
package config

import "os"

type Config struct {
	Port        string
	DatabaseURL string
	RedisURL    string
	JWTSecret   string
}

func Load() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "file:authn.db?mode=memory&cache=shared&_fk=1"
	}
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	return &Config{
		Port:        port,
		DatabaseURL: dbURL,
		RedisURL:    redisURL,
		JWTSecret:   os.Getenv("JWT_SECRET"),
	}
}
```

- [ ] **Step 3: Commit Go Backend Setup**

```bash
git add apps/auth-engine/
git commit -m "feat: initialize Go auth-engine project structure and configuration loader"
```

---

### Task 5: Ent ORM Database Schemas & Privacy Interceptors

**Files:**
- Create: `apps/auth-engine/ent/schema/tenant.go`
- Create: `apps/auth-engine/ent/schema/application.go`
- Create: `apps/auth-engine/ent/schema/user.go`
- Create: `apps/auth-engine/ent/schema/session.go`
- Create: `apps/auth-engine/ent/schema/pushdevice.go`

**Interfaces:**
- Consumes: Ent Framework
- Produces: Type-safe database schemas with tenant isolation privacy rules

- [ ] **Step 1: Create `apps/auth-engine/ent/schema/user.go`**

```go
package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type User struct {
	ent.Schema
}

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").StorageKey("id").Unique(),
		field.String("tenant_id"),
		field.String("email").Unique(),
		field.String("password_hash").Optional(),
		field.Bool("email_verified").Default(false),
		field.String("name").Optional(),
		field.String("avatar_url").Optional(),
		field.Time("created_at").Default(time.Now),
		field.Time("updated_at").Default(time.Now),
	}
}

func (User) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "email").Unique(),
	}
}
```

- [ ] **Step 2: Create `apps/auth-engine/ent/schema/session.go`**

```go
package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type Session struct {
	ent.Schema
}

func (Session) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").StorageKey("id").Unique(),
		field.String("user_id"),
		field.String("refresh_token_hash").Unique(),
		field.String("ip_address").Optional(),
		field.String("user_agent").Optional(),
		field.Time("expires_at"),
		field.Time("created_at").Default(time.Now),
	}
}

func (Session) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id"),
		index.Fields("refresh_token_hash"),
	}
}
```

- [ ] **Step 3: Commit Ent Database Schemas**

```bash
git add apps/auth-engine/ent/
git commit -m "feat: add Ent database schemas for User and Session with indexes"
```

---

### Task 6: Refresh Token Hashing & Rotation Manager

**Files:**
- Create: `apps/auth-engine/services/token.go`
- Test: `apps/auth-engine/services/token_test.go`

**Interfaces:**
- Consumes: Go crypto/sha256, Ent Session store
- Produces: SHA-256 refresh token generator, validator, and rotation with 10s grace window

- [ ] **Step 1: Write failing test `apps/auth-engine/services/token_test.go`**

```go
package services

import (
	"testing"
)

func TestHashRefreshToken(t *testing.T) {
	rawToken := "raw_refresh_token_12345"
	hash1 := HashRefreshToken(rawToken)
	hash2 := HashRefreshToken(rawToken)

	if hash1 != hash2 {
		t.Errorf("Expected identical SHA-256 hashes, got %s and %s", hash1, hash2)
	}

	if len(hash1) != 64 {
		t.Errorf("Expected 64 hex characters for SHA-256 string, got len %d", len(hash1))
	}
}
```

- [ ] **Step 2: Implement `apps/auth-engine/services/token.go`**

```go
package services

import (
	"crypto/sha256"
	"encoding/hex"
)

func HashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
```

- [ ] **Step 3: Run Go tests**

```bash
cd apps/auth-engine && go test ./services/... -v
```

- [ ] **Step 4: Commit Token Manager**

```bash
git add apps/auth-engine/services/
git commit -m "feat: implement SHA-256 refresh token hashing manager and test suite"
```

---

### Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-30-authn-phase1-core-foundation.md`.
