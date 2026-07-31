# SDK Specification (`@authn/js` & `@authn/react`)

**Document Version**: 1.0.0  
**Date**: 2026-08-01  
**Status**: Approved Specification (Execution Ready)  
**Author**: Authn Core Team  

---

## 1. Core JavaScript SDK (`@authn/js`)

The `@authn/js` package is a framework-agnostic, zero-dependency client library for Web and Node.js/Native environments.

### 1.1 TypeScript Interfaces (`packages/sdk-js/src/types.ts`)
```typescript
export interface AuthnConfig {
  publishableKey: string;        // "pk_test_..." or "pk_live_..."
  baseUrl?: string;               // Default: "https://api.authn.com"
  clientType?: "web" | "native"; // Default: "web"
  autoRefresh?: boolean;         // Default: true (silent background token refresh)
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
  /**
   * refreshToken is returned in JSON for native mobile clients (Android/iOS).
   * For web clients, refreshToken is managed automatically via HttpOnly SameSite cookies.
   */
  refreshToken?: string;
  expiresAt: number;
  user: User;
}

export interface AuthResponse {
  session?: Session;
  requires2FA?: boolean;
  twoFactorToken?: string;
  matchNumber?: number;
  error?: string;
}

export type AuthStateCallback = (user: User | null, session: Session | null) => void;
```

---

### 1.2 Initialization & Automatic Headers
```typescript
import { AuthnClient } from "@authn/js";

export const authn = new AuthnClient({
  publishableKey: process.env.NEXT_PUBLIC_AUTHN_CLIENT_KEY!,
  baseUrl: "https://api.authn.com",
  clientType: "web",
  autoRefresh: true
});
```

* **Automatic Headers**: `AuthnClient` automatically appends `X-Authn-Publishable-Key` and `X-Authn-Client-Type: web|native` on all outgoing HTTP requests.
* **Credentials Policy**: All fetch calls use `credentials: "include"` so web browsers attach `HttpOnly` refresh cookies automatically.

---

### 1.3 Silent Background Refresh & State Listener

#### Automatic Token Refresh
When `autoRefresh: true` (default), `AuthnClient` schedules an internal timer 60 seconds before `expiresAt`. It calls `POST /oauth/token` with `grant_type=refresh_token` and `credentials: "include"`, renewing the `accessToken` and rotating the `HttpOnly` refresh cookie without user interaction.

#### Manual Session Refresh & State Listener
```typescript
// 1. Explicit manual session renewal
const session = await authn.refreshSession();

// 2. Subscribe to auth state changes (used internally by @authn/react hooks)
const unsubscribe = authn.onAuthStateChanged((user, session) => {
  console.log("Current user:", user);
});

// Unsubscribe when component unmounts
unsubscribe();
```

---

### 1.4 Authentication Methods

```typescript
// 1. Password Login
const { session, requires2FA, twoFactorToken, matchNumber, error } = await authn.signInWithPassword({
  email: "user@example.com",
  password: "Password123!"
});

// 2A. Direct TOTP / Passkey 2FA Verification
const { session } = await authn.verify2FA({
  twoFactorToken,
  method: "totp",
  code: "482910"
});

// 2B. Real-Time Push 2FA Verification (Abstracts WebSocket & Exchange Route)
// Displays matchNumber on screen, opens WebSocket to /v1/client/ws/2fa, 
// waits for phone approval broadcast, and exchanges exchangeToken for session.
const session = await authn.waitForPushApproval(twoFactorToken);

// 3. Social Auth Login (Redirects with 32-byte state CSRF protection)
authn.signInWithProvider("google", {
  redirectUri: "https://myapp.com/callback" // Optional override
});

// 4. Sign Out & Clear Session
await authn.signOut();
```

---

## 2. React SDK (`@authn/react`)

The `@authn/react` package provides idiomatic React 19 hooks and pre-built UI components.

### 2.1 Provider Setup
```tsx
import { AuthnProvider } from "@authn/react";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthnProvider publishableKey={process.env.NEXT_PUBLIC_AUTHN_CLIENT_KEY!}>
      {children}
    </AuthnProvider>
  );
}
```

### 2.2 React Hooks (`useAuthn` & `useUser`)
```tsx
import { useAuthn, useUser, SignInButton, UserButton } from "@authn/react";

export function Header() {
  const { isSignedIn, isLoading, signOut } = useAuthn();
  const { user } = useUser();

  if (isLoading) return <div>Loading...</div>;

  return (
    <header>
      {isSignedIn ? (
        <div>
          <span>Welcome, {user?.name}</span>
          <UserButton />
        </div>
      ) : (
        <SignInButton />
      )}
    </header>
  );
}
```
