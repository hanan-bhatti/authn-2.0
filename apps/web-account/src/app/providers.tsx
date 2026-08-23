"use client";

/**
 * Authn Platform — Account app providers
 * File: apps/web-account/src/app/providers.tsx
 *
 * The provider tree is its own client component so the root layout can stay a
 * server component. A layout marked "use client" would opt every page beneath it
 * out of server rendering.
 */

import type { ReactNode } from "react";
import { AuthnProvider } from "@authn/react";
import { env } from "@/lib/env";

export function Providers({ children }: { children: ReactNode }): ReactNode {
  return (
    <AuthnProvider publishableKey={env.publishableKey} endpoint={env.apiUrl}>
      {children}
    </AuthnProvider>
  );
}
