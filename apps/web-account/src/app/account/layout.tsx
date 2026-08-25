import type { ReactNode } from "react";
import { AccountShell } from "@/components/AccountShell";
import { RequireSession } from "@/components/RequireSession";

/**
 * Authn Platform — Account section layout
 * File: apps/web-account/src/app/account/layout.tsx
 *
 * Wraps every account page in the two-column shell. A layout rather than a
 * component each page imports: Next keeps a layout mounted across navigations
 * within its segment, so the sidebar's expansion state and scroll position survive
 * moving between pages. Wrapping per page would remount the tree on every click
 * and snap a manually opened branch shut.
 *
 * The guard sits inside the shell rather than around it, so the sidebar and the
 * navigation are painted while the session is still being established. Outside it,
 * the whole frame would appear only once the probe returned, which on a slow
 * connection is a blank screen where there is enough to show.
 */

export default function AccountLayout({ children }: { children: ReactNode }): ReactNode {
  return (
    <AccountShell>
      <RequireSession>{children}</RequireSession>
    </AccountShell>
  );
}
