"use client";

import { useEffect, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@authn/react";
import { Skeleton } from "@authn/ui";

/**
 * Authn Platform — Account section guard
 * File: apps/web-account/src/components/RequireSession.tsx
 *
 * Holds the account pages back until there is a session, and sends a signed-out
 * visitor to sign-in with the page they wanted attached.
 *
 * A client guard and not middleware, deliberately. The session lives in an
 * HttpOnly refresh cookie scoped to the engine's origin, and in development the
 * engine is a different origin from this app — so a Next middleware running on
 * this app's server has no cookie to read and could only ever guess. The check
 * that means anything is the one the provider already performs on mount: a
 * refresh call to the engine, which either returns a session or does not.
 *
 * None of this is the security boundary. Every account page reads its data from
 * the engine over an authenticated request, and the engine answers 401 to a caller
 * without a session whatever this component decides. What the guard buys is that a
 * signed-out visitor gets the sign-in page instead of seven cards that each fail
 * to load.
 */

export interface RequireSessionProps {
  children: ReactNode;
}

export function RequireSession({ children }: RequireSessionProps): ReactNode {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (isLoading || isAuthenticated) return;

    /**
     * `replace`, not `push`. The account page was never usable, so leaving it in
     * history means the back button from sign-in returns to a redirect that fires
     * again — the reader presses back and lands where they already were.
     */
    router.replace(`/sign-in?next=${encodeURIComponent(pathname)}`);
  }, [isAuthenticated, isLoading, pathname, router]);

  if (isLoading) return <SessionProbeSkeleton />;

  /**
   * Rendered as nothing while the redirect is in flight. `router.replace` is not
   * synchronous, so there is a frame or two between deciding to leave and
   * leaving, and rendering the children into it would fire every page's requests
   * knowing they will 401.
   */
  if (!isAuthenticated) return null;

  return children;
}

function SessionProbeSkeleton(): ReactNode {
  return (
    <div className="flex flex-col">
      <span role="status" className="sr-only">
        Checking your session.
      </span>

      {/* Shaped like `PageHeader` and one card below it, so the layout does not
          jump when the real page arrives. Hidden from the accessibility tree —
          there is nothing in these bars to read, and the one thing worth saying
          is said once above. */}
      <div aria-hidden="true" className="border-b border-hairline-strong">
        <div className="mx-auto flex max-w-page flex-col gap-sm px-lg py-xxl sm:px-xl">
          <Skeleton variant="text" className="h-3 w-24" />
          <Skeleton variant="text" className="h-9 w-64 rounded-md" />
          <Skeleton variant="text" className="w-full max-w-broad" />
        </div>
      </div>

      <div aria-hidden="true" className="mx-auto w-full max-w-page px-lg py-xl sm:px-xl">
        <Skeleton variant="card" className="h-48" />
      </div>
    </div>
  );
}
