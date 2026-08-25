"use client";

/**
 * Authn Platform — Landing actions
 * File: apps/web-account/src/app/HomeActions.tsx
 */

import type { ReactNode } from "react";
import Link from "next/link";
import { buttonClassName, Skeleton } from "@authn/ui";
import { useAuth } from "@authn/react";

/**
 * The pair of actions the landing offers, which depends on whether anyone is
 * signed in.
 *
 * Split out from the page so the heading and copy stay on the server: only this
 * part needs the session.
 *
 * Both actions are anchors wearing button classes rather than buttons calling the
 * router. A button loses middle-click, cmd-click and "copy link address", and on
 * a page whose entire purpose is to send you somewhere else that is the wrong
 * trade.
 */
export function HomeActions(): ReactNode {
  const { isAuthenticated, isLoading, user } = useAuth();

  // The provider opens by probing the refresh cookie, so the first paint does not
  // yet know which pair of actions is right. Showing one and swapping it is worse
  // than showing neither for a moment: the visitor reaches for "Sign in" and it
  // becomes something else under the cursor.
  if (isLoading) {
    return (
      <div className="flex flex-col gap-md">
        <span role="status" className="sr-only">
          Checking whether you are already signed in.
        </span>
        <div aria-hidden="true" className="flex gap-md">
          <Skeleton variant="control" className="w-32" />
          <Skeleton variant="control" className="w-40" />
        </div>
      </div>
    );
  }

  if (isAuthenticated) {
    return (
      <div className="flex flex-col gap-md">
        <div className="flex flex-wrap gap-md">
          <Link href="/account" className={buttonClassName({ variant: "primary" })}>
            Go to your account
          </Link>
        </div>
        <p className="text-caption text-mute">
          Signed in as <span className="font-mono text-charcoal">{user?.email ?? user?.username}</span>
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-wrap gap-md">
      <Link href="/sign-in" className={buttonClassName({ variant: "primary" })}>
        Sign in
      </Link>
      <Link href="/sign-up" className={buttonClassName({ variant: "secondary" })}>
        Create account
      </Link>
    </div>
  );
}
