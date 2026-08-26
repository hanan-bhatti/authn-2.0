"use client";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Avatar,
  IconButton,
  LogOutIcon,
  MenuIcon,
  Skeleton,
  Sidebar,
  useToast,
} from "@authn/ui";
import type { AuthnUser } from "@authn/js";
import { useAuth, useSignOut } from "@authn/react";
import { useOrganizations } from "@/components/OrganizationsProvider";
import { accountNav, activeNavId } from "@/lib/accountNav";

/**
 * Authn Platform — Account shell
 * File: apps/web-account/src/components/AccountShell.tsx
 *
 * The two-column frame every account page sits in: the navigation tree on the
 * left, the page on the right, and below `md` a top bar with the tree behind a
 * button.
 *
 * A client component, unlike `AuthShell`, because four things here are live: which
 * row is current, whether the drawer is open, who is signed in, and which
 * workspaces they belong to.
 */

export interface AccountShellProps {
  children: ReactNode;
}

export function AccountShell({ children }: AccountShellProps): ReactNode {
  const pathname = usePathname();
  const [isOpen, setIsOpen] = useState(false);

  const { user, isLoading } = useAuth();

  /**
   * The same list the organizations page draws its cards from, fetched once by the
   * provider around this component rather than here.
   *
   * The tree is visible from all seven pages, so it cannot wait for a visit to the
   * one page that would otherwise own the request; and it has to be the *same* list,
   * or creating a workspace fills in a card with no row beside it.
   */
  const { organizations } = useOrganizations();

  /**
   * Closed on every navigation. Without this the drawer stays open over the page
   * it just took you to — the click landed, the route changed, and the panel that
   * caused it is still covering the result.
   *
   * Keyed on the pathname rather than done in the link's own handler because a
   * route can change without a click: the back button, a redirect, a
   * `router.push` from somewhere else entirely.
   */
  useEffect(() => {
    setIsOpen(false);
  }, [pathname]);

  const sections = useMemo(() => accountNav(organizations), [organizations]);

  return (
    <div className="flex min-h-dvh flex-col md:flex-row">
      <Sidebar
        sections={sections}
        activeId={activeNavId(pathname)}
        linkAs={Link}
        isOpen={isOpen}
        onOpenChange={setIsOpen}
        header={
          <Link
            href="/account"
            className="flex items-center gap-sm px-sm font-mono text-caption tracking-wide text-mute uppercase"
          >
            Authn
          </Link>
        }
        footer={<AccountFooter user={user} isProbing={isLoading} />}
      />

      {/* Only below `md`, and sticky rather than fixed: fixed would need the content
          column padded by exactly the bar's height to compensate, which is a number
          in two places that has to agree. */}
      <header className="sticky top-0 z-40 flex h-14 shrink-0 items-center gap-md border-b border-hairline-strong bg-canvas/90 px-lg backdrop-blur-[25px] md:hidden">
        <IconButton
          size="sm"
          label="Open navigation"
          onClick={() => setIsOpen(true)}
          icon={<MenuIcon size={16} />}
        />
        <span className="font-mono text-caption tracking-wide text-mute uppercase">Authn</span>
      </header>

      {/* `min-w-0` is load-bearing. A flex child defaults to `min-width: auto`, so a
          wide table or a long unbroken token inside a page would push this column
          past the viewport and take the sidebar off-screen with it, instead of
          scrolling inside its own bounds. */}
      <div className="flex min-w-0 flex-1 flex-col">{children}</div>
    </div>
  );
}

interface AccountFooterProps {
  user: AuthnUser | null;
  /** True while the provider's session probe is still in flight. */
  isProbing: boolean;
}

/**
 * Who is signed in, and the way out.
 *
 * Declared at module scope rather than nested inside the shell. A component
 * defined during render is a new type on every render, and React unmounts and
 * remounts a subtree whose type changed — which here would discard the sign-out
 * button's own state each time the drawer opened.
 */
function AccountFooter({ user, isProbing }: AccountFooterProps): ReactNode {
  if (!user) return isProbing ? <FooterSkeleton /> : null;

  /**
   * The handle when there is one, the address otherwise. A username is the
   * shorter, more recognisable label and is what the sign-in field accepts, but it
   * is optional — and a second line repeating the name above it says nothing.
   */
  const primary = user.name ?? user.email;
  const secondary = user.username ? `@${user.username}` : user.email;

  return (
    <div className="flex items-center gap-sm px-sm">
      {/* Named rather than handed initials: `Avatar` derives them, so passing them
          in would be the same rule written in two places. */}
      <Avatar size="sm" name={primary} />
      <div className="flex min-w-0 flex-col">
        <span className="truncate text-body-sm text-ink">{primary}</span>
        <span className="truncate font-mono text-caption text-ash">{secondary}</span>
      </div>
      <SignOutButton />
    </div>
  );
}

/**
 * Sign-out, at the trailing edge of the footer.
 *
 * Visible rather than inside a menu. It is the one control in the frame a reader
 * may need in a hurry — on a machine that is not theirs — and a control you have to
 * find first is the wrong shape for that.
 */
function SignOutButton(): ReactNode {
  const { signOut, isLoading } = useSignOut();
  const router = useRouter();
  const toast = useToast();

  const handleSignOut = useCallback(async () => {
    const result = await signOut();

    /**
     * Sent to sign-in either way. A failed revocation is worth saying out loud,
     * but the local session is gone regardless — the SDK clears it whatever the
     * request returns — so leaving the reader on a page that can no longer load
     * anything would be the worse half of the outcome.
     */
    if (!result.ok) {
      toast.warning(
        "Signed out on this device only",
        "The server could not be reached, so your other sessions may still be active. Sign in again and revoke them from Sessions.",
      );
    }

    router.replace("/sign-in");
  }, [router, signOut, toast]);

  return (
    <IconButton
      size="sm"
      label="Sign out"
      className="ml-auto"
      disabled={isLoading}
      icon={<LogOutIcon size={16} />}
      onClick={() => void handleSignOut()}
    />
  );
}

function FooterSkeleton(): ReactNode {
  return (
    <div aria-hidden="true" className="flex items-center gap-sm px-sm">
      <Skeleton variant="avatar" className="size-6" />
      <div className="flex min-w-0 flex-1 flex-col gap-xxs">
        <Skeleton variant="text" className="h-3 w-24" />
        <Skeleton variant="text" className="h-2.5 w-16" />
      </div>
    </div>
  );
}
