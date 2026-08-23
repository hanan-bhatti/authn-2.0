/**
 * Authn Platform — Auth page shell
 * File: apps/web-account/src/components/AuthShell.tsx
 *
 * The chrome every credential page shares: one centred card on the true-black
 * canvas, with the tenant's identity above it and its legal links below.
 *
 * A server component on purpose. Only the form inside a credential page needs
 * interactivity, and marking the shell client would pull the whole page — card,
 * headings, footer links — across the boundary with it.
 */

import type { CSSProperties, ReactNode } from "react";

export interface AuthShellProps {
  /** Product or tenant name, set above the card. */
  brand: ReactNode;
  title: string;
  subtitle?: ReactNode;
  /** Rendered under the card, outside its border: "Already have an account?" */
  footer?: ReactNode;
  /** Legal and support links, from the tenant's branding. */
  links?: ReactNode;
  children: ReactNode;
}

export function AuthShell({
  brand,
  title,
  subtitle,
  footer,
  links,
  children,
}: AuthShellProps): ReactNode {
  return (
    // A single atmospheric wash anchored at the top edge, which is the system's
    // one permitted use of an accent as a surface.
    <div
      className="glow-section min-h-dvh"
      style={{ "--glow": "var(--color-accent-blue-glow)" } as CSSProperties}
    >
      <main className="mx-auto flex min-h-dvh w-full max-w-panel flex-col justify-center gap-xl px-lg py-xxxl">
        <div className="flex flex-col gap-xs">
          <span className="font-mono text-caption tracking-wide text-mute uppercase">{brand}</span>
          <h1 className="font-display text-heading-md text-ink">{title}</h1>
          {subtitle && <p className="text-body-sm text-charcoal">{subtitle}</p>}
        </div>

        {/* The card sits at lg where its controls sit at md; the step between the
            two radii is what makes the form read as nested rather than as one slab. */}
        <div className="rounded-lg border border-hairline-strong bg-surface-card p-xl">
          {children}
        </div>

        {footer && <p className="text-center text-caption text-mute">{footer}</p>}

        {links && (
          <div className="flex flex-wrap items-center justify-center gap-md text-caption text-ash">
            {links}
          </div>
        )}
      </main>
    </div>
  );
}
