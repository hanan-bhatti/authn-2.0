/**
 * Authn Platform — The panel an emailed-link landing renders
 * File: apps/web-account/src/components/LinkStatusPanel.tsx
 *
 * Every state of both landings looks the same: a heading, some prose, and
 * sometimes one button. What is worth sharing is not that layout but the live
 * region above it.
 */

import type { ReactNode } from "react";

export interface LinkStatusPanelProps {
  /**
   * What a screen reader should hear when the page moves on.
   *
   * These pages advance without being touched — they redeem a token on mount and
   * then rewrite themselves — so nothing about the change is announced by
   * default. The user with the screen reader is the one who cannot see the
   * heading swap.
   */
  announcement: string;
  title: string;
  children?: ReactNode;
}

export function LinkStatusPanel({
  announcement,
  title,
  children,
}: LinkStatusPanelProps): ReactNode {
  return (
    <div className="flex flex-col gap-md">
      {/*
        Mounted for every state, with only its text changing. A live region added
        to the page at the same moment as its message is frequently not announced
        at all: assistive technology watches an existing region for changes, and a
        region that arrives already full has nothing to compare against.
      */}
      <span role="status" aria-live="polite" className="sr-only">
        {announcement}
      </span>

      <h2 className="font-display text-heading-sm text-ink">{title}</h2>
      {children}
    </div>
  );
}
