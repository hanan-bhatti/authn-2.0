import type { ReactNode } from "react";
import { AlertIcon, Button, Skeleton } from "@authn/ui";
import { asSentence } from "@/lib/authError";

/**
 * Authn Platform — Card loading and failure states
 * File: apps/web-account/src/components/CardState.tsx
 *
 * The two things a card can be other than its contents: still loading, or unable
 * to load.
 *
 * Both are here rather than on each page because they are the states most likely
 * to be written differently seven times and noticed by the reader as inconsistency
 * — one page saying "Loading…", another showing a spinner, a third showing nothing
 * at all until the answer arrives.
 */

export interface RowSkeletonProps {
  /** How many rows the card will have. Best guess at the real count. */
  rows?: number;
  /** Matches the plaque in `SettingsRow`, for a card whose rows carry glyphs. */
  hasIcon?: boolean;
  /** What is being loaded, for the single announcement: "your profile". */
  label: string;
}

/**
 * Placeholder rows shaped like `SettingsRow`.
 *
 * The geometry is copied so the card is the same height before and after the
 * answer: `p-lg` padding, the `not-first` divider, the size-9 plaque, and a label
 * line above a value line. A generic block here would resize the card the instant
 * the data landed, and on a page of stacked cards that moves everything below it.
 */
export function RowSkeleton({ rows = 3, hasIcon = false, label }: RowSkeletonProps): ReactNode {
  return (
    <div className="flex flex-col">
      {/* One announcement for the whole card. The bars themselves are hidden from
          the accessibility tree — there is no text in them to read, and a screen
          reader that walked them would report a list of nothing. */}
      <span role="status" className="sr-only">
        Loading {label}.
      </span>

      {Array.from({ length: rows }, (_, index) => (
        <div
          key={index}
          aria-hidden="true"
          className="flex flex-wrap items-center justify-between gap-md p-lg not-first:border-t not-first:border-hairline"
        >
          <div className="flex min-w-0 flex-1 basis-[20rem] items-center gap-md">
            {hasIcon ? <Skeleton className="size-9 shrink-0 self-start rounded-md" /> : null}
            <div className="flex min-w-0 flex-1 flex-col gap-xs">
              <Skeleton variant="text" className="h-3 w-24" />
              {/* Staggered widths. Three identical bars read as a graphic; uneven
                  ones read as text that has not arrived, which is what they are. */}
              <Skeleton
                variant="text"
                className={index % 3 === 0 ? "h-4 w-56" : index % 3 === 1 ? "h-4 w-40" : "h-4 w-48"}
              />
            </div>
          </div>
          <Skeleton className="h-8 w-20 shrink-0 rounded-md" />
        </div>
      ))}
    </div>
  );
}

export interface LoadErrorProps {
  /** The noun for what failed, lower case: "your profile", "your sessions". */
  label: string;
  /**
   * The engine's reason, when it gave one worth repeating.
   *
   * Read as a sentence on the way in, since the engine's own strings are clauses:
   * lower case, no full stop. See `asSentence`.
   */
  message?: string;
  onRetry: () => void;
  isRetrying?: boolean;
}

/**
 * A card that could not load, with the way to try again.
 *
 * The retry is a button on the card and not a page-wide reload, because the pages
 * read several resources independently: reloading the page to recover one failed
 * card discards the four that arrived.
 */
export function LoadError({ label, message, onRetry, isRetrying = false }: LoadErrorProps): ReactNode {
  return (
    <div className="flex flex-wrap items-center justify-between gap-md p-lg">
      <div className="flex min-w-0 flex-1 basis-[20rem] items-start gap-md">
        <span className="mt-xxs flex size-9 shrink-0 items-center justify-center self-start rounded-md border border-hairline bg-surface-elevated">
          <AlertIcon variant="line" size={16} className="text-accent-red" />
        </span>
        <div className="flex min-w-0 flex-col gap-xxs">
          {/* Named rather than "Something went wrong": the reader is looking at a
              page of cards and needs to know it is this one that is missing. */}
          <span className="text-body-md text-ink">Could not load {label}</span>
          <span className="text-caption text-ash">
            {asSentence(message) ??
              "This is usually temporary. Nothing on your account has changed."}
          </span>
        </div>
      </div>
      <Button size="sm" variant="ghost" isLoading={isRetrying} onClick={onRetry}>
        Try again
      </Button>
    </div>
  );
}
