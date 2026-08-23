"use client";

/**
 * Authn Platform — Password requirements list
 * File: apps/web-account/src/components/PasswordCriteria.tsx
 */

import type { ReactNode } from "react";
import type { Criterion } from "@/lib/password";

export interface PasswordCriteriaProps {
  id: string;
  criteria: readonly Criterion[];
  /**
   * Suppresses the announcement until the user has actually typed. An empty
   * field fails every rule, and a live region that says so on focus scolds
   * someone who has not done anything yet.
   */
  isActive: boolean;
}

/**
 * Shows the policy as a checklist that resolves while the user types.
 *
 * State is never carried by colour alone: a met row swaps the marker glyph as
 * well as its colour, and each row ends in a visually-hidden verdict so a screen
 * reader reading it gets "At least 8 characters, met" rather than the label on
 * its own. The rows are ordinary content — the password field points at them
 * with `aria-describedby` — so they can be read on demand instead of only when
 * they change.
 *
 * The one live region is a count, not the rows. Announcing each row on every
 * keystroke turns a four-rule policy into four interruptions per character; a
 * single "2 of 3 met" changes only when something actually flips.
 */
export function PasswordCriteria({ id, criteria, isActive }: PasswordCriteriaProps): ReactNode {
  const metCount = criteria.filter((c) => c.met).length;

  return (
    <div className="flex flex-col gap-xs">
      <ul id={id} className="flex flex-col gap-xs">
        {criteria.map((criterion) => (
          <li
            key={criterion.id}
            className={`flex items-center gap-sm text-caption ${
              criterion.met ? "text-charcoal" : "text-ash"
            }`}
          >
            <Marker isMet={criterion.met} />
            <span>{criterion.label}</span>
            <span className="sr-only">{criterion.met ? ", met" : ", not met"}</span>
          </li>
        ))}
      </ul>

      <span role="status" aria-live="polite" className="sr-only">
        {isActive ? `${metCount} of ${criteria.length} password requirements met.` : ""}
      </span>
    </div>
  );
}

function Marker({ isMet }: { isMet: boolean }): ReactNode {
  return isMet ? (
    <svg
      aria-hidden="true"
      viewBox="0 0 12 12"
      className="size-3 shrink-0 stroke-accent-green"
      fill="none"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M2.5 6.5 4.75 8.75 9.5 3.5" />
    </svg>
  ) : (
    // A hollow ring rather than a cross. A rule not yet satisfied is the
    // starting state of every field, and marking it as an error from the first
    // keystroke makes typing a password feel like failing at it.
    <svg
      aria-hidden="true"
      viewBox="0 0 12 12"
      className="size-3 shrink-0 stroke-stone"
      fill="none"
      strokeWidth="1.25"
    >
      <circle cx="6" cy="6" r="3" />
    </svg>
  );
}
