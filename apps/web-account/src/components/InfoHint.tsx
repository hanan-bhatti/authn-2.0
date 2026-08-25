"use client";

import type { ReactNode } from "react";
import { InfoIcon, Tooltip } from "@authn/ui";
import { helpTopics, type HelpTopicId } from "@/lib/docs";

/**
 * Authn Platform — Inline explanation
 * File: apps/web-account/src/components/InfoHint.tsx
 *
 * The small "i" beside a label, carrying the rule or limit that would otherwise
 * only be discovered by breaking it.
 *
 * It sits beside the label rather than under it because the rules it carries are
 * ones a reader wants *before* deciding — what a username may contain, what
 * changing a password will do to their other sessions. Text under the field is
 * read after the field is filled in, which is too late to be a rule and only
 * early enough to be a reproach.
 */

export interface InfoHintProps {
  topic: HelpTopicId;
  /**
   * What the icon is called for assistive technology, phrased as the thing being
   * explained: "usernames", "recovery codes".
   *
   * Required, because "more information" repeated eleven times down a page is a
   * list of eleven identical items to anyone navigating by control.
   */
  label: string;
  position?: "top" | "bottom" | "left" | "right";
}

export function InfoHint({ topic, label, position = "top" }: InfoHintProps): ReactNode {
  return (
    <Tooltip content={helpTopics[topic].summary} position={position} multiline>
      {/*
        A button rather than a bare icon: the explanation has to be reachable
        without a pointer, and only a focusable element can be tabbed to. `type`
        is set because these appear inside forms, where a button with no type
        defaults to submit — so asking what a rule is would save the form.

        No focus ring here. The design system applies one treatment to every
        focusable element globally, and a second one on this button would make
        the same key press look different depending on where it landed.
      */}
      <button
        type="button"
        aria-label={`About ${label}`}
        className="inline-flex size-5 shrink-0 items-center justify-center rounded-full text-ash transition-colors duration-fast hover:text-ink"
      >
        <InfoIcon size={15} />
      </button>
    </Tooltip>
  );
}
