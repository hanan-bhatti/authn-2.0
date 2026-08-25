import type { ReactNode } from "react";
import { ExternalLinkIcon } from "@authn/ui";
import { helpHref, helpTopics, type HelpTopic, type HelpTopicId } from "@/lib/docs";

/**
 * Authn Platform — Explanatory help text
 * File: apps/web-account/src/components/HelpText.tsx
 *
 * The longer answer, for a card footer or an empty state.
 *
 * The text comes first and the link is an addition to it, which is the opposite
 * of the button this replaced. "Read about OAuth scopes" put the whole
 * explanation behind a click and then, with no documentation site configured,
 * behind a click that went nowhere — so the reader got a control that looked like
 * an answer and was not one. Here the answer is on the page, and the link is
 * offered only when there is something at the other end of it.
 */

export interface HelpTextProps {
  topic: HelpTopicId;
  /**
   * Renders the one-line summary instead of the fuller explanation. For a place
   * with a paragraph's worth of room already spent.
   */
  short?: boolean;
  className?: string;
}

export function HelpText({ topic, short = false, className }: HelpTextProps): ReactNode {
  // Annotated rather than inferred. `helpTopics` is declared `as const satisfies
  // Record<string, HelpTopic>`, which keeps every entry's literal shape — so an
  // entry that omits the optional `detail` has no such property to read at all,
  // and indexing the table gives a union in which `detail` exists on only some
  // members. The annotation widens to the shape `satisfies` already proved.
  const entry: HelpTopic = helpTopics[topic];
  const href = helpHref(topic);
  const body = short ? entry.summary : (entry.detail ?? entry.summary);

  return (
    <p className={className ?? "text-caption text-ash"}>
      {body}
      {href !== null && (
        <>
          {" "}
          {/*
            `noreferrer` alongside `noopener` because the destination is a
            different origin and the path of the page a reader was on when they
            asked what a recovery code is is nobody else's business.
          */}
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-xs text-ink underline decoration-hairline-strong underline-offset-2 transition-colors duration-fast hover:decoration-ink"
          >
            Read more
            <ExternalLinkIcon size={12} />
          </a>
        </>
      )}
    </p>
  );
}
