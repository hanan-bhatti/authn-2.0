import type { CSSProperties, ReactNode } from "react";
import { ACCENT_GLOW, type Accent, type IllustrationComponent } from "@authn/ui";

/**
 * Authn Platform — Account page header
 * File: apps/web-account/src/components/PageHeader.tsx
 *
 * The band at the top of every account page: an eyebrow, a title, a sentence, and
 * the page's illustration.
 *
 * The illustration is the reason this is a component rather than three lines of
 * markup per page. Seven pages that each place their own drawing at their own size
 * against their own wash is seven near-misses, and the near-misses are what a
 * reader notices — a header whose picture sits four pixels lower than the last
 * one's reads as sloppiness even when nobody can say why.
 */

export interface PageHeaderProps {
  eyebrow: string;
  title: string;
  description: string;
  /** The page's scene. Passed as the component so the header owns its size. */
  illustration: IllustrationComponent;
  /** Must match the sidebar row's hue for this page. */
  accent: Accent;
  /** Actions belonging to the page as a whole, set under the sentence. */
  actions?: ReactNode;
}

export function PageHeader({
  eyebrow,
  title,
  description,
  illustration: Art,
  accent,
  actions,
}: PageHeaderProps): ReactNode {
  return (
    /* The wash is anchored to the header rather than to the page, so it fades out
       before the first card instead of tinting the content underneath it. */
    <header
      className="glow-section border-b border-hairline-strong"
      style={{ "--glow": ACCENT_GLOW[accent] } as CSSProperties}
    >
      {/* Column-reverse below `md`, so the illustration is above the title on a phone
          while staying after it in the DOM. A drawing is not a heading, and a screen
          reader or a text browser should meet the words first — reordering with flex
          keeps the reading order fixed and moves only the paint. */}
      <div className="mx-auto flex max-w-page flex-col-reverse items-start gap-xl px-lg py-xxl sm:px-xl md:flex-row md:items-center md:justify-between">
        <div className="flex max-w-broad flex-col gap-sm">
          <p className="font-mono text-caption tracking-wide text-ash uppercase">{eyebrow}</p>
          <h1 className="font-display text-display-lg text-ink">{title}</h1>
          <p className="text-body-md text-charcoal">{description}</p>
          {actions ? <div className="flex flex-wrap gap-md pt-sm">{actions}</div> : null}
        </div>

        {/* 200 at phone width and 260 above it. Below about 140 these close up, and
            the floor matters more than the ceiling here: a header that shrinks its
            drawing to fit a narrow screen is how an illustration turns into a smudge
            on exactly the device most people are holding. */}
        <Art size={200} className="md:hidden" />
        <Art size={260} className="hidden md:block" />
      </div>
    </header>
  );
}
