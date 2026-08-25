import type { ReactNode } from "react";
import { ACCENT_SOLID, tint, type Accent, type IconComponent } from "@authn/ui";

/**
 * Authn Platform — Account page primitives
 * File: apps/web-account/src/components/SettingsCard.tsx
 *
 * The two shapes every account page is built from: a titled card, and a row inside
 * it that pairs a label with a value and an action.
 *
 * Extracted because the alternative is seven pages that each invent their own
 * padding. The rules worth enforcing in one place are that a card is `lg` where its
 * controls are `md`, that a row's divider comes from the list rather than from the
 * row, and that the action sits at the trailing edge on wide screens and under the
 * value on narrow ones.
 */

export interface SettingsCardProps {
  /** Anchor target, for a sidebar child that links to a fragment of this page. */
  id?: string;
  title: string;
  description?: string;
  /** Actions belonging to the card as a whole, set beside its title. */
  action?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  /**
   * Recolours the frame, for a card that differs in *kind* from the ones around
   * it rather than merely in subject — the deletion card being the case that
   * needs it, since a reader skimming three identically framed cards has been
   * given no signal that the third one cannot be undone.
   *
   * A prop and not a `className` passed in from the page, because `cn` here
   * concatenates rather than resolving conflicts: a card emitting both
   * `border-hairline-strong` and an accent border has two rules setting one
   * property, and which one lands is decided by the order Tailwind happened to
   * write them into the stylesheet. The hue arrives as a value instead, so there
   * is only ever one border colour to be had.
   */
  accent?: Accent;
}

export function SettingsCard({
  id,
  title,
  description,
  action,
  children,
  footer,
  accent,
}: SettingsCardProps): ReactNode {
  return (
    /* `scroll-mt` and not just an id. The mobile top bar is sticky, so a fragment
       jump lands the card's first line underneath it — the browser scrolls the anchor
       to y=0 and the bar is already there. The margin is the bar's height plus a
       little air. */
    <section
      id={id}
      className="scroll-mt-20 rounded-lg border border-hairline-strong bg-surface-card"
      /* 0.4 rather than the solid: the frame has to be readable as red without
         becoming the loudest thing in the card, which is the button inside it. */
      style={accent ? { borderColor: tint(accent, 0.4) } : undefined}
    >
      <div className="flex flex-wrap items-start justify-between gap-md border-b border-hairline p-lg">
        {/* Same fixed basis as the rows below, for the same reason: a two-line
            description would otherwise be measured at its full unwrapped width and
            push the card's action onto its own line on a screen with room for both. */}
        <div className="flex min-w-0 flex-1 basis-[20rem] max-w-broad flex-col gap-xxs">
          <h2 className="font-display text-heading-sm text-ink">{title}</h2>
          {description ? <p className="text-body-sm text-charcoal">{description}</p> : null}
        </div>
        {action ? <div className="flex shrink-0 items-center gap-sm">{action}</div> : null}
      </div>

      {children ? <div className="flex flex-col">{children}</div> : null}

      {footer ? (
        <div className="flex flex-wrap items-center justify-end gap-md border-t border-hairline p-lg">
          {footer}
        </div>
      ) : null}
    </section>
  );
}

export interface SettingsRowProps {
  label: string;
  /** The current setting, as text or as a control. */
  value?: ReactNode;
  hint?: string;
  action?: ReactNode;
  /**
   * A glyph for the row's subject, set on a plaque at the leading edge.
   *
   * All-or-nothing within a card: one row with a plaque and three without reads as
   * a row that failed to load its icon. Worth having where the rows are a list of
   * *kinds* — a password, an authenticator, a passkey — because the glyph is what
   * makes them scannable without reading. Worth skipping where they are fields of
   * one thing, as on Profile, where three plaques would be decorating "name",
   * "handle" and "email" with pictures nobody needs.
   */
  icon?: IconComponent;
  /** The glyph's hue. Left off, it is `text-ash`, the same weight as the hint. */
  accent?: Accent;
}

export function SettingsRow({
  label,
  value,
  hint,
  action,
  icon: Glyph,
  accent,
}: SettingsRowProps): ReactNode {
  return (
    /* The divider is a top border on every row but the first, rather than a bottom
       border on every row but the last. `:not(:first-child)` is one selector; the
       other needs the list to know its own length, which a component rendering one
       row does not. */
    <div className="flex flex-wrap items-center justify-between gap-md p-lg not-first:border-t not-first:border-hairline">
      {/* `basis-[20rem]` with grow and shrink both on, which is what decides where the
          action sits. Flex line-breaking happens before shrinking, so a block whose
          basis is `auto` is measured at its content's full width — one long hint and
          the row wraps, dropping the button under the text on a screen with room to
          spare. A fixed basis says: give this 320px and let it grow into whatever is
          left, and only wrap when 320px plus the action genuinely does not fit, which
          is the behaviour a phone wants and a laptop does not. */}
      <div className="flex min-w-0 flex-1 basis-[20rem] items-center gap-md">
        {Glyph ? (
          /* `self-start` with a top margin rather than centred, so a row whose hint
             wraps to three lines keeps the plaque beside the label instead of
             floating it down to the middle of the block. */
          <span className="mt-xxs flex size-9 shrink-0 items-center justify-center self-start rounded-md border border-hairline bg-surface-elevated">
            <Glyph
              variant="line"
              size={16}
              style={accent ? { color: ACCENT_SOLID[accent] } : undefined}
              className={accent ? undefined : "text-ash"}
            />
          </span>
        ) : null}
        <div className="flex min-w-0 flex-col gap-xxs">
          <span className="text-body-sm text-mute">{label}</span>
          {value ? <span className="text-body-md text-ink">{value}</span> : null}
          {hint ? <span className="text-caption text-ash">{hint}</span> : null}
        </div>
      </div>
      {action ? <div className="flex shrink-0 items-center gap-sm">{action}</div> : null}
    </div>
  );
}
