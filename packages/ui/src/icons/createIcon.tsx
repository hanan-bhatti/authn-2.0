import type { ReactNode, SVGProps } from "react";
import { type Accent, ACCENT_SOLID, tint } from "../utils/accent.js";
import { cn } from "../utils/cn.js";

/**
 * Authn Platform — Icon primitive
 * File: packages/ui/src/icons/createIcon.tsx
 */

/**
 * Which cut of an icon to draw.
 *
 * `line` is the default and the only one that belongs in dense UI: a sidebar of
 * filled glyphs reads as a column of blobs at 16px, because a filled shape at
 * that size loses its interior detail before its silhouette. `filled` is for the
 * one icon in a view that is currently selected or is the subject of the screen.
 * `color` is for the largest sizes only — a section header, an empty state, an
 * onboarding step — where there is enough area for a second tone to be a
 * deliberate accent rather than noise.
 */
export type IconVariant = "line" | "filled" | "color";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "children"> {
  variant?: IconVariant;
  /**
   * Edge length in px, written to `width`/`height`. A Tailwind size class still
   * wins over it — these are presentation attributes and CSS outranks them — so
   * a caller can pass `className="size-4"` and ignore this.
   */
  size?: number;
  /**
   * Names the icon for assistive technology, which also makes it a graphic
   * rather than decoration.
   *
   * Left off, the icon is marked `aria-hidden`. That is the right default: an
   * icon almost always sits beside the text it illustrates, and announcing both
   * makes a screen reader read every label twice.
   */
  title?: string;
}

/** Draws one variant's geometry. Receives the variant so shared art can branch. */
export type IconArt = (variant: IconVariant) => ReactNode;

/**
 * What `createIcon` returns, named so a component can be *passed* an icon rather
 * than a rendered one.
 *
 * The distinction decides who picks the variant. A prop typed `ReactNode` forces
 * the caller to render the glyph, and therefore to choose `line` or `filled`
 * before handing it over — but the thing that knows which row is selected is the
 * list, not the caller building its data. Taking the component lets the list
 * switch cuts, which is the entire reason the cuts exist.
 */
export type IconComponent = (props: IconProps) => ReactNode;

/**
 * The accent a `color` icon washes its subject in.
 *
 * Re-exported from the shared accent module rather than declared here, because
 * the illustration layer answers to the same five meanings and a second
 * declaration is how the two layers drift apart.
 */
export type IconAccent = Accent;

/**
 * The wash strengths this layer uses.
 *
 * Green and red sit lower than the rest because they are the two most luminous
 * accents on a black canvas — at a shared alpha they would read as brighter
 * badges rather than as the same badge in a different hue.
 */
export const ACCENT_WASH: Record<Accent, string> = {
  blue: tint("blue", 0.22),
  green: tint("green", 0.2),
  orange: tint("orange", 0.22),
  yellow: tint("yellow", 0.22),
  red: tint("red", 0.2),
};

/**
 * The area a `color` icon's hue lives in.
 *
 * A stroked glyph tinted an accent has almost no area on a black canvas — it
 * reads as a thin coloured scratch rather than as a coloured icon. The disc
 * gives the hue enough surface to register, which is also what keeps the accent
 * off the stroke weight: the silhouette stays the same one the `line` cut draws.
 *
 * Radius 11 fills the 24-unit box rather than the 20-unit live area. It carries
 * no stroke, so nothing clips, and the extra ring is what makes the subject look
 * inset in a badge instead of pressed against its edge.
 */
export function wash(accent: Accent): ReactNode {
  return <circle cx="12" cy="12" r="11" fill={ACCENT_WASH[accent]} stroke="none" />;
}

/**
 * Re-strokes shared art in an accent.
 *
 * A presentation attribute on a child outranks the same attribute inherited from
 * its parent, so this recolours whatever the `line` cut drew without that art
 * knowing anything about accents.
 *
 * `color` is set as well as `stroke`, and it is not redundant: a few icons carry
 * a solid detail inside otherwise stroked art — the dot under a warning triangle
 * — which has to declare `fill="currentColor"` to survive the `fill="none"` on
 * the svg. Overriding `stroke` alone leaves that detail the colour of the
 * surrounding text, so a yellow warning icon keeps a white dot.
 */
export function tinted(accent: Accent, art: ReactNode): ReactNode {
  return (
    <g style={{ color: ACCENT_SOLID[accent] }} stroke={ACCENT_SOLID[accent]}>
      {art}
    </g>
  );
}

/**
 * The `color` cut, assembled from the `line` cut.
 *
 * Every colour icon in the set is this: one wash, one tinted silhouette. Drawing
 * a separate colour geometry per icon is how a set ends up with two icons that
 * disagree about their own shape depending on which size you look at.
 */
export function washed(accent: Accent, art: ReactNode): ReactNode {
  return (
    <>
      {wash(accent)}
      {tinted(accent, art)}
    </>
  );
}

/**
 * A heavier stroke, for icons a solid fill would destroy.
 *
 * Most icons have an interior to flood. A few are glyphs — an at-sign, a link, a
 * hash — whose meaning *is* the negative space, and filling them yields a blob.
 * Those get weight instead of area, which is what a bold cut of a typeface does
 * with the same problem.
 */
export function weighted(art: ReactNode): ReactNode {
  return (
    <g fill="none" stroke="currentColor" strokeWidth={2.25}>
      {art}
    </g>
  );
}

/**
 * Builds an icon component from its geometry.
 *
 * Every icon is drawn on the same 24-unit grid with its art kept inside a 20-unit
 * live area, which is what makes a row of them look aligned: mixed grids show up
 * as icons that appear to be different sizes even when their boxes match. The
 * presentation attributes live here rather than on each path so a variant is one
 * decision per icon instead of one per shape, and so `strokeWidth` stays uniform
 * across the set — an icon a quarter-unit heavier than its neighbours is the most
 * common way a hand-drawn set looks amateur.
 *
 * Deliberately not a client component, and deliberately not wrapped in
 * `forwardRef`. `forwardRef` is unavailable to a server component, so using it
 * would force a `"use client"` directive onto this module — and because the icon
 * modules *call* this function while their own module is evaluated, that
 * directive makes every icon file unimportable from a server component. React 19
 * passes `ref` through as an ordinary prop, so the spread below still forwards
 * one; on React 18 a ref would be dropped with a warning.
 */
export function createIcon(displayName: string, art: IconArt) {
  function Icon({ variant = "line", size = 20, title, className, ...props }: IconProps): ReactNode {
    const isFilled = variant === "filled";

    return (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        width={size}
        height={size}
        fill={isFilled ? "currentColor" : "none"}
        stroke={isFilled ? "none" : "currentColor"}
        strokeWidth={isFilled ? undefined : 1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        className={cn("shrink-0", className)}
        role={title ? "img" : undefined}
        aria-hidden={title ? undefined : true}
        focusable="false"
        {...props}
      >
        {title && <title>{title}</title>}
        {art(variant)}
      </svg>
    );
  }

  Icon.displayName = displayName;
  return Icon;
}
