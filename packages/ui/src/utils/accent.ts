/**
 * Authn Platform — Accent semantics
 * File: packages/ui/src/utils/accent.ts
 *
 * The one thing the icon layer and the illustration layer share.
 *
 * They must not share geometry: an icon is a 24-unit functional glyph and an
 * illustration is a 200-unit scene, and a set that scales one into the other
 * produces a wireframe at the top end and mud at the bottom. What they do share
 * is what a hue *means*, because a reader learns that code once and then applies
 * it to everything on the page — the small green tick beside "Two-factor is on"
 * and the large green shield above the section heading have to be making the
 * same claim.
 */

/**
 * Fixed meaning per hue: blue is identity, green is a protection that is on,
 * orange is a live session or a device, yellow needs attention, red destroys
 * something.
 */
export type Accent = "blue" | "green" | "orange" | "yellow" | "red";

/**
 * The saturated accent, for contours and inline marks.
 *
 * A `var()` rather than a literal, so a tenant that overrides
 * `--color-accent-blue` on the document root recolours every icon and every
 * illustration without a rebuild.
 */
export const ACCENT_SOLID: Record<Accent, string> = {
  blue: "var(--color-accent-blue)",
  green: "var(--color-accent-green)",
  orange: "var(--color-accent-orange)",
  yellow: "var(--color-accent-yellow)",
  red: "var(--color-accent-red)",
};

/**
 * The atmospheric wash behind a section, one per accent.
 *
 * A separate token from the solid rather than the solid at low alpha, because a
 * wash the same hue as the marks in front of it flattens the two together — each
 * glow is a deeper, more saturated version of its accent, which is what makes the
 * accent read as lit *by* it.
 *
 * All five exist. Yellow's was missing for a while, and the failure was not a
 * missing wash: an SVG presentation attribute holding an undefined `var()`
 * resolves to black rather than to nothing, so anything reaching for it drew a
 * black shape.
 */
export const ACCENT_GLOW: Record<Accent, string> = {
  blue: "var(--color-accent-blue-glow)",
  green: "var(--color-accent-green-glow)",
  orange: "var(--color-accent-orange-glow)",
  yellow: "var(--color-accent-yellow-glow)",
  red: "var(--color-accent-red-glow)",
};

/**
 * The same hues as `r, g, b` triples, which is what `tint` needs.
 *
 * Duplicating the values from the stylesheet is deliberate. The alternative is
 * `color-mix(in oklab, var(--color-accent-blue) 22%, transparent)`, which does
 * follow a runtime override — but every wash in both drawing layers goes through
 * `tint`, including inside SVG presentation attributes, and those have no
 * tolerance for a token that turns out not to exist: the result is black, not
 * nothing. Literals cannot fail that way.
 */
const ACCENT_RGB: Record<Accent, string> = {
  blue: "59, 158, 255",
  green: "17, 255, 153",
  orange: "255, 128, 31",
  yellow: "255, 197, 61",
  red: "255, 32, 71",
};

/**
 * An accent at partial opacity, for area rather than for line.
 *
 * Area is where accents get dangerous on this canvas: the design system reserves
 * solid accent surfaces for inline marks precisely because a saturated fill
 * competes with the single white primary button a page is built around. Every
 * filled region in both layers goes through here, so "how loud is the colour"
 * stays one number rather than a judgement made per shape.
 */
export function tint(accent: Accent, alpha: number): string {
  return `rgba(${ACCENT_RGB[accent]}, ${alpha})`;
}
