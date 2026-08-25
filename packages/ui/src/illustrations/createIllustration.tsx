import type { ReactNode, SVGProps } from "react";
import { type Accent, ACCENT_SOLID, tint } from "../utils/accent.js";
import { cn } from "../utils/cn.js";

/**
 * Authn Platform — Illustration primitive
 * File: packages/ui/src/illustrations/createIllustration.tsx
 *
 * The second of the two drawing layers, and deliberately not the first one made
 * bigger.
 *
 * An icon labels a control: it is 24 units wide, it is one stroke weight, it is
 * read in a fifth of a second beside a word it repeats, and it has to survive
 * being 16px tall in a table row. An illustration does the opposite job — it
 * gives a page a subject, tells a reader at a glance which of seven near
 * identical settings screens they are on, and makes a screen with nothing on it
 * yet feel finished rather than broken. So it gets 200 units, several stroke
 * weights, real fills, and no obligation to be legible at any size at all.
 *
 * The two layers share exactly one thing, in `../utils/accent.ts`: what a hue
 * means. Nothing else crosses over. An icon path scaled up to 240px is a
 * wireframe — its 1.5-unit stroke becomes a hairline around an enormous empty
 * silhouette — and an illustration scaled down to 20px is mud.
 */

/** Scene width in the local coordinate system. */
const SCENE_W = 200;

/** Scene height. 5:4 leaves room for a subject with air above and a floor below. */
const SCENE_H = 160;

export interface IllustrationProps extends Omit<SVGProps<SVGSVGElement>, "children"> {
  /**
   * Rendered width in px; height follows the scene's 5:4 ratio.
   *
   * The default suits a page header or an empty state. Below about 140 the
   * interior detail starts closing up and an icon is the better tool; above
   * about 320 the flat fills start looking like flat fills.
   */
  size?: number;
}

/**
 * A scene is a fixed drawing, not a function of a variant.
 *
 * The icon factory takes a callback because one icon has three cuts to switch
 * between. An illustration has one cut, so the geometry can be a plain node —
 * evaluated once when the module loads rather than on every render.
 */
export type IllustrationScene = ReactNode;

/**
 * What `createIllustration` returns, so a component can be handed a scene rather
 * than a rendered one.
 *
 * Same reason as `IconComponent`, different beneficiary: here it is the *size* the
 * receiver needs to own. A page header that accepted a rendered element would have
 * to trust seven call sites to have each picked the same number, and the one that
 * picked 240 instead of 260 is a defect nobody can see without opening two pages
 * side by side.
 */
export type IllustrationComponent = (props: IllustrationProps) => ReactNode;

/**
 * The `<svg>` element's stroke, and a fallback rather than a colour any scene
 * should ask for.
 *
 * Ink is the brightest value the palette has. A scene that outlines its subject in
 * it gets an object brighter than every heading on the page, and — because
 * `currentColor` resolves against whatever block the illustration is dropped into —
 * one that changes weight when it moves next to muted copy. The set's rule is that
 * a subject's contour is either the accent or a hairline; nothing in between, and
 * nothing that depends on its surroundings. This constant exists so that a path
 * which forgets its stroke is visible instead of invisible.
 */
export const INK = "currentColor";

export const HAIR = "var(--color-hairline)";
export const HAIR_STRONG = "var(--color-hairline-strong)";
export const CANVAS = "var(--color-canvas)";
export const SURFACE_CARD = "var(--color-surface-card)";
export const SURFACE_ELEVATED = "var(--color-surface-elevated)";

/**
 * Cooler and darker than the canvas, which the eye reads as recession — the one
 * fill that makes the inside of something look like an inside.
 */
export const SURFACE_DEEP = "var(--color-surface-deep)";

/** The saturated accent, for a scene's focal contour. */
export function solid(accent: Accent): string {
  return ACCENT_SOLID[accent];
}

/**
 * The atmospheric wash behind a subject.
 *
 * Depth without a gradient, and that constraint is load-bearing rather than
 * stylistic: a `linearGradient` needs an `id` to be referenced by, `id` has to be
 * unique in a document, and a server component cannot call `useId`. Two of the
 * same illustration on one page would emit the same id twice. Layering flat
 * translucent shapes gets the falloff — two overlapping washes read as three
 * tones — and keeps every scene a static tree with no ids in it at all.
 */
export function halo(accent: Accent, radius = 58): ReactNode {
  return <circle cx="100" cy="74" r={radius} fill={tint(accent, 0.07)} stroke="none" />;
}

/**
 * The shadow a subject sits on.
 *
 * The single strongest signal that eight separately drawn scenes are one set:
 * every subject rests on the same ellipse at the same height, so they share a
 * horizon and a light direction even though no two of them share a shape.
 */
export function plinth(accent: Accent, rx = 62): ReactNode {
  return <ellipse cx="100" cy="142" rx={rx} ry="6.5" fill={tint(accent, 0.1)} stroke="none" />;
}

/**
 * A glint.
 *
 * The cheapest source of life in a scene, and the reason every one of these has
 * two or three: a drawing built only from the object itself reads as a technical
 * diagram, and one built from the object plus a few asymmetric glints reads as a
 * picture of it. Asymmetric matters — sparks placed in a tidy row look like a
 * loading indicator.
 *
 * The sides are quadratic rather than straight, so the arms taper to a point
 * instead of forming a diamond. A diamond at this size is a bullet.
 */
export function spark(x: number, y: number, r: number, color: string): ReactNode {
  const w = r * 0.26;
  return (
    <path
      d={
        `M${x} ${y - r}Q${x + w} ${y - w} ${x + r} ${y}` +
        `Q${x + w} ${y + w} ${x} ${y + r}` +
        `Q${x - w} ${y + w} ${x - r} ${y}` +
        `Q${x - w} ${y - w} ${x} ${y - r}Z`
      }
      fill={color}
      stroke="none"
    />
  );
}

/**
 * Builds an illustration component from its geometry.
 *
 * `aria-hidden` is unconditional and there is no `title` prop, which is the one
 * hard line between this layer and the icons. An icon can be the only label a
 * control has, so it needs a way to name itself. An illustration is never the
 * only carrier of anything — if a scene were load-bearing, a screen reader user
 * would be missing information no `<title>` could adequately replace, and the
 * page needs real text instead.
 */
export function createIllustration(displayName: string, scene: IllustrationScene) {
  function Illustration({ size = 240, className, ...props }: IllustrationProps): ReactNode {
    return (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox={`0 0 ${SCENE_W} ${SCENE_H}`}
        width={size}
        height={(size * SCENE_H) / SCENE_W}
        fill="none"
        stroke={INK}
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
        className={cn("shrink-0", className)}
        aria-hidden="true"
        focusable="false"
        {...props}
      >
        {scene}
      </svg>
    );
  }

  Illustration.displayName = displayName;
  return Illustration;
}
