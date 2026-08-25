import { tint } from "../utils/accent.js";
import { createIllustration, halo, plinth, solid, spark } from "./createIllustration.js";

/**
 * Authn Platform — Connected accounts illustration
 * File: packages/ui/src/illustrations/Rings.tsx
 *
 * Two rings genuinely interlocked, and a third one dashed and empty.
 *
 * This is the one scene that uses more than one accent, and the exception is the
 * subject's own fault: everywhere else on the account a hue names a single
 * status, but linked accounts are by definition two parties, and drawing both in
 * the same colour would be drawing the wrong thing. The dashed third ring with a
 * plus in it carries the page's actual affordance — two are joined, another could
 * be — which a static pair of rings cannot say.
 *
 * Interlocking is done by redrawing one arc, not by clipping. `clipPath` needs an
 * `id`, and this layer refuses ids so that a scene can appear twice on a page.
 * Ring A is drawn, ring B covers it, then the upper half of A's overlapping arc
 * is drawn again on top: A crosses over B at the top and under it at the bottom,
 * which is exactly what two joined links do. Redrawing A's *whole* overlap arc
 * would put A in front at both crossings and the pair would look stacked instead.
 */

/**
 * Both rings have r=34 and centres 48 apart, so they meet at x=100, y=86±24.08.
 * Those two points are where every path below starts or ends; nudging a centre
 * without recomputing them is how an interlock turns into a near miss.
 */
const LENS = "M100 61.9A34 34 0 0 1 100 110.1A34 34 0 0 1 100 61.9Z";

const OVER_ARC = "M100 61.9A34 34 0 0 1 110 86";

const SCENE = (
  <>
    {halo("blue")}
    {plinth("blue", 64)}

    <circle cx="76" cy="86" r="34" fill={tint("blue", 0.08)} stroke={solid("blue")} strokeWidth="6" />
    <circle
      cx="124"
      cy="86"
      r="34"
      fill={tint("green", 0.08)}
      stroke={solid("green")}
      strokeWidth="6"
    />

    <path d={LENS} fill={tint("blue", 0.1)} stroke="none" />
    <path d={OVER_ARC} stroke={solid("blue")} strokeWidth="6" />

    <circle
      cx="166"
      cy="40"
      r="12"
      stroke={tint("blue", 0.42)}
      strokeWidth="3"
      strokeDasharray="6 7"
    />
    <path d="M166 34v12M160 40h12" stroke={tint("blue", 0.55)} strokeWidth="2.5" />

    {spark(34, 40, 5, tint("blue", 0.45))}
    {spark(184, 106, 4, tint("green", 0.4))}
  </>
);

export const RingsIllustration = createIllustration("RingsIllustration", SCENE);
