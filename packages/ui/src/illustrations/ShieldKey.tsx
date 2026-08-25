import { tint } from "../utils/accent.js";
import {
  createIllustration,
  halo,
  plinth,
  solid,
  spark,
  HAIR_STRONG,
  SURFACE_CARD,
} from "./createIllustration.js";

/**
 * Authn Platform — Security illustration
 * File: packages/ui/src/illustrations/ShieldKey.tsx
 *
 * A shield with a second one hinged behind it and a key tucked in at the back.
 *
 * The shield is redrawn from scratch rather than borrowed from the icon set. At
 * 240px the icon's shield is an 84-unit silhouette held by a stroke a third of a
 * unit thick, and it looks like a template someone forgot to fill. This one
 * carries a bevel, a fill and a tick heavy enough to be the thing you notice
 * first — a shield with a faint tick in it says "protection, probably", and the
 * whole job of the page's illustration is to say "protection, on".
 *
 * The key is drawn before the shield and its tip runs under it. Occlusion is the
 * only depth cue available without gradients or shadows, and it is a strong one:
 * a shape that disappears behind another is unambiguously behind it.
 */

const SHIELD =
  "M100 28 58 42v36c0 21 17 40 42 50 25-10 42-29 42-50V42L100 28Z";

const BEVEL =
  "M100 39 68 50v28c0 16.5 13 31.5 32 39.5 19-8 32-23 32-39.5V50L100 39Z";

const SCENE = (
  <>
    {halo("green")}
    {plinth("green", 56)}

    {/* The shield behind, pivoted about a point near its own tip so the plate
        swings rather than slides. A pure offset copy reads as a printing
        misregistration; a rotation reads as a second plate. */}
    <g transform="translate(-4 -6) rotate(-9 100 90)">
      <path d={SHIELD} stroke={HAIR_STRONG} strokeWidth="1.5" />
    </g>

    {/* The key sits low and to the left, where the shield has already tapered,
        and only its tip runs under the plate. Placed against the shield's full
        width it loses its whole shaft to occlusion, and a bow with a 4-unit stub
        on it is not a key — it is a magnifying glass.

        The shield's left edge passes through roughly (63,98) and (70,107), which
        is what puts the shaft's vanishing point where it is. */}
    <g stroke={tint("green", 0.55)} strokeWidth="3">
      <circle cx="40" cy="112" r="9.5" />
      <path d="M49.5 112 82 106" />
      <path d="M57 111l1 5" />
      <path d="M64 109.5l1 5" />
    </g>

    {/* Opaque base, then the tint on top of it. One translucent fill would let
        the key's tip show through the shield and lose the occlusion. */}
    <path d={SHIELD} fill={SURFACE_CARD} stroke="none" />
    <path d={SHIELD} fill={tint("green", 0.12)} stroke={solid("green")} strokeWidth="2.5" />
    <path d={BEVEL} stroke={tint("green", 0.3)} strokeWidth="1.5" />

    <path
      d="M84 76 96 89 118 62"
      stroke={solid("green")}
      strokeWidth="6"
      strokeLinecap="round"
      strokeLinejoin="round"
    />

    {spark(166, 38, 5.5, tint("green", 0.6))}
    {spark(178, 60, 3.2, tint("green", 0.4))}
    {spark(26, 54, 4.5, tint("green", 0.45))}
  </>
);

export const ShieldKeyIllustration = createIllustration("ShieldKeyIllustration", SCENE);
