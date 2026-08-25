import { tint } from "../utils/accent.js";
import {
  createIllustration,
  halo,
  plinth,
  solid,
  spark,
  HAIR,
  HAIR_STRONG,
  SURFACE_CARD,
  SURFACE_ELEVATED,
} from "./createIllustration.js";

/**
 * Authn Platform — Profile illustration
 * File: packages/ui/src/illustrations/IdCard.tsx
 *
 * Two cards, tilted against each other, the front one carrying a portrait and a
 * name. The second card is doing real work: one card alone sits flat on the page
 * and looks like a form, and the pair immediately reads as a thing you hold.
 *
 * The tilts oppose each other — the card behind leans left, the card in front
 * leans right — because two shapes tilted the same way look like a mistake in
 * the layout rather than a stack.
 */

const SCENE = (
  <>
    {halo("blue")}
    {plinth("blue", 58)}

    <g transform="rotate(-7 100 76)">
      <rect
        x="56"
        y="32"
        width="92"
        height="60"
        rx="8"
        fill={SURFACE_ELEVATED}
        stroke={HAIR_STRONG}
        strokeWidth="1.5"
      />
    </g>

    <g transform="rotate(3 100 80)">
      <rect
        x="40"
        y="44"
        width="120"
        height="74"
        rx="10"
        fill={SURFACE_CARD}
        stroke={HAIR_STRONG}
        strokeWidth="1.5"
      />

      {/* The portrait. A head and a shoulder dome rather than the icon set's
          user glyph: at this size the icon's single 1.5-unit stroke would be a
          scratch inside a 30-unit disc, so the figure is redrawn with weight
          that belongs to the scene.

          The dome is a flattened arc, 24 wide and 8 tall, and both numbers
          matter. A semicircular one — equal radii — closes up under the head and
          the pair reads as a lightbulb rather than as a bust. */}
      <circle cx="70" cy="72" r="15" fill={tint("blue", 0.16)} stroke={solid("blue")} />
      <circle cx="70" cy="65" r="6" stroke={solid("blue")} strokeWidth="1.8" />
      <path d="M58 84a14 8 0 0 1 24 0" stroke={solid("blue")} strokeWidth="1.8" />

      {/* Name and handle. Pills rather than lettering: real text at this scale
          would have to be a font the SVG cannot guarantee, and a name nobody
          chose is worse than no name. */}
      <rect x="96" y="62" width="46" height="8" rx="4" fill={tint("blue", 0.38)} stroke="none" />
      <rect x="96" y="76" width="32" height="6" rx="3" fill={HAIR_STRONG} stroke="none" />

      <path d="M54 100h92" stroke={HAIR} strokeWidth="1.5" />
      <rect x="54" y="106" width="28" height="5" rx="2.5" fill={HAIR_STRONG} stroke="none" />
      <rect x="88" y="106" width="18" height="5" rx="2.5" fill={HAIR} stroke="none" />

      {/* The verified mark sits on the card's edge rather than inside it, so it
          reads as applied to the card instead of printed on it. */}
      <circle cx="146" cy="54" r="7.5" stroke={tint("blue", 0.4)} strokeWidth="1.5" />
      <circle cx="146" cy="54" r="3.5" fill={solid("blue")} stroke="none" />
    </g>

    {spark(174, 36, 6, tint("blue", 0.7))}
    {spark(184, 58, 3.5, tint("blue", 0.45))}
    {spark(24, 104, 4.5, tint("blue", 0.5))}
  </>
);

export const IdCardIllustration = createIllustration("IdCardIllustration", SCENE);
