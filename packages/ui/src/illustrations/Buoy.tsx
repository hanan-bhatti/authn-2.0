import { tint } from "../utils/accent.js";
import {
  createIllustration,
  halo,
  plinth,
  solid,
  spark,
  HAIR_STRONG,
  SURFACE_ELEVATED,
} from "./createIllustration.js";

/**
 * Authn Platform — Recovery illustration
 * File: packages/ui/src/illustrations/Buoy.tsx
 *
 * A life ring with its rope, and two code slips drifting beside it.
 *
 * The slips are what make this a recovery picture rather than a swimming one.
 * They are also the honest shape for the thing they stand in for: recovery codes
 * are the one credential on the platform a user is told to print, and a scrap of
 * paper is what a scrap of paper looks like.
 */

/**
 * The ring's band, as eight 45° arcs alternating between full and washed.
 *
 * The classic buoy has its stripes in the background colour. That would work
 * here and break the first time someone put this illustration on a card instead
 * of the canvas — the stripes would still be canvas-black and seam against the
 * card. Two strengths of the same accent belong to the drawing rather than to
 * whatever is behind it.
 *
 * Every endpoint is a point on r=36 at a multiple of 45°, which is why they carry
 * two decimals: 36·cos45 is 25.456, and rounding it to 25 opens a visible notch
 * between two 11-unit-wide segments.
 */
const BAND = [
  "M100 40A36 36 0 0 1 125.46 50.54",
  "M125.46 50.54A36 36 0 0 1 136 76",
  "M136 76A36 36 0 0 1 125.46 101.46",
  "M125.46 101.46A36 36 0 0 1 100 112",
  "M100 112A36 36 0 0 1 74.54 101.46",
  "M74.54 101.46A36 36 0 0 1 64 76",
  "M64 76A36 36 0 0 1 74.54 50.54",
  "M74.54 50.54A36 36 0 0 1 100 40",
];

const SCENE = (
  <>
    {halo("yellow")}
    {plinth("yellow", 58)}

    {/* Butt caps, not the set's round ones. A round cap on an 11-unit stroke
        overhangs its own endpoint by 5.5 units, so each segment would bleed into
        both neighbours and the alternation would turn into a gradient. */}
    {BAND.map((d, index) => (
      <path
        key={d}
        d={d}
        stroke={index % 2 === 0 ? solid("yellow") : tint("yellow", 0.3)}
        strokeWidth="11"
        strokeLinecap="butt"
      />
    ))}

    <path d="M62 92c-14 2-24-8-36-4" stroke={tint("yellow", 0.5)} strokeWidth="3" />

    <g transform="rotate(-12 35 115)">
      <rect
        x="18"
        y="104"
        width="34"
        height="22"
        rx="3"
        fill={SURFACE_ELEVATED}
        stroke={HAIR_STRONG}
        strokeWidth="1.5"
      />
      <rect x="23" y="110" width="24" height="3.5" rx="1.75" fill={tint("yellow", 0.45)} stroke="none" />
      <rect x="23" y="117" width="16" height="3.5" rx="1.75" fill={HAIR_STRONG} stroke="none" />
    </g>

    <g transform="rotate(10 167 109)">
      <rect
        x="150"
        y="98"
        width="34"
        height="22"
        rx="3"
        fill={SURFACE_ELEVATED}
        stroke={HAIR_STRONG}
        strokeWidth="1.5"
      />
      <rect x="155" y="104" width="24" height="3.5" rx="1.75" fill={tint("yellow", 0.45)} stroke="none" />
      <rect x="155" y="111" width="16" height="3.5" rx="1.75" fill={HAIR_STRONG} stroke="none" />
    </g>

    {spark(100, 26, 5, tint("yellow", 0.55))}
    {spark(178, 54, 3.5, tint("yellow", 0.4))}
  </>
);

export const BuoyIllustration = createIllustration("BuoyIllustration", SCENE);
