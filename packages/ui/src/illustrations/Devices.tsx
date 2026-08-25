import { tint } from "../utils/accent.js";
import {
  createIllustration,
  halo,
  plinth,
  solid,
  spark,
  HAIR_STRONG,
  SURFACE_CARD,
  SURFACE_ELEVATED,
} from "./createIllustration.js";

/**
 * Authn Platform — Sessions illustration
 * File: packages/ui/src/illustrations/Devices.tsx
 *
 * A laptop and a phone, with a signal travelling between them and a live ping on
 * the larger screen.
 *
 * The ping is the point of the drawing. Two devices alone illustrate "devices";
 * a pulse on one of them illustrates "something is signed in right now", which is
 * what the sessions page is actually about. Three rings at falling opacity read
 * as a pulse caught mid-expansion — the same trick a status dot's halo uses,
 * scaled up.
 */

const SCENE = (
  <>
    {halo("orange")}
    {plinth("orange", 68)}

    {/* Lid and base as separate shapes rather than one traced silhouette. A
        laptop outline drawn in one path puts two near-parallel vertical edges a
        few units apart where the base meets the lid, and at this stroke weight
        they merge into a smudge.

        The chassis is stroked in the accent at three-fifths, not in ink. Ink is
        the brightest value the palette has, and a white-outlined laptop next to a
        green-outlined shield reads as two different sets — this one lands between
        the shield's full accent and the ID card's hairline, which is where a
        neutral object in a coloured scene belongs. */}
    <g stroke={tint("orange", 0.6)}>
      <rect x="32" y="36" width="100" height="64" rx="6" fill={SURFACE_ELEVATED} />
      <rect x="20" y="102" width="124" height="10" rx="5" fill={SURFACE_CARD} />
      <rect x="152" y="62" width="36" height="64" rx="9" fill={SURFACE_ELEVATED} />
    </g>
    <rect x="38" y="42" width="88" height="48" rx="3" fill={tint("orange", 0.1)} stroke="none" />
    <path d="M72 107h20" stroke={HAIR_STRONG} />
    <rect x="157" y="72" width="26" height="44" rx="4" fill={tint("orange", 0.12)} stroke="none" />
    <path d="M164 67h12" stroke={HAIR_STRONG} />
    <path d="M166 121h8" stroke={HAIR_STRONG} />

    {/* The rings stop at r=23 so the outermost stays inside the screen it is
        drawn on. A pulse that overhangs the bezel stops reading as something
        happening on the screen and starts reading as a drawing mistake. */}
    <circle cx="82" cy="66" r="23" stroke={tint("orange", 0.16)} strokeWidth="1.5" />
    <circle cx="82" cy="66" r="16" stroke={tint("orange", 0.3)} strokeWidth="1.5" />
    <circle cx="82" cy="66" r="9" stroke={tint("orange", 0.55)} strokeWidth="1.5" />
    <circle cx="82" cy="66" r="4.5" fill={solid("orange")} stroke="none" />

    {/* Signal, as three dots on a rising curve. Dots rather than a dashed line:
        a dash pattern reads as a border, and the gaps between separate dots are
        what suggest travel. */}
    <circle cx="137" cy="80" r="2" fill={tint("orange", 0.55)} stroke="none" />
    <circle cx="143.5" cy="76" r="2" fill={tint("orange", 0.4)} stroke="none" />
    <circle cx="149" cy="71" r="2" fill={tint("orange", 0.28)} stroke="none" />

    {spark(22, 26, 4.5, tint("orange", 0.5))}
    {spark(176, 36, 4, tint("orange", 0.42))}
  </>
);

export const DevicesIllustration = createIllustration("DevicesIllustration", SCENE);
