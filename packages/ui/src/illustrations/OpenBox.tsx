import { tint } from "../utils/accent.js";
import {
  createIllustration,
  halo,
  plinth,
  spark,
  HAIR_STRONG,
  SURFACE_DEEP,
  SURFACE_ELEVATED,
} from "./createIllustration.js";

/**
 * Authn Platform — Empty state illustration
 * File: packages/ui/src/illustrations/OpenBox.tsx
 *
 * An open carton with its flaps folded out and nothing inside, and three shapes
 * drifting up out of it.
 *
 * The box is open, not closed, and that distinction is the whole message. A closed
 * box on an empty list says "there is something here you cannot see", which is
 * what a broken screen looks like. An open one says "there is nothing here yet",
 * which is what an empty list actually is — and the drifting shapes say the state
 * is a beginning rather than a failure.
 */

/**
 * The mouth is an ellipse seen from above and in front, so the front face's top
 * edge is that ellipse's *lower* half — bulging down toward the viewer — and the
 * far rim is its upper half. Swapping the two sweep flags turns the box inside out:
 * the front face bulges away and the whole thing reads as a bowl.
 */
const FRONT = "M58 86a42 9 0 0 0 84 0v34a6 6 0 0 1-6 6H64a6 6 0 0 1-6-6V86Z";

const FAR_RIM = "M58 86a42 9 0 0 1 84 0";

/**
 * Each flap is a true parallelogram: two vertices on the rim, and the same two
 * displaced by one fold vector. Drawing them freehand is how a flap ends up
 * tapering, which reads as a torn box rather than an opened one.
 */
const LEFT_FLAP = "M58 86 76 82 58 60 40 64Z";

const RIGHT_FLAP = "M142 86 124 82 142 60 160 64Z";

const SCENE = (
  <>
    {halo("blue", 54)}
    {plinth("blue", 54)}

    {/* Carton stroked in the accent rather than in ink. This scene fronts an empty
        list, so it sits inside a panel next to muted copy — an ink outline there is
        the loudest thing on the screen, which is the wrong emphasis for "nothing
        here yet". */}
    <g stroke={tint("blue", 0.55)}>
      <path d={LEFT_FLAP} fill={SURFACE_ELEVATED} strokeWidth="1.8" />
      <path d={RIGHT_FLAP} fill={SURFACE_ELEVATED} strokeWidth="1.8" />
    </g>

    <ellipse cx="100" cy="86" rx="42" ry="9" fill={SURFACE_DEEP} stroke="none" />
    <path d={FAR_RIM} stroke={HAIR_STRONG} strokeWidth="1.5" />

    <path d={FRONT} fill={SURFACE_ELEVATED} stroke={tint("blue", 0.55)} />
    <path d="M78 108h44" stroke={HAIR_STRONG} strokeWidth="1.5" />

    {/* Rising, and deliberately unequal in size and spacing. Three identical
        shapes evenly spaced read as a loading indicator, which on an empty state
        is precisely the wrong thing to suggest. */}
    <circle cx="100" cy="44" r="4.5" stroke={tint("blue", 0.45)} strokeWidth="1.8" />
    <rect
      x="74"
      y="30"
      width="9"
      height="9"
      rx="2"
      stroke={tint("blue", 0.32)}
      strokeWidth="1.6"
      transform="rotate(22 78.5 34.5)"
    />
    <path d="M118 34h11" stroke={tint("blue", 0.28)} strokeWidth="2" />

    {spark(100, 18, 5.5, tint("blue", 0.5))}
    {spark(28, 108, 4, tint("blue", 0.35))}
  </>
);

export const OpenBoxIllustration = createIllustration("OpenBoxIllustration", SCENE);
