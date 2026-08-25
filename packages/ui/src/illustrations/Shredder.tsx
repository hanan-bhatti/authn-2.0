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
 * Authn Platform — Danger zone illustration
 * File: packages/ui/src/illustrations/Shredder.tsx
 *
 * A sheet going into a shredder and coming out as confetti.
 *
 * Chosen over the obvious trash can because a bin is reversible and this page is
 * not. Deletion here erases sessions, passkeys, recovery codes and organisation
 * membership, and the drawing should make a reader hesitate for the right reason
 * rather than warn them with a colour and hope.
 *
 * The sheet is not tilted, which is the opposite of the choice every other scene
 * in the set makes. A page feeding into a slot is constrained by the slot; tilting
 * it would say the machine had jammed. The confetti carries all the disorder, and
 * it carries a lot — eight scraps at eight angles, because four tidy ones look
 * like a pattern rather than a mess.
 */

const BODY =
  "M44 76h112a8 8 0 0 1 8 8v14a8 8 0 0 1-8 8H44a8 8 0 0 1-8-8V84a8 8 0 0 1 8-8Z" +
  "M54 80h92a2.5 2.5 0 0 1 0 5H54a2.5 2.5 0 0 1 0-5Z";

const CONFETTI = [
  { x: 60, y: 116, w: 10, angle: 18, fill: tint("red", 0.5) },
  { x: 80, y: 120, w: 14, angle: -12, fill: tint("red", 0.35) },
  { x: 104, y: 115, w: 9, angle: 26, fill: HAIR_STRONG },
  { x: 124, y: 121, w: 12, angle: -20, fill: tint("red", 0.45) },
  { x: 68, y: 130, w: 12, angle: -8, fill: tint("red", 0.3) },
  { x: 94, y: 132, w: 10, angle: 15, fill: HAIR_STRONG },
  { x: 116, y: 133, w: 13, angle: 8, fill: tint("red", 0.4) },
  { x: 140, y: 128, w: 8, angle: -28, fill: tint("red", 0.32) },
];

const SCENE = (
  <>
    {halo("red")}
    {plinth("red", 60)}

    {/* Drawn before the body and running well past the slot's lower lip, because
        what makes the sheet look fed in rather than propped against the machine is
        that it is visible *through* the slot. */}
    <rect
      x="66"
      y="12"
      width="68"
      height="78"
      rx="4"
      fill={SURFACE_ELEVATED}
      stroke={HAIR_STRONG}
      strokeWidth="1.5"
    />
    <rect x="76" y="24" width="44" height="5" rx="2.5" fill={tint("red", 0.4)} stroke="none" />
    <rect x="76" y="36" width="48" height="4" rx="2" fill={HAIR_STRONG} stroke="none" />
    <rect x="76" y="46" width="34" height="4" rx="2" fill={HAIR_STRONG} stroke="none" />

    {/* The slot is a hole in the body's fill, not a dark rectangle painted over
        it. A painted slot would have to be filled in some specific colour, and the
        moment this scene sits on a card rather than the canvas that colour seams.
        A hole shows whatever is behind — here, the sheet.

        Stroking the path strokes both subpaths, so the same declaration that
        outlines the machine also rims the slot. This is the one scene that takes
        the accent at full strength on its principal object: the page it fronts is
        the one page in the account where an accidental click is unrecoverable, and
        a shredder outlined in a polite tint undersells that. */}
    <path
      d={BODY}
      fillRule="evenodd"
      fill={SURFACE_CARD}
      stroke={solid("red")}
      strokeWidth="2.5"
    />
    <path d="M46 94h10M46 99h10" stroke={HAIR_STRONG} strokeWidth="1.5" />
    <circle cx="152" cy="97" r="2.5" fill={solid("red")} stroke="none" />

    <g fill={SURFACE_CARD} stroke={tint("red", 0.5)} strokeWidth="1.5">
      <rect x="52" y="106" width="14" height="6" rx="2" />
      <rect x="134" y="106" width="14" height="6" rx="2" />
    </g>

    {CONFETTI.map((scrap) => (
      <rect
        key={`${scrap.x}-${scrap.y}`}
        x={scrap.x}
        y={scrap.y}
        width={scrap.w}
        height="4"
        rx="1.5"
        fill={scrap.fill}
        stroke="none"
        transform={`rotate(${scrap.angle} ${scrap.x + scrap.w / 2} ${scrap.y + 2})`}
      />
    ))}

    {spark(30, 62, 4, tint("red", 0.4))}
    {spark(172, 62, 3.2, tint("red", 0.35))}
  </>
);

export const ShredderIllustration = createIllustration("ShredderIllustration", SCENE);
