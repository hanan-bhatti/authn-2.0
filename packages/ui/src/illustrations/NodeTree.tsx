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
 * Authn Platform — Organizations illustration
 * File: packages/ui/src/illustrations/NodeTree.tsx
 *
 * An org, its two teams, and a nested team inside one of them — drawn as the same
 * elbow-connected tree the sidebar uses, because a reader who has just navigated
 * that tree recognises the shape before reading a word of the heading.
 *
 * The whole thing is tilted three degrees, and that is the only reason it is an
 * illustration instead of a diagram. Axis-aligned boxes joined by right angles
 * read as information to be studied; the same boxes off-axis read as a picture of
 * a structure. Three degrees is enough — past about five the text pills start
 * looking like they are sliding out of their nodes.
 */

const SCENE = (
  <>
    {halo("blue")}
    {plinth("blue", 66)}

    <g transform="translate(0 -4) rotate(-3 100 80)">
      {/* One path for the trunk and its final elbow, so the corner radius is a
          property of the line rather than two shapes meeting at a rounded join
          that only looks round at one stroke weight.

          The connectors are tinted rather than hairline. A hairline is right for a
          box's edge, where the box's own fill carries the shape, but here the lines
          are the subject: drop them and four staggered cards are four cards. At the
          140px this has to survive, `hairline-strong` over 1.5 units is a single
          device pixel at fourteen percent, which is nothing. */}
      <g stroke={tint("blue", 0.32)} strokeWidth="2">
        <path d="M40 50v73a6 6 0 0 1 6 6h10" />
        <path d="M40 73h16" />
        <path d="M70 84v11a6 6 0 0 1 6 6h10" />
      </g>

      {/* The root is the organisation, and it stays neutral. Two accent-bordered
          nodes read as two selections, which is one more than a tree can have —
          the root's rank comes from sitting at indent zero with everything hanging
          off it, so it does not need colour as well. The muted disc is its mark. */}
      <rect
        x="26"
        y="26"
        width="76"
        height="24"
        rx="8"
        fill={SURFACE_ELEVATED}
        stroke={HAIR_STRONG}
        strokeWidth="1.5"
      />
      <circle cx="40" cy="38" r="5" fill={tint("blue", 0.4)} stroke="none" />
      <rect x="52" y="35" width="38" height="6" rx="3" fill={HAIR_STRONG} stroke="none" />

      <rect
        x="56"
        y="62"
        width="84"
        height="22"
        rx="7"
        fill={SURFACE_ELEVATED}
        stroke={HAIR_STRONG}
        strokeWidth="1.5"
      />
      <circle cx="68" cy="73" r="4.5" stroke={HAIR_STRONG} strokeWidth="1.5" />
      <rect x="80" y="70.5" width="34" height="5" rx="2.5" fill={HAIR_STRONG} stroke="none" />

      {/* The nested team is the one carrying the accent. A tree where every node
          is styled the same is a taxonomy; one highlighted node makes it "you are
          here", which is the sentence the page wants. Its border is the heaviest
          line in the scene, which is what makes it the highlighted one rather than
          just the blue one. */}
      <rect
        x="86"
        y="90"
        width="84"
        height="22"
        rx="7"
        fill={tint("blue", 0.14)}
        stroke={solid("blue")}
        strokeWidth="2"
      />
      <circle cx="98" cy="101" r="4.5" fill={solid("blue")} stroke="none" />
      <rect x="110" y="98" width="34" height="6" rx="3" fill={tint("blue", 0.5)} stroke="none" />

      <rect
        x="56"
        y="118"
        width="84"
        height="22"
        rx="7"
        fill={SURFACE_ELEVATED}
        stroke={HAIR_STRONG}
        strokeWidth="1.5"
      />
      <circle cx="68" cy="129" r="4.5" stroke={HAIR_STRONG} strokeWidth="1.5" />
      <rect x="80" y="126.5" width="26" height="5" rx="2.5" fill={HAIR_STRONG} stroke="none" />
    </g>

    {spark(180, 124, 4.5, tint("blue", 0.4))}
    {spark(16, 66, 3.5, tint("blue", 0.35))}
  </>
);

export const NodeTreeIllustration = createIllustration("NodeTreeIllustration", SCENE);
