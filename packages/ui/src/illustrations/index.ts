/**
 * Authn Platform — Illustration barrel
 * File: packages/ui/src/illustrations/index.ts
 *
 * The factory and its props type are public; the drawing vocabulary — `halo`,
 * `plinth`, `spark`, `solid` and the surface constants — is not. Same reasoning as
 * the icon barrel: those are the names the scenes in this directory are composed
 * from, and they are ordinary enough that an application importing `@authn/ui`
 * could plausibly want them for something of its own.
 *
 * A consumer building an illustration of their own imports `createIllustration`
 * plus `tint` and `ACCENT_SOLID` from the package root, which is enough to draw a
 * scene that matches this set without reaching into it.
 */

export {
  createIllustration,
  type IllustrationComponent,
  type IllustrationProps,
  type IllustrationScene,
} from "./createIllustration.js";

export * from "./IdCard.js";
export * from "./ShieldKey.js";
export * from "./Devices.js";
export * from "./Rings.js";
export * from "./Buoy.js";
export * from "./NodeTree.js";
export * from "./Shredder.js";
export * from "./OpenBox.js";
