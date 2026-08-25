/**
 * Authn Platform — Icon barrel
 * File: packages/ui/src/icons/index.ts
 *
 * The primitive is re-exported by name rather than with a star. `wash`, `tinted`,
 * `washed` and `weighted` are the internal vocabulary the icon modules are drawn
 * with, and they are names a consuming application could plausibly want for
 * something of its own; keeping them off the package's public surface means
 * importing `@authn/ui` cannot collide with them.
 */

export {
  createIcon,
  ACCENT_WASH,
  type IconAccent,
  type IconArt,
  type IconComponent,
  type IconProps,
  type IconVariant,
} from "./createIcon.js";

export * from "./identity.js";
export * from "./security.js";
export * from "./activity.js";
export * from "./structure.js";
export * from "./ui.js";
