import { createIcon, washed, weighted } from "./createIcon.js";

/**
 * Authn Platform — Identity icons
 * File: packages/ui/src/icons/identity.tsx
 *
 * Who the account belongs to: the person, the address, the handle, the locale,
 * the portrait. Blue is the accent for all of them, so a coloured icon says
 * "this is about identity" before its shape is read.
 */

const USER_ART = (
  <>
    <circle cx="12" cy="8.25" r="3.75" />
    <path d="M5 20.25c0-3.73 3.13-6.25 7-6.25s7 2.52 7 6.25" />
  </>
);

/**
 * The account holder.
 *
 * The shoulders are an open arc rather than a closed dome: closing it puts a
 * horizontal line under the chin at 16px, which reads as a collar the head is
 * resting on instead of a body continuing past the frame.
 */
export const UserIcon = createIcon("UserIcon", (variant) => {
  if (variant === "filled") {
    return (
      <>
        <circle cx="12" cy="8" r="4" />
        <path d="M12 13.75c-3.99 0-7.25 2.68-7.25 6.4 0 .61.44 1.1 1 1.1h12.5c.56 0 1-.49 1-1.1 0-3.72-3.26-6.4-7.25-6.4Z" />
      </>
    );
  }
  if (variant === "color") return washed("blue", USER_ART);
  return USER_ART;
});

const MAIL_ART = (
  <>
    <rect x="2.75" y="5" width="18.5" height="14" rx="2.75" />
    <path d="M4 7.4 10.6 12a2.45 2.45 0 0 0 2.8 0L20 7.4" />
  </>
);

/**
 * An email address.
 *
 * The filled cut is two shapes with a hairline of canvas between them rather
 * than one envelope with a stroked flap. A solid envelope has nowhere to put the
 * flap — drawn in `currentColor` it disappears into the body, and drawn in the
 * background colour it seams the moment the icon sits on a card instead of the
 * canvas. The gap is the flap, and it survives any surface.
 */
export const MailIcon = createIcon("MailIcon", (variant) => {
  if (variant === "filled") {
    return (
      <>
        <path d="M2.75 8.55v7.7A2.75 2.75 0 0 0 5.5 19h13a2.75 2.75 0 0 0 2.75-2.75v-7.7l-7.83 5.01a2.63 2.63 0 0 1-2.84 0L2.75 8.55Z" />
        <path d="M21.02 6.52A2.75 2.75 0 0 0 18.5 5h-13a2.75 2.75 0 0 0-2.52 1.52l8.15 5.22a1.6 1.6 0 0 0 1.74 0l8.15-5.22Z" />
      </>
    );
  }
  if (variant === "color") return washed("blue", MAIL_ART);
  return MAIL_ART;
});

const AT_SIGN_ART = (
  <>
    <circle cx="12" cy="12" r="3.9" />
    <path d="M15.9 8.1v5.15a2.8 2.8 0 0 0 5.6 0V12a9.5 9.5 0 1 0-3.72 7.54" />
  </>
);

/**
 * A username.
 *
 * Filled by weight rather than by area: the at-sign is a glyph whose meaning is
 * the gap between its ring and its tail, and flooding it leaves a disc with a
 * bite out of the side that no longer reads as an at-sign at any size.
 */
export const AtSignIcon = createIcon("AtSignIcon", (variant) => {
  if (variant === "filled") return weighted(AT_SIGN_ART);
  if (variant === "color") return washed("blue", AT_SIGN_ART);
  return AT_SIGN_ART;
});

const GLOBE_ART = (
  <>
    <circle cx="12" cy="12" r="9.25" />
    <path d="M2.75 12h18.5" />
    <path d="M12 2.75c2.6 2.5 4.05 5.77 4.05 9.25S14.6 18.75 12 21.25c-2.6-2.5-4.05-5.77-4.05-9.25S9.4 5.25 12 2.75Z" />
  </>
);

/**
 * Locale and time zone.
 *
 * One meridian and one equator, not a mesh. Every extra line on a 20-unit sphere
 * lands within a stroke width of its neighbour and the interior turns into a
 * grey patch, which is the failure mode of nearly every globe icon at 16px.
 */
export const GlobeIcon = createIcon("GlobeIcon", (variant) => {
  if (variant === "filled") return weighted(GLOBE_ART);
  if (variant === "color") return washed("blue", GLOBE_ART);
  return GLOBE_ART;
});

const CAMERA_ART = (
  <>
    <rect x="2.75" y="7.75" width="18.5" height="12.5" rx="2.5" />
    <path d="M8.75 7.75l1.2-2.4a1 1 0 0 1 .9-.6h2.3a1 1 0 0 1 .9.6l1.2 2.4" />
    <circle cx="12" cy="14" r="3.4" />
  </>
);

/** Replacing the portrait. The lens stays a hole when filled, so the body reads as a body. */
export const CameraIcon = createIcon("CameraIcon", (variant) => {
  if (variant === "filled") {
    return (
      <path
        fillRule="evenodd"
        d="M9.5 4.75a1.6 1.6 0 0 0-1.43.88L7.3 7.15H5.25a2.5 2.5 0 0 0-2.5 2.5v8.1a2.5 2.5 0 0 0 2.5 2.5h13.5a2.5 2.5 0 0 0 2.5-2.5v-8.1a2.5 2.5 0 0 0-2.5-2.5H16.7l-.77-1.52a1.6 1.6 0 0 0-1.43-.88H9.5Zm2.5 5.9a3.4 3.4 0 1 0 0 6.8 3.4 3.4 0 0 0 0-6.8Z"
      />
    );
  }
  if (variant === "color") return washed("blue", CAMERA_ART);
  return CAMERA_ART;
});
