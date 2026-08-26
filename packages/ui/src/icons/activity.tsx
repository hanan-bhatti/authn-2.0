import { createIcon, washed, weighted } from "./createIcon.js";

/**
 * Authn Platform — Activity icons
 * File: packages/ui/src/icons/activity.tsx
 *
 * Where and when the account is being used: the devices holding a session, the
 * place a sign-in came from, the age of a token, the log itself. Orange, which in
 * this product means a live session or a device rather than a warning — the
 * warning hue is yellow, and keeping them apart is what lets a list of sessions
 * be coloured without reading as a list of problems.
 */

const MONITOR_ART = (
  <>
    <rect x="2.75" y="3.75" width="18.5" height="12.5" rx="2.5" />
    <path d="M12 16.25v4" />
    <path d="M8.25 20.25h7.5" />
  </>
);

/**
 * A desktop session.
 *
 * The filled cut is three separate shapes rather than one traced silhouette. The
 * neck is two units wide, and folding it into the screen's outline would put two
 * near-coincident vertical edges in one path — the shape stays correct and the
 * rasteriser thins it unpredictably between 16px and 20px.
 */
export const MonitorIcon = createIcon("MonitorIcon", (variant) => {
  if (variant === "filled") {
    return (
      <>
        <rect x="2.75" y="3.75" width="18.5" height="12.5" rx="2.5" />
        <rect x="11" y="16.25" width="2" height="3.5" />
        <rect x="7.5" y="19" width="9" height="1.75" rx="0.875" />
      </>
    );
  }
  if (variant === "color") return washed("orange", MONITOR_ART);
  return MONITOR_ART;
});

const SMARTPHONE_ART = (
  <>
    <rect x="6.25" y="2.75" width="11.5" height="18.5" rx="2.75" />
    <path d="M10.5 5.75h3" />
  </>
);

/**
 * A mobile session.
 *
 * Marked at the top by an earpiece slot, where the phone in `security` is marked
 * at the bottom by a home bar. Two icons in one product that mean different
 * things — a device holding a session, and a number that receives a code — have
 * to be told apart at a glance, and the accent alone does not do it in a
 * monochrome list.
 */
export const SmartphoneIcon = createIcon("SmartphoneIcon", (variant) => {
  if (variant === "filled") {
    return (
      <path
        fillRule="evenodd"
        d="M9 2.75A2.75 2.75 0 0 0 6.25 5.5v13A2.75 2.75 0 0 0 9 21.25h6a2.75 2.75 0 0 0 2.75-2.75v-13A2.75 2.75 0 0 0 15 2.75H9Zm1.5 2.25a.75.75 0 0 0 0 1.5h3a.75.75 0 0 0 0-1.5h-3Z"
      />
    );
  }
  if (variant === "color") return washed("orange", SMARTPHONE_ART);
  return SMARTPHONE_ART;
});

const TABLET_ART = (
  <>
    <rect x="3.75" y="2.75" width="16.5" height="18.5" rx="2.75" />
    <circle cx="12" cy="17.65" r="1.05" fill="currentColor" stroke="none" />
  </>
);

/**
 * A tablet session.
 *
 * The engine reports three form factors and this is the third. Without it a
 * tablet is drawn as a phone, and a reader auditing their devices sees a phone
 * they do not own.
 *
 * Told apart from the phone by proportion — 16.5 units wide against 11.5 — and by
 * a home dot at the bottom. Proportion alone is legible with the phone beside it
 * and ambiguous without, and a session list shows whichever devices the account
 * happens to have.
 */
export const TabletIcon = createIcon("TabletIcon", (variant) => {
  if (variant === "filled") {
    return (
      <path
        fillRule="evenodd"
        d="M6.5 2.75A2.75 2.75 0 0 0 3.75 5.5v13a2.75 2.75 0 0 0 2.75 2.75h11a2.75 2.75 0 0 0 2.75-2.75v-13A2.75 2.75 0 0 0 17.5 2.75h-11Zm5.5 13.85a1.05 1.05 0 1 0 0 2.1 1.05 1.05 0 0 0 0-2.1Z"
      />
    );
  }
  if (variant === "color") return washed("orange", TABLET_ART);
  return TABLET_ART;
});

const CLOCK_ART = (
  <>
    <circle cx="12" cy="12" r="9.25" />
    <path d="M12 6.75V12l3.75 2.25" />
  </>
);

/** How long ago, or how long for — a last-seen time, a token lifetime. */
export const ClockIcon = createIcon("ClockIcon", (variant) => {
  if (variant === "filled") {
    return (
      <path
        fillRule="evenodd"
        d="M12 2.75a9.25 9.25 0 1 0 0 18.5 9.25 9.25 0 0 0 0-18.5Zm-.9 4.75a.9.9 0 0 1 1.8 0v3.99l2.96 1.78a.9.9 0 0 1-.92 1.54l-3.4-2.04a.9.9 0 0 1-.44-.78V7.5Z"
      />
    );
  }
  if (variant === "color") return washed("orange", CLOCK_ART);
  return CLOCK_ART;
});

const MAP_PIN_ART = (
  <>
    <path d="M12 21.5s7.25-5.6 7.25-11.25a7.25 7.25 0 1 0-14.5 0C4.75 15.9 12 21.5 12 21.5Z" />
    <circle cx="12" cy="10.25" r="2.75" />
  </>
);

/**
 * Where a session signed in from.
 *
 * The aperture stays a hole in the filled cut. A solid teardrop is a map marker
 * on a map, where its position carries the meaning; in a list it needs the ring
 * to read as a place rather than as a generic blob.
 */
export const MapPinIcon = createIcon("MapPinIcon", (variant) => {
  if (variant === "filled") {
    return (
      <path
        fillRule="evenodd"
        d="M4.75 10.25a7.25 7.25 0 1 1 14.5 0c0 2.9-1.83 5.6-3.63 7.5a24 24 0 0 1-3.07 2.83 1.02 1.02 0 0 1-1.1 0 24 24 0 0 1-3.07-2.83c-1.8-1.9-3.63-4.6-3.63-7.5Zm7.25-2.75a2.75 2.75 0 1 0 0 5.5 2.75 2.75 0 0 0 0-5.5Z"
      />
    );
  }
  if (variant === "color") return washed("orange", MAP_PIN_ART);
  return MAP_PIN_ART;
});

const PULSE_ART = <path d="M2.75 12.5h3.1l2.05-6.25 3.35 12 2.35-8 1.6 2.25h5.05" />;

/**
 * The activity log.
 *
 * One tall spike among smaller ones, off-centre. A symmetric trace reads as
 * decoration; the asymmetry is what makes it read as a recording of something
 * that happened.
 */
export const PulseIcon = createIcon("PulseIcon", (variant) => {
  if (variant === "filled") return weighted(PULSE_ART);
  if (variant === "color") return washed("orange", PULSE_ART);
  return PULSE_ART;
});
