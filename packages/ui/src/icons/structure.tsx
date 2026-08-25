import { createIcon, washed, weighted } from "./createIcon.js";

/**
 * Authn Platform — Structure icons
 * File: packages/ui/src/icons/structure.tsx
 *
 * What the account belongs to and what it is attached to: organisations, the
 * people in them, the third-party accounts linked to it, and the way back in when
 * everything else is lost. Blue for the structural ones, since they are all
 * facets of identity; yellow for the buoy, because recovery is the thing the page
 * wants set up before it is needed.
 */

const BUILDING_ART = (
  <>
    <path d="M4.75 21.25V5.25a2.5 2.5 0 0 1 2.5-2.5h6.5a2.5 2.5 0 0 1 2.5 2.5v16" />
    <path d="M16.25 9.75h2.5a2.5 2.5 0 0 1 2.5 2.5v9" />
    <path d="M2.75 21.25h18.5" />
    <path d="M8.25 7.25h4" />
    <path d="M8.25 11.25h4" />
    <path d="M8.25 15.25h4" />
  </>
);

/**
 * An organisation.
 *
 * A tall block with a lower annex rather than a single slab. The step in the
 * roofline is the only thing distinguishing a building from a window or a card at
 * this size, and three window courses give it a storey count without becoming a
 * grid.
 */
export const BuildingIcon = createIcon("BuildingIcon", (variant) => {
  if (variant === "filled") {
    return (
      <>
        <path
          fillRule="evenodd"
          d="M4.75 5.25a2.5 2.5 0 0 1 2.5-2.5h6.5a2.5 2.5 0 0 1 2.5 2.5v16H4.75v-16Zm3.5 1.1a.9.9 0 0 0 0 1.8h4a.9.9 0 0 0 0-1.8h-4Zm0 4a.9.9 0 0 0 0 1.8h4a.9.9 0 0 0 0-1.8h-4Zm0 4a.9.9 0 0 0 0 1.8h4a.9.9 0 0 0 0-1.8h-4Z"
        />
        <path d="M17.25 9.75h1.5a2.5 2.5 0 0 1 2.5 2.5v9h-4V9.75Z" />
        <rect x="2.75" y="20.35" width="18.5" height="1.6" rx="0.8" />
      </>
    );
  }
  if (variant === "color") return washed("blue", BUILDING_ART);
  return BUILDING_ART;
});

const USERS_ART = (
  <>
    <circle cx="9.5" cy="8.25" r="3.5" />
    <path d="M3.25 19.75c0-3.45 2.8-5.75 6.25-5.75s6.25 2.3 6.25 5.75" />
    <path d="M16.5 5.1a3.5 3.5 0 0 1 0 6.3" />
    <path d="M18 14.6c1.85.78 3.05 2.28 3.05 4.15" />
  </>
);

/**
 * The members of an organisation.
 *
 * The second person is half a head and half a shoulder line, clipped by the
 * first. Drawing two whole people forces both down to about two-thirds scale to
 * fit, and a shrunken head stops reading as a person before it stops fitting.
 */
export const UsersIcon = createIcon("UsersIcon", (variant) => {
  if (variant === "filled") {
    return (
      <>
        <circle cx="9.25" cy="8" r="3.75" />
        <path d="M9.25 13.75c-3.6 0-6.5 2.35-6.5 5.6 0 .55.4.9.95.9h11.1c.55 0 .95-.35.95-.9 0-3.25-2.9-5.6-6.5-5.6Z" />
        <circle cx="17.75" cy="8.75" r="3" />
        <path d="M17.75 13.5c-.76 0-1.48.11-2.14.32 1.62 1.33 2.64 3.26 2.64 5.58h2.85c.55 0 .9-.35.9-.9 0-2.8-1.9-5-4.25-5Z" />
      </>
    );
  }
  if (variant === "color") return washed("blue", USERS_ART);
  return USERS_ART;
});

const LINK_ART = (
  <>
    <path d="M9.75 14.25 14.25 9.75" />
    <path d="M13 7l1.5-1.5a4.25 4.25 0 0 1 6 6L19 13" />
    <path d="M11 17l-1.5 1.5a4.25 4.25 0 0 1-6-6L5 11" />
  </>
);

/**
 * A linked third-party account.
 *
 * Two open hooks with a bar between them, not a closed chain. Closing both loops
 * puts four curves and two crossings inside 20 units, and the crossings are the
 * first thing to blur; the open form keeps the "these two are joined" reading with
 * half the ink.
 */
export const LinkIcon = createIcon("LinkIcon", (variant) => {
  if (variant === "filled") return weighted(LINK_ART);
  if (variant === "color") return washed("blue", LINK_ART);
  return LINK_ART;
});

const LIFE_BUOY_ART = (
  <>
    <circle cx="12" cy="12" r="9.25" />
    <circle cx="12" cy="12" r="4" />
    <path d="m5.45 5.45 3.72 3.72" />
    <path d="m14.83 14.83 3.72 3.72" />
    <path d="m18.55 5.45-3.72 3.72" />
    <path d="m9.17 14.83-3.72 3.72" />
  </>
);

/**
 * Account recovery.
 *
 * Filled by weight. A flooded buoy is a donut, because the spokes sit inside the
 * ring that the fill covers — the four gaps are what make it a buoy, and holes
 * cut from a ring are four arc segments that have to be hand-fitted and will
 * still drift out of line with the strokes in the other cuts.
 */
export const LifeBuoyIcon = createIcon("LifeBuoyIcon", (variant) => {
  if (variant === "filled") return weighted(LIFE_BUOY_ART);
  if (variant === "color") return washed("yellow", LIFE_BUOY_ART);
  return LIFE_BUOY_ART;
});
