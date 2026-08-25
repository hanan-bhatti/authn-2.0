import { createIcon, washed, weighted } from "./createIcon.js";

/**
 * Authn Platform — Interface icons
 * File: packages/ui/src/icons/ui.tsx
 *
 * The verbs and the controls: open, close, confirm, add, copy, leave, destroy.
 * These carry no domain, so most of them take blue in the coloured cut simply
 * because it is the quietest accent on this canvas. The three that do carry
 * meaning keep it — yellow warns, red destroys, orange ends a session — and those
 * three are the only ones whose hue a reader should ever have to notice.
 */

const MENU_ART = (
  <>
    <path d="M3.75 6.75h16.5" />
    <path d="M3.75 12h16.5" />
    <path d="M3.75 17.25h16.5" />
  </>
);

/** Opens the navigation drawer below the sidebar's breakpoint. */
export const MenuIcon = createIcon("MenuIcon", (variant) => {
  if (variant === "filled") return weighted(MENU_ART);
  if (variant === "color") return washed("blue", MENU_ART);
  return MENU_ART;
});

const CLOSE_ART = (
  <>
    <path d="m6.25 6.25 11.5 11.5" />
    <path d="M17.75 6.25 6.25 17.75" />
  </>
);

/**
 * Dismisses a drawer, a dialog or a toast.
 *
 * The arms stop at 6.25 and 17.75 rather than spanning the live area. A cross
 * drawn corner to corner is optically larger than every other icon in the set,
 * because a diagonal covers more distance inside the same box than an upright
 * shape does.
 */
export const CloseIcon = createIcon("CloseIcon", (variant) => {
  if (variant === "filled") return weighted(CLOSE_ART);
  if (variant === "color") return washed("blue", CLOSE_ART);
  return CLOSE_ART;
});

const CHECK_ART = <path d="m4.75 12.5 4.75 4.75 9.75-10.5" />;

/** Confirmation — a met requirement, a saved change, a selected option. */
export const CheckIcon = createIcon("CheckIcon", (variant) => {
  if (variant === "filled") return weighted(CHECK_ART);
  if (variant === "color") return washed("green", CHECK_ART);
  return CHECK_ART;
});

const PLUS_ART = (
  <>
    <path d="M12 4.75v14.5" />
    <path d="M4.75 12h14.5" />
  </>
);

/** Adding one of something — a passkey, an organisation, a recovery address. */
export const PlusIcon = createIcon("PlusIcon", (variant) => {
  if (variant === "filled") return weighted(PLUS_ART);
  if (variant === "color") return washed("blue", PLUS_ART);
  return PLUS_ART;
});

const ALERT_ART = (
  <>
    <path d="M10.3 4.1 2.85 17.1a2 2 0 0 0 1.73 3h14.84a2 2 0 0 0 1.73-3L13.7 4.1a2 2 0 0 0-3.4 0Z" />
    <path d="M12 9.5v4" />
    <circle cx="12" cy="16.7" r="0.95" fill="currentColor" stroke="none" />
  </>
);

/**
 * Something needs attention but nothing has broken.
 *
 * The dot is a filled circle rather than a zero-length round-capped stroke. Both
 * render as a disc, but a stroked one scales with `strokeWidth` — so the day the
 * set's weight changes, every warning icon's dot changes size with it while the
 * bar above it does not.
 */
export const AlertIcon = createIcon("AlertIcon", (variant) => {
  if (variant === "filled") {
    return (
      <path
        fillRule="evenodd"
        d="M10.3 4.1 2.85 17.1a2 2 0 0 0 1.73 3h14.84a2 2 0 0 0 1.73-3L13.7 4.1a2 2 0 0 0-3.4 0ZM13 9.5a1 1 0 1 0-2 0v4a1 1 0 1 0 2 0v-4Zm-1 6.05a1.15 1.15 0 1 0 0 2.3 1.15 1.15 0 0 0 0-2.3Z"
      />
    );
  }
  if (variant === "color") return washed("yellow", ALERT_ART);
  return ALERT_ART;
});

const INFO_ART = (
  <>
    <circle cx="12" cy="12" r="8.25" />
    <path d="M12 11.25v5" />
    <circle cx="12" cy="8.1" r="0.95" fill="currentColor" stroke="none" />
  </>
);

/**
 * An explanation is available — the trigger for a tooltip carrying a rule, a
 * limit, or what a control is about to do.
 *
 * A lowercase "i" rather than a question mark. A question mark asks the reader
 * whether they need help, which is a question about them; an "i" says there is
 * more here, which is a statement about the page.
 */
export const InfoIcon = createIcon("InfoIcon", (variant) => {
  if (variant === "filled") {
    return (
      <path
        fillRule="evenodd"
        d="M12 2.75a9.25 9.25 0 1 0 0 18.5 9.25 9.25 0 0 0 0-18.5ZM13 11.25a1 1 0 1 0-2 0v5a1 1 0 1 0 2 0v-5ZM12 7.15a1.15 1.15 0 1 0 0 2.3 1.15 1.15 0 0 0 0-2.3Z"
      />
    );
  }
  if (variant === "color") return washed("blue", INFO_ART);
  return INFO_ART;
});

const TRASH_ART = (
  <>
    <path d="M3.75 6.75h16.5" />
    <path d="M9.25 6.75V4.9a1.65 1.65 0 0 1 1.65-1.65h2.2a1.65 1.65 0 0 1 1.65 1.65v1.85" />
    <path d="m5.75 6.75.85 12.6a2 2 0 0 0 2 1.9h6.8a2 2 0 0 0 2-1.9l.85-12.6" />
    <path d="M10.25 10.75v6" />
    <path d="M13.75 10.75v6" />
  </>
);

/**
 * Destroying something — revoking a key, deleting an account.
 *
 * The lid stays a stroke in every cut. Filling it merges it with the can and the
 * icon becomes an urn; the gap between lid and body is what says the thing is
 * still openable, which is the difference between "delete" and "deleted".
 */
export const TrashIcon = createIcon("TrashIcon", (variant) => {
  if (variant === "filled") {
    return (
      <>
        <g fill="none" stroke="currentColor" strokeWidth={1.5}>
          <path d="M3.75 6.75h16.5" />
          <path d="M9.25 6.75V4.9a1.65 1.65 0 0 1 1.65-1.65h2.2a1.65 1.65 0 0 1 1.65 1.65v1.85" />
        </g>
        <path
          fillRule="evenodd"
          d="M5.75 8h12.5l-.8 11.35a2 2 0 0 1-2 1.9h-6.9a2 2 0 0 1-2-1.9L5.75 8Zm4.5 2.75a.9.9 0 0 0-1.8 0v6a.9.9 0 0 0 1.8 0v-6Zm5.3 0a.9.9 0 0 0-1.8 0v6a.9.9 0 0 0 1.8 0v-6Z"
        />
      </>
    );
  }
  if (variant === "color") return washed("red", TRASH_ART);
  return TRASH_ART;
});

const LOG_OUT_ART = (
  <>
    <path d="M9.75 20.25H6.25a2.5 2.5 0 0 1-2.5-2.5V6.25a2.5 2.5 0 0 1 2.5-2.5h3.5" />
    <path d="m15.5 8.25 3.75 3.75-3.75 3.75" />
    <path d="M19.25 12H9" />
  </>
);

/** Signing out here, or revoking a session somewhere else. */
export const LogOutIcon = createIcon("LogOutIcon", (variant) => {
  if (variant === "filled") return weighted(LOG_OUT_ART);
  if (variant === "color") return washed("orange", LOG_OUT_ART);
  return LOG_OUT_ART;
});

const COPY_ART = (
  <>
    <rect x="8.75" y="8.75" width="12.5" height="12.5" rx="2.5" />
    <path d="M15.25 8.75V5.25a2.5 2.5 0 0 0-2.5-2.5h-7.5a2.5 2.5 0 0 0-2.5 2.5v7.5a2.5 2.5 0 0 0 2.5 2.5h3.5" />
  </>
);

/**
 * Copying a value — a recovery code, an organisation id.
 *
 * The filled cut fills the front sheet only. Filling both leaves one blob with a
 * step in it, and the step is not enough to say there are two sheets.
 */
export const CopyIcon = createIcon("CopyIcon", (variant) => {
  if (variant === "filled") {
    return (
      <>
        <path
          d="M15.25 8.75V5.25a2.5 2.5 0 0 0-2.5-2.5h-7.5a2.5 2.5 0 0 0-2.5 2.5v7.5a2.5 2.5 0 0 0 2.5 2.5h3.5"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
        />
        <rect x="8.75" y="8.75" width="12.5" height="12.5" rx="2.5" />
      </>
    );
  }
  if (variant === "color") return washed("blue", COPY_ART);
  return COPY_ART;
});

const EXTERNAL_LINK_ART = (
  <>
    <path d="M13.75 4.25h6v6" />
    <path d="M19.75 4.25 11.5 12.5" />
    <path d="M18.5 14.5v3.25a2.5 2.5 0 0 1-2.5 2.5H6.25a2.5 2.5 0 0 1-2.5-2.5V8a2.5 2.5 0 0 1 2.5-2.5H9.5" />
  </>
);

/** A link that leaves the account app — documentation, a provider's own settings. */
export const ExternalLinkIcon = createIcon("ExternalLinkIcon", (variant) => {
  if (variant === "filled") return weighted(EXTERNAL_LINK_ART);
  if (variant === "color") return washed("blue", EXTERNAL_LINK_ART);
  return EXTERNAL_LINK_ART;
});

const SETTINGS_ART = (
  <>
    <path d="M3.75 7.25h4.5" />
    <circle cx="10.75" cy="7.25" r="2.5" />
    <path d="M13.25 7.25h7" />
    <path d="M3.75 16.75h7" />
    <circle cx="13.25" cy="16.75" r="2.5" />
    <path d="M15.75 16.75h4.5" />
  </>
);

/**
 * Preferences.
 *
 * Two sliders rather than a cog. A cog needs eight teeth and a hub inside 20
 * units, which is more contour than any other icon in this set carries, and it is
 * the one icon that visibly degrades first at 16px. Sliders also say the truer
 * thing: these pages set values, they do not configure machinery.
 */
export const SettingsIcon = createIcon("SettingsIcon", (variant) => {
  if (variant === "filled") {
    return (
      <>
        <g fill="none" stroke="currentColor" strokeWidth={1.5}>
          <path d="M3.75 7.25h16.5" />
          <path d="M3.75 16.75h16.5" />
        </g>
        <circle cx="10.75" cy="7.25" r="2.75" />
        <circle cx="13.25" cy="16.75" r="2.75" />
      </>
    );
  }
  if (variant === "color") return washed("blue", SETTINGS_ART);
  return SETTINGS_ART;
});

const SEARCH_ART = (
  <>
    <circle cx="10.75" cy="10.75" r="7" />
    <path d="m15.7 15.7 4.55 4.55" />
  </>
);

/** Filtering a long list — sessions, members, audit entries. */
export const SearchIcon = createIcon("SearchIcon", (variant) => {
  if (variant === "filled") {
    return (
      <>
        <path
          fillRule="evenodd"
          d="M10.75 3.75a7 7 0 1 0 0 14 7 7 0 0 0 0-14Zm0 2a5 5 0 1 1 0 10 5 5 0 0 1 0-10Z"
        />
        <path
          d="m15.7 15.7 4.55 4.55"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          strokeLinecap="round"
        />
      </>
    );
  }
  if (variant === "color") return washed("blue", SEARCH_ART);
  return SEARCH_ART;
});

/**
 * A row's own menu.
 *
 * The only icon in the set with no line cut, because it has no line to draw. All
 * three variants are discs; the filled one is simply larger, which is the one
 * honest way to show this icon as active.
 */
export const DotsIcon = createIcon("DotsIcon", (variant) => {
  const r = variant === "filled" ? 1.9 : 1.6;
  const discs = (
    <g fill="currentColor" stroke="none">
      <circle cx="12" cy="5.25" r={r} />
      <circle cx="12" cy="12" r={r} />
      <circle cx="12" cy="18.75" r={r} />
    </g>
  );

  if (variant === "color") return washed("blue", discs);
  return discs;
});
