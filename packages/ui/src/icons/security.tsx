import { createIcon, washed, weighted } from "./createIcon.js";

/**
 * Authn Platform — Security icons
 * File: packages/ui/src/icons/security.tsx
 *
 * What protects the account: the password, the second factors, the passkeys, the
 * recovery codes. Green throughout, because in this product green means "a
 * protection that is switched on" — so the coloured cut of any of these reads as
 * enabled before the shape is read.
 */

/**
 * The shield silhouette, shared by every cut of every shield icon.
 *
 * The flanks are straight and only the base curves. A shield curved along its
 * whole outline loses its shoulders below about 20px and starts to read as a
 * pointed egg; the straight flanks keep the corners the eye uses to identify it.
 */
const SHIELD_PATH =
  "M12 2.75 4.5 5.6v5.72c0 4.2 2.96 8.14 7.5 9.93 4.54-1.79 7.5-5.73 7.5-9.93V5.6L12 2.75Z";

/**
 * A tick as a closed outline rather than a stroke.
 *
 * A stroked tick cannot be a hole — only a closed subpath can — and a filled
 * shield needs the tick to be a hole, since drawn in `currentColor` it vanishes
 * into the shield and drawn in the background colour it seams as soon as the
 * icon sits on a card. The corners are mitred rather than rounded because at
 * 16px a 0.85-unit round join eats the point of the tick.
 */
const TICK_HOLE = "M9.3 11.3 10.98 12.98 14.88 8.77 16.12 9.93 11.03 15.42 8.1 12.5Z";

const SHIELD_ART = <path d={SHIELD_PATH} />;

/** Security as a section. */
export const ShieldIcon = createIcon("ShieldIcon", (variant) => {
  if (variant === "color") return washed("green", SHIELD_ART);
  return SHIELD_ART;
});

const SHIELD_CHECK_ART = (
  <>
    <path d={SHIELD_PATH} />
    <path d="m8.75 11.85 2.35 2.35 4.15-4.6" />
  </>
);

/** A protection that is confirmed on — two-factor enabled, a verified address. */
export const ShieldCheckIcon = createIcon("ShieldCheckIcon", (variant) => {
  if (variant === "filled") return <path fillRule="evenodd" d={`${SHIELD_PATH}${TICK_HOLE}`} />;
  if (variant === "color") return washed("green", SHIELD_CHECK_ART);
  return SHIELD_CHECK_ART;
});

const KEY_ART = (
  <>
    <circle cx="8" cy="15.75" r="5" />
    <path d="M11.54 12.21 20.5 3.25" />
    <path d="m15.75 8 2.75 2.75 2.5-2.5-2.75-2.75" />
  </>
);

/**
 * A password.
 *
 * The bow sits low-left and the shaft runs to the top-right corner, which buys
 * the longest diagonal the box allows — a key drawn horizontally has to shrink
 * its bow to fit the shaft, and the bow is the part that identifies it.
 */
export const KeyIcon = createIcon("KeyIcon", (variant) => {
  if (variant === "filled") return weighted(KEY_ART);
  if (variant === "color") return washed("green", KEY_ART);
  return KEY_ART;
});

const FINGERPRINT_ART = (
  <>
    <path d="M3.25 16.75V13.5a8.75 8.75 0 0 1 17.5 0v3.75" />
    <path d="M6 19.5V13.5a6 6 0 0 1 12 0v2.75" />
    <path d="M8.5 21V13.5a3.5 3.5 0 0 1 7 0v5.5" />
    <path d="M10.75 13.75a1.25 1.25 0 0 1 2.5 0v6" />
  </>
);

/**
 * A passkey or a biometric unlock.
 *
 * Four nested arches, each with legs of a different length. Equal legs would be
 * geometrically tidier and would read as a diagram of concentric arcs; a
 * fingerprint is recognised by ridges that stop at different heights.
 */
export const FingerprintIcon = createIcon("FingerprintIcon", (variant) => {
  if (variant === "filled") return weighted(FINGERPRINT_ART);
  if (variant === "color") return washed("green", FINGERPRINT_ART);
  return FINGERPRINT_ART;
});

const QR_CODE_ART = (
  <>
    <rect x="3.25" y="3.25" width="7" height="7" rx="1.75" />
    <rect x="13.75" y="3.25" width="7" height="7" rx="1.75" />
    <rect x="3.25" y="13.75" width="7" height="7" rx="1.75" />
    <path d="M13.75 13.75h3.25v3.25h-3.25z" />
    <path d="M20.75 13.75v3.5" />
    <path d="M20.75 20.75h-3.5" />
  </>
);

/**
 * Enrolling an authenticator app.
 *
 * Three finder squares and four modules, not a plausible-looking data field. A
 * denser grid is unreadable at 16px and, worse, invites the reader to try to
 * scan it.
 */
export const QrCodeIcon = createIcon("QrCodeIcon", (variant) => {
  if (variant === "filled") return weighted(QR_CODE_ART);
  if (variant === "color") return washed("green", QR_CODE_ART);
  return QR_CODE_ART;
});

const PHONE_ART = (
  <>
    <rect x="6.75" y="2.75" width="10.5" height="18.5" rx="2.5" />
    <path d="M10.75 18.25h2.5" />
  </>
);

/** A phone number as a factor — the destination of an SMS code. */
export const PhoneIcon = createIcon("PhoneIcon", (variant) => {
  if (variant === "filled") {
    return (
      <path
        fillRule="evenodd"
        d="M9.25 2.75a2.5 2.5 0 0 0-2.5 2.5v13.5a2.5 2.5 0 0 0 2.5 2.5h5.5a2.5 2.5 0 0 0 2.5-2.5V5.25a2.5 2.5 0 0 0-2.5-2.5h-5.5Zm1.5 14.5a1 1 0 0 0 0 2h2.5a1 1 0 0 0 0-2h-2.5Z"
      />
    );
  }
  if (variant === "color") return washed("green", PHONE_ART);
  return PHONE_ART;
});

const LOCK_ART = (
  <>
    <rect x="3.75" y="10.25" width="16.5" height="11" rx="2.5" />
    <path d="M7.75 10.25V7.5a4.25 4.25 0 0 1 8.5 0v2.75" />
  </>
);

/**
 * Changing the password.
 *
 * The filled cut keeps the shackle as a stroke and draws it first, so the body
 * overlaps it. A shackle converted to a filled outline would be the only closed
 * loop in the set whose two sides can disagree in width as the icon scales.
 */
export const LockIcon = createIcon("LockIcon", (variant) => {
  if (variant === "filled") {
    return (
      <>
        <path
          d="M7.75 10.75V7.5a4.25 4.25 0 0 1 8.5 0v3.25"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
        />
        <path
          fillRule="evenodd"
          d="M6.25 9.75a2.5 2.5 0 0 0-2.5 2.5v6.5a2.5 2.5 0 0 0 2.5 2.5h11.5a2.5 2.5 0 0 0 2.5-2.5v-6.5a2.5 2.5 0 0 0-2.5-2.5H6.25Zm5.75 3.75a1.5 1.5 0 0 0-.75 2.8v1.45a.75.75 0 0 0 1.5 0V16.3a1.5 1.5 0 0 0-.75-2.8Z"
        />
      </>
    );
  }
  if (variant === "color") return washed("green", LOCK_ART);
  return LOCK_ART;
});

const BACKUP_CODES_ART = (
  <>
    <rect x="2.75" y="4.75" width="18.5" height="14.5" rx="2.5" />
    <path d="M6.25 10h3.25" />
    <path d="M12.25 10h5.5" />
    <path d="M6.25 14h5.5" />
    <path d="M14.25 14h3.5" />
  </>
);

/**
 * Recovery codes.
 *
 * The rules are deliberately uneven in length. Four equal bars read as a table;
 * unequal ones read as a printed list of codes, which is what the page hands out.
 */
export const BackupCodesIcon = createIcon("BackupCodesIcon", (variant) => {
  if (variant === "filled") {
    return (
      <path
        fillRule="evenodd"
        d="M5.25 4.75a2.5 2.5 0 0 0-2.5 2.5v9.5a2.5 2.5 0 0 0 2.5 2.5h13.5a2.5 2.5 0 0 0 2.5-2.5v-9.5a2.5 2.5 0 0 0-2.5-2.5H5.25Zm1 4.5a.75.75 0 0 0 0 1.5h3.25a.75.75 0 0 0 0-1.5H6.25Zm6 0a.75.75 0 0 0 0 1.5h5.5a.75.75 0 0 0 0-1.5h-5.5Zm-6 4a.75.75 0 0 0 0 1.5h5.5a.75.75 0 0 0 0-1.5H6.25Zm8 0a.75.75 0 0 0 0 1.5h3.5a.75.75 0 0 0 0-1.5h-3.5Z"
      />
    );
  }
  if (variant === "color") return washed("green", BACKUP_CODES_ART);
  return BACKUP_CODES_ART;
});
