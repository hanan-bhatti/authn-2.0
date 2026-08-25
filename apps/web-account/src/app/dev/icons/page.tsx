import type { Metadata } from "next";
import type { ReactNode } from "react";
import { notFound } from "next/navigation";
import {
  AlertIcon,
  AtSignIcon,
  BackupCodesIcon,
  BuildingIcon,
  CameraIcon,
  CheckIcon,
  Chevron,
  ClockIcon,
  CloseIcon,
  CopyIcon,
  DotsIcon,
  ExternalLinkIcon,
  FingerprintIcon,
  GlobeIcon,
  KeyIcon,
  LifeBuoyIcon,
  LinkIcon,
  LockIcon,
  LogOutIcon,
  MailIcon,
  MapPinIcon,
  MenuIcon,
  MonitorIcon,
  PhoneIcon,
  PlusIcon,
  PulseIcon,
  QrCodeIcon,
  SearchIcon,
  SettingsIcon,
  ShieldCheckIcon,
  ShieldIcon,
  SmartphoneIcon,
  TrashIcon,
  UserIcon,
  UsersIcon,
  type IconProps,
} from "@authn/ui";

/**
 * Authn Platform — Icon gallery
 * File: apps/web-account/src/app/dev/icons/page.tsx
 *
 * A workbench, not a product page: every icon in every cut at the sizes it will
 * actually be used at, so the set can be judged as a set. An icon that is a
 * quarter-unit heavy or half a unit off-centre is invisible on its own and
 * obvious in a column of its neighbours, which is the whole reason this page
 * exists rather than a screenshot of one icon at a time.
 *
 * Development only. `NODE_ENV` is replaced at build time, so the production
 * bundle contains a route that does nothing but call notFound().
 */

export const metadata: Metadata = {
  title: "Icon gallery",
  robots: { index: false, follow: false },
};

type IconComponent = (props: IconProps) => ReactNode;

interface Group {
  title: string;
  note: string;
  icons: ReadonlyArray<readonly [string, IconComponent]>;
}

const GROUPS: readonly Group[] = [
  {
    title: "Identity",
    note: "blue — who the account belongs to",
    icons: [
      ["User", UserIcon],
      ["Mail", MailIcon],
      ["AtSign", AtSignIcon],
      ["Globe", GlobeIcon],
      ["Camera", CameraIcon],
    ],
  },
  {
    title: "Security",
    note: "green — a protection that is on",
    icons: [
      ["Shield", ShieldIcon],
      ["ShieldCheck", ShieldCheckIcon],
      ["Key", KeyIcon],
      ["Lock", LockIcon],
      ["Fingerprint", FingerprintIcon],
      ["QrCode", QrCodeIcon],
      ["Phone", PhoneIcon],
      ["BackupCodes", BackupCodesIcon],
    ],
  },
  {
    title: "Activity",
    note: "orange — a live session or a device",
    icons: [
      ["Monitor", MonitorIcon],
      ["Smartphone", SmartphoneIcon],
      ["Clock", ClockIcon],
      ["MapPin", MapPinIcon],
      ["Pulse", PulseIcon],
    ],
  },
  {
    title: "Structure",
    note: "blue, and yellow for recovery",
    icons: [
      ["Building", BuildingIcon],
      ["Users", UsersIcon],
      ["Link", LinkIcon],
      ["LifeBuoy", LifeBuoyIcon],
    ],
  },
  {
    title: "Interface",
    note: "neutral, except warn / destroy / leave",
    icons: [
      ["Menu", MenuIcon],
      ["Close", CloseIcon],
      ["Check", CheckIcon],
      ["Plus", PlusIcon],
      ["Alert", AlertIcon],
      ["Trash", TrashIcon],
      ["LogOut", LogOutIcon],
      ["Copy", CopyIcon],
      ["ExternalLink", ExternalLinkIcon],
      ["Settings", SettingsIcon],
      ["Search", SearchIcon],
      ["Dots", DotsIcon],
    ],
  },
];

interface Row {
  label: string;
  icon: IconComponent;
  active?: boolean;
  expandable?: boolean;
}

const ROWS: readonly Row[] = [
  { label: "Profile", icon: UserIcon },
  { label: "Security", icon: ShieldIcon, active: true, expandable: true },
  { label: "Sessions", icon: MonitorIcon },
  { label: "Connected accounts", icon: LinkIcon },
  { label: "Recovery", icon: LifeBuoyIcon },
  { label: "Organizations", icon: BuildingIcon, expandable: true },
  { label: "Delete account", icon: TrashIcon },
];

export default function IconGalleryPage(): ReactNode {
  if (process.env.NODE_ENV !== "development") notFound();

  return (
    <main className="mx-auto flex max-w-page flex-col gap-xxxl px-lg py-xxl sm:px-xl">
      <header className="flex flex-col gap-sm">
        <h1 className="font-display text-display-lg text-ink">Icons</h1>
        <p className="max-w-broad text-body-sm text-charcoal">
          Every cut at the size it is used at. Line at 16 is the sidebar and the
          table row, line at 20 is the section label, filled at 20 is the selected
          item, colour at 36 is a page header.
        </p>
      </header>

      {GROUPS.map((group) => (
        <section key={group.title} className="flex flex-col gap-lg">
          <div className="flex flex-wrap items-baseline gap-md border-b border-hairline-strong pb-sm">
            <h2 className="font-display text-heading-md text-ink">{group.title}</h2>
            <span className="font-mono text-caption text-ash">{group.note}</span>
          </div>

          <div className="grid grid-cols-1 gap-px overflow-hidden rounded-lg border border-hairline bg-hairline sm:grid-cols-2 xl:grid-cols-3">
            {group.icons.map(([name, Icon]) => (
              <div key={name} className="flex items-center gap-lg bg-surface-card p-lg">
                {/* The row order is deliberate: the two line sizes sit next to
                    each other so a weight that only breaks at 16px is visible as
                    a difference rather than having to be remembered. */}
                <div className="flex items-center gap-lg text-ink">
                  <Icon size={16} />
                  <Icon size={20} />
                  <Icon variant="filled" size={20} />
                  <Icon variant="color" size={36} />
                </div>
                <span className="ml-auto font-mono text-caption text-mute">{name}</span>
              </div>
            ))}
          </div>
        </section>
      ))}

      <section className="flex flex-col gap-lg">
        <div className="flex flex-wrap items-baseline gap-md border-b border-hairline-strong pb-sm">
          <h2 className="font-display text-heading-md text-ink">In a column</h2>
          <span className="font-mono text-caption text-ash">
            the real test — one active row, the rest at rest
          </span>
        </div>

        {/* A stand-in for the navigation rather than the navigation itself. The
            set has to hold together as a vertical stack of 16px glyphs beside
            14px labels, and nothing in the grid above reproduces that: optical
            weight is a property of the column, not of the icon. The two rows
            carrying a chevron are the check that matters most, since a
            disclosure arrow is the only glyph that shares a row with another. */}
        <nav className="w-full max-w-compact rounded-lg border border-hairline-strong bg-surface-card p-sm">
          {ROWS.map(({ label, icon: Glyph, active, expandable }) => (
            <span
              key={label}
              className={`flex items-center gap-md rounded-md px-md py-sm text-body-sm ${
                active ? "bg-ink/[0.06] text-ink" : "text-charcoal"
              }`}
            >
              <Glyph variant={active ? "filled" : "line"} size={16} />
              {label}
              {expandable && (
                <Chevron
                  direction={active ? "down" : "right"}
                  size="md"
                  className="ml-auto text-ash"
                />
              )}
            </span>
          ))}
        </nav>
      </section>
    </main>
  );
}
