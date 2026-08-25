import type { Metadata } from "next";
import type { ReactNode } from "react";
import { notFound } from "next/navigation";
import {
  BackupCodesIcon,
  BuoyIllustration,
  DevicesIllustration,
  FingerprintIcon,
  IdCardIllustration,
  NodeTreeIllustration,
  OpenBoxIllustration,
  QrCodeIcon,
  RingsIllustration,
  ShieldKeyIllustration,
  ShredderIllustration,
  SmartphoneIcon,
  type IconProps,
  type IllustrationProps,
} from "@authn/ui";

/**
 * Authn Platform — Illustration gallery
 * File: apps/web-account/src/app/dev/illustrations/page.tsx
 *
 * Three checks the scene files cannot make on their own.
 *
 * 1. At 240 and at 150 side by side, because an illustration whose interior detail
 *    closes up at the smaller size cannot be used in a card header.
 * 2. On `surface-card` as well as on the canvas, which is where a shape filled with
 *    a background colour instead of being left as a hole shows its seam.
 * 3. All eight in one column, which is the only way to see whether they share a
 *    horizon, a stroke weight and a light direction — the things that make eight
 *    drawings a set.
 *
 * Development only. `NODE_ENV` is replaced at build time, so the production bundle
 * contains a route that does nothing but call notFound().
 */

export const metadata: Metadata = {
  title: "Illustration gallery",
  robots: { index: false, follow: false },
};

type IllustrationComponent = (props: IllustrationProps) => ReactNode;

interface Scene {
  name: string;
  page: string;
  accent: string;
  component: IllustrationComponent;
}

const SCENES: readonly Scene[] = [
  { name: "IdCard", page: "Profile", accent: "blue", component: IdCardIllustration },
  { name: "ShieldKey", page: "Security", accent: "green", component: ShieldKeyIllustration },
  { name: "Devices", page: "Sessions", accent: "orange", component: DevicesIllustration },
  { name: "Rings", page: "Connected accounts", accent: "blue + green", component: RingsIllustration },
  { name: "Buoy", page: "Recovery", accent: "yellow", component: BuoyIllustration },
  { name: "NodeTree", page: "Organizations", accent: "blue", component: NodeTreeIllustration },
  { name: "Shredder", page: "Danger zone", accent: "red", component: ShredderIllustration },
  { name: "OpenBox", page: "Empty states", accent: "blue", component: OpenBoxIllustration },
];

interface Method {
  label: string;
  icon: (props: IconProps) => ReactNode;
  state: "on" | "off";
}

const METHODS: readonly Method[] = [
  { label: "Authenticator app", icon: QrCodeIcon, state: "on" },
  { label: "Passkey", icon: FingerprintIcon, state: "on" },
  { label: "Text message", icon: SmartphoneIcon, state: "off" },
  { label: "Recovery codes", icon: BackupCodesIcon, state: "off" },
];

export default function IllustrationGalleryPage(): ReactNode {
  if (process.env.NODE_ENV !== "development") notFound();

  return (
    <main className="mx-auto flex max-w-page flex-col gap-xxxl px-lg py-xxl sm:px-xl">
      <header className="flex flex-col gap-sm">
        <h1 className="font-display text-display-lg text-ink">Illustrations</h1>
        <p className="max-w-broad text-body-sm text-charcoal">
          One scene per page, 200×160 units, decorative. Left is 240px on the canvas,
          middle is 240px on a card, right is 150px — the smallest size any of these
          should be asked to hold.
        </p>
      </header>

      {SCENES.map(({ name, page, accent, component: Art }) => (
        <section key={name} className="flex flex-col gap-lg">
          <div className="flex flex-wrap items-baseline gap-md border-b border-hairline-strong pb-sm">
            <h2 className="font-display text-heading-md text-ink">{page}</h2>
            <span className="font-mono text-caption text-ash">
              {name} · {accent}
            </span>
          </div>

          <div className="flex flex-wrap items-end gap-xl">
            <Art size={240} />
            <div className="rounded-lg border border-hairline-strong bg-surface-card p-lg">
              <Art size={240} />
            </div>
            <Art size={150} />
          </div>
        </section>
      ))}

      <section className="flex flex-col gap-lg">
        <div className="flex flex-wrap items-baseline gap-md border-b border-hairline-strong pb-sm">
          <h2 className="font-display text-heading-md text-ink">As a set</h2>
          <span className="font-mono text-caption text-ash">
            shared horizon, shared weight, one accent each
          </span>
        </div>

        {/* Tight and small, which is the unflattering view. Anything that is a
            different scale from its neighbours, or floats where the others are
            grounded, shows up here and nowhere else. */}
        <div className="grid grid-cols-2 gap-lg sm:grid-cols-4">
          {SCENES.map(({ name, component: Art }) => (
            <div
              key={name}
              className="flex flex-col items-center gap-sm rounded-lg border border-hairline bg-surface-card py-lg"
            >
              <Art size={140} />
              <span className="font-mono text-caption text-mute">{name}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="flex flex-col gap-lg">
        <div className="flex flex-wrap items-baseline gap-md border-b border-hairline-strong pb-sm">
          <h2 className="font-display text-heading-md text-ink">Against an icon</h2>
          <span className="font-mono text-caption text-ash">
            the two layers doing their own jobs
          </span>
        </div>

        {/* The comparison the whole two-layer split exists for. The illustration
            gives the section a subject; the icons label the rows underneath it. Neither
            could do the other's job, and the point of putting them a paragraph apart is
            to confirm they still look related.

            The rows are deliberately the real thing — 16px glyphs beside 14px labels,
            which is the size an icon actually ships at. Showing an icon at 48px next to
            an illustration proves nothing, because at 48px an icon is a small
            illustration. */}
        <div className="flex max-w-panel flex-col gap-md rounded-lg border border-hairline-strong bg-surface-card p-xl">
          <ShieldKeyIllustration size={200} className="self-center" />
          <h3 className="font-display text-heading-sm text-ink">Two-factor authentication</h3>
          <p className="text-body-sm text-charcoal">
            An app on your phone generates a code. You enter it after your password.
          </p>

          <ul className="flex flex-col divide-y divide-divider-soft border-t border-divider-soft">
            {METHODS.map(({ label, icon: Glyph, state }) => (
              <li key={label} className="flex items-center gap-sm py-sm">
                <Glyph variant={state === "on" ? "filled" : "line"} size={16} className="text-mute" />
                <span className="text-body-sm text-body">{label}</span>
                <span className="ml-auto font-mono text-caption text-ash">{state}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </main>
  );
}
