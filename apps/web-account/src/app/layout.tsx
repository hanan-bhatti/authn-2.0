import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";
import { Providers } from "./providers";
import "./globals.css";

/**
 * Authn Platform — Account app root layout
 * File: apps/web-account/src/app/layout.tsx
 */

export const metadata: Metadata = {
  title: {
    default: "Account — Authn",
    template: "%s — Authn",
  },
  description:
    "Sign in, manage your sessions and devices, and secure your account.",

  // An auth surface has nothing to gain from indexing and something to lose:
  // a crawler following a magic-link or verification URL consumes the token.
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  // The canvas is true black, which the browser uses for the address bar and
  // any overscroll area. Left unset, those regions stay white and frame the
  // page in a colour the design system does not contain.
  themeColor: "#000000",

  // Declared rather than inferred from the visitor's OS. The design system has
  // one theme, and this is what makes the browser's own chrome — form controls,
  // scrollbars, autofill — render against it instead of against white.
  colorScheme: "dark",
};

export default function RootLayout({
  children,
}: {
  children: ReactNode;
}): ReactNode {
  return (
    <html lang="en">
      <body className="min-h-dvh bg-canvas font-sans text-body antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
