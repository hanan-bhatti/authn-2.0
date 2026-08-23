/**
 * Authn Platform — Account app build configuration
 * File: apps/web-account/next.config.ts
 *
 * The repository root .env is the only source of truth for configuration, and
 * Next reads .env from the app directory rather than from a monorepo root, so
 * this file loads it explicitly.
 *
 * The load has to happen here, not only in the `dev` script's dotenv-cli
 * wrapper, because NEXT_PUBLIC_ values are inlined into the client bundle at
 * build time — a variable absent from the process when the compiler runs is
 * baked in as `undefined` rather than read later at runtime.
 */

import { config as loadEnv } from "dotenv";
import { resolve } from "node:path";
import type { NextConfig } from "next";

// `override: false` is the default and is the behaviour wanted: a real
// environment variable — what a deployment platform injects — must win over the
// checked-in development file.
loadEnv({ path: resolve(process.cwd(), "../../.env"), quiet: true });

const nextConfig: NextConfig = {
  reactStrictMode: true,

  // Reported in the footer. Read from the engine's own AUTHN_APP_VERSION rather
  // than a NEXT_PUBLIC_ twin so a release bumps one variable, and mapped through
  // `env` because only the NEXT_PUBLIC_ prefix is inlined automatically.
  env: {
    NEXT_PUBLIC_AUTHN_APP_VERSION: process.env.AUTHN_APP_VERSION ?? "0.0.0-dev",
  },

  // @authn/ui and @authn/react ship ESM built by tsup. Transpiling them here
  // lets Next apply its own JSX and module handling to the workspace sources
  // instead of treating them as opaque third-party bundles.
  transpilePackages: ["@authn/ui", "@authn/react", "@authn/js"],

  // An auth surface should not advertise its framework version.
  poweredByHeader: false,
};

export default nextConfig;
