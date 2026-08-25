/**
 * Authn Platform — Account app environment
 * File: apps/web-account/src/lib/env.ts
 *
 * Every value the app reads from the environment is resolved here, once.
 *
 * The reads are written as literal `process.env.NEXT_PUBLIC_…` expressions
 * rather than through a variable or a loop because the compiler replaces the
 * literal text at build time. `process.env[name]` with a computed name has
 * nothing to replace and evaluates to undefined in the browser, so indirection
 * that looks like a tidy refactor here silently empties the values.
 */

/**
 * Fail at module load rather than at first use. A publishable key that is
 * missing surfaces otherwise as a 401 on the first request, which reads as a
 * server problem; naming the variable turns it back into a configuration one.
 */
function required(name: string, value: string | undefined): string {
  if (!value) {
    throw new Error(
      `${name} is not set. The account app reads the repository root .env; ` +
        `add the variable there and restart the dev server.`,
    );
  }
  return value;
}

export const env = {
  /** The engine's base URL. Requests are same-origin only in production. */
  apiUrl: required(
    "NEXT_PUBLIC_AUTHN_API_URL",
    process.env.NEXT_PUBLIC_AUTHN_API_URL,
  ),

  /**
   * The application this app signs users into. Safe in browser code by
   * construction — a `pk_` key can only reach the client surface of the API.
   */
  publishableKey: required(
    "NEXT_PUBLIC_AUTHN_PUBLISHABLE_KEY",
    process.env.NEXT_PUBLIC_AUTHN_PUBLISHABLE_KEY,
  ),

  /**
   * Mapped from AUTHN_APP_VERSION by next.config.ts, so the engine and the web
   * apps report the same build. Not required: a footer without a version is a
   * cosmetic loss, and refusing to boot over one would be a worse trade.
   */
  appVersion: process.env.NEXT_PUBLIC_AUTHN_APP_VERSION ?? "0.0.0-dev",

  /**
   * Where the documentation is published, with no trailing slash.
   *
   * Empty until a docs site exists. Help text is written to stand on its own and
   * `docs.ts` only adds a link when this is set, so an unset value costs the
   * reader nothing — it does not leave a button that goes nowhere.
   */
  docsUrl: (process.env.NEXT_PUBLIC_AUTHN_DOCS_URL ?? "").replace(/\/+$/, ""),
} as const;
