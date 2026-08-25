/**
 * Authn Platform — Reading one value out of a Next searchParams bag
 * File: apps/web-account/src/lib/searchParams.ts
 */

/**
 * Returns the first value of a query parameter, or undefined when it is absent.
 *
 * Next hands back an array whenever a parameter appears more than once, and
 * `?token=a&token=b` is something a mail client's link rewriting can produce. The
 * array form has to collapse to a single value somewhere, and doing it here means
 * neither landing page has to hold a `string | string[]` union.
 */
export function firstParam(value: string | string[] | undefined): string | undefined {
  const first = Array.isArray(value) ? value[0] : value;
  return first && first.length > 0 ? first : undefined;
}

/** Where sign-in lands when it was not sent anywhere in particular. */
export const DEFAULT_SIGNED_IN_PATH = "/account";

/**
 * Turns a `?next=` value into a destination, or falls back to the account page.
 *
 * The guard on the account section writes this parameter so that a visitor who
 * asked for `/account/sessions` and was bounced to sign in arrives back at
 * sessions rather than at the profile. The value is therefore attacker-supplied:
 * a link to `/sign-in?next=https://example.invalid/pay` would otherwise hand a
 * freshly authenticated person to somebody else's page, and the sign-in they had
 * just completed is exactly what makes them believe it.
 *
 * So only a path on this origin is accepted. `//host` is rejected because a
 * browser reads a protocol-relative URL as another origin, and a backslash
 * because some parsers normalise `/\` to the same thing.
 */
export function safeNextPath(value: string | null | undefined): string {
  if (!value || !value.startsWith("/")) return DEFAULT_SIGNED_IN_PATH;
  if (value.startsWith("//") || value.startsWith("/\\")) return DEFAULT_SIGNED_IN_PATH;
  return value;
}
