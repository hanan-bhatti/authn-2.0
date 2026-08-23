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
