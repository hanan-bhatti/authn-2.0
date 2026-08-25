/**
 * Authn Platform — Dates as a reader reads them
 * File: apps/web-account/src/lib/datetime.ts
 *
 * The engine sends RFC 3339 timestamps. Nothing on these pages should print one:
 * `2026-03-02T09:14:22Z` asks the reader to work out both the calendar and the
 * offset, and the answer they wanted was "last Tuesday".
 *
 * Both functions here are for client components only. They read the browser's own
 * locale and zone, which the server does not have — formatting a date during a
 * server render and again on hydration produces two different strings for the same
 * instant and React replaces the whole subtree. Every caller is a component that
 * fetches its data after mount, so there is no server-rendered value to disagree
 * with.
 */

/**
 * Parses a timestamp, or returns null when there is nothing usable.
 *
 * Null rather than an Invalid Date, because `Intl` throws on one: a single absent
 * field in a payload would otherwise take down the card rendering it.
 */
function parse(value: string | null | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * A calendar date: "2 March 2026".
 *
 * The month is spelled out because the numeric forms are ambiguous across the
 * readers of one page — 03/02/2026 is two different days depending on where the
 * browser is — and the year is always present because these dates are frequently
 * years old.
 *
 * @param fallback What to show when the timestamp is missing or unparseable.
 */
export function formatDate(value: string | null | undefined, fallback = "Unknown"): string {
  const date = parse(value);
  if (!date) return fallback;

  return new Intl.DateTimeFormat(undefined, {
    day: "numeric",
    month: "long",
    year: "numeric",
  }).format(date);
}

/** A date with the time of day, for a record where the hour matters. */
export function formatDateTime(value: string | null | undefined, fallback = "Unknown"): string {
  const date = parse(value);
  if (!date) return fallback;

  return new Intl.DateTimeFormat(undefined, {
    day: "numeric",
    month: "long",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

const MINUTE = 60;
const HOUR = MINUTE * 60;
const DAY = HOUR * 24;

/**
 * How long ago, in words: "just now", "4 minutes ago", "3 days ago".
 *
 * Relative rather than absolute for recency, because that is the question being
 * asked of it. A session list exists to answer "is one of these not me", and
 * "active 2 minutes ago" answers that where "active at 09:14" needs the reader to
 * check the clock first.
 *
 * Past 30 days it hands over to {@link formatDate}. "Active 400 days ago" is
 * arithmetic pretending to be a fact.
 */
export function formatRelative(value: string | null | undefined, fallback = "Unknown"): string {
  const date = parse(value);
  if (!date) return fallback;

  const seconds = Math.round((Date.now() - date.getTime()) / 1000);

  // A clock a few seconds ahead of the server produces a small negative, and
  // "in 3 seconds" for something that has already happened reads as a bug.
  if (seconds < MINUTE) return "just now";
  if (seconds > DAY * 30) return formatDate(value, fallback);

  const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

  if (seconds < HOUR) return relative.format(-Math.floor(seconds / MINUTE), "minute");
  if (seconds < DAY) return relative.format(-Math.floor(seconds / HOUR), "hour");
  return relative.format(-Math.floor(seconds / DAY), "day");
}
