/**
 * Authn Platform — Text measurement
 * File: apps/web-account/src/lib/text.ts
 */

const utf8 = new TextEncoder();

/**
 * Length in UTF-8 bytes, which is what Go's `len` returns.
 *
 * This is the right measure for a bound backed by a database column — the 255 on
 * a user's name — because that limit is in bytes whatever the text is. It is the
 * wrong measure for a password; see {@link characterLength}.
 */
export function byteLength(value: string): number {
  return utf8.encode(value).length;
}

/**
 * Length as the engine measures a password: characters, after NFKC.
 *
 * Both halves matter, and each fixes a different disagreement.
 *
 * Characters rather than `String.length`, because `String.length` counts UTF-16
 * units: an emoji is two, so "AA1" plus two emoji reads as 7 when it is 5. And
 * characters rather than bytes, because the same input is 11 bytes — which is
 * how a five-character password used to satisfy a minimum of eight.
 *
 * After NFKC, because the engine normalizes before it measures and before it
 * hashes. "e" plus a combining acute is two characters until it is composed into
 * "é", which is one, so counting first would measure a string the engine throws
 * away.
 */
export function characterLength(value: string): number {
  return [...value.normalize("NFKC")].length;
}
