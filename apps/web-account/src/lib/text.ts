/**
 * Authn Platform — Text measurement
 * File: apps/web-account/src/lib/text.ts
 */

const utf8 = new TextEncoder();

/**
 * Length as the engine counts it: UTF-8 bytes.
 *
 * Go's `len` on a string returns bytes, so every length bound the engine
 * enforces — a password minimum, a name maximum — is a byte bound. `AA1`
 * followed by two emoji is 11 there and 7 to `String.length`, and under a
 * minimum of 8 those two numbers disagree about the same input. Any check meant
 * to predict the engine's answer has to count the way the engine counts.
 */
export function byteLength(value: string): number {
  return utf8.encode(value).length;
}
