/**
 * @authn/js — Username Handle Rules
 *
 * A mirror of the engine's `pkg/username`, kept here so a sign-up form can answer
 * "is this shape even allowed" without a round trip, and so every client renders
 * the same sentence the engine would have sent.
 *
 * The engine stays authoritative. Two questions cannot be answered here at all —
 * whether a handle is already held, and whether it is on the reserved list — and
 * the reserved list is deliberately not copied: it is a server-side list that
 * grows, and a stale copy shipped in a client would either accept a handle the
 * engine refuses or refuse one it now allows. Availability and reservation come
 * back from {@link AuthnClient.checkUsername}.
 *
 * @packageDocumentation
 */

/**
 * Length bounds on the canonical handle, in characters.
 *
 * Thirty is a display bound: a handle appears in mention lists and member tables
 * where a longer one breaks the row beside it. Three keeps one- and
 * two-character handles — scarce and disproportionately valuable — out of
 * first-come-first-served allocation.
 */
export const USERNAME_MIN_LENGTH = 3;
export const USERNAME_MAX_LENGTH = 30;

/**
 * The largest raw value that will be normalized, in UTF-8 bytes.
 *
 * NFKC can expand its input several times over, so the ceiling is checked before
 * normalizing rather than after. Four bytes per character at the character
 * ceiling is the most a handle of the maximum length can occupy.
 */
export const USERNAME_MAX_INPUT_BYTES = USERNAME_MAX_LENGTH * 4;

/** Which rule a handle broke, for a caller that wants to branch rather than render. */
export type UsernameProblem =
  | "empty"
  | "too_short"
  | "too_long"
  | "charset"
  | "leading_char"
  | "trailing_char";

export interface UsernameFormat {
  valid: boolean;
  problem?: UsernameProblem;
  /**
   * The sentence to show the person who typed it, worded identically to the
   * engine's. Each one names the fix rather than the violation: "must start with
   * a letter" tells the user what to type, where "invalid leading character"
   * tells them only that they were wrong.
   */
  message?: string;
  /**
   * The identity form: NFKC-composed and lower-cased. Present only when valid.
   * Worth showing — someone who typed `AlexSmith` gets `@alexsmith`, and seeing
   * it now beats discovering it after the account exists.
   */
  canonical?: string;
}

const MESSAGES: Record<UsernameProblem, string> = {
  empty: "username is required",
  too_short: `username must be at least ${USERNAME_MIN_LENGTH} characters`,
  too_long: `username must be at most ${USERNAME_MAX_LENGTH} characters`,
  charset: "username may contain only letters, digits and underscores",
  leading_char: "username must start with a letter",
  trailing_char: "username must not end with an underscore",
};

/** The general rule statement, for a hint under the field rather than an error. */
export const USERNAME_RULE_HINT =
  `${USERNAME_MIN_LENGTH}-${USERNAME_MAX_LENGTH} characters, letters, digits and underscores, ` +
  "starting with a letter";

function invalid(problem: UsernameProblem): UsernameFormat {
  return { valid: false, problem, message: MESSAGES[problem] };
}

function isLetter(char: string): boolean {
  return char >= "a" && char <= "z";
}

function isAllowed(char: string): boolean {
  return isLetter(char) || (char >= "0" && char <= "9") || char === "_";
}

/**
 * Check a handle's shape and return its canonical form.
 *
 * The rules are applied in the engine's order, which is load-bearing for the
 * message: normalization runs before the charset check, so a fullwidth `ａ` folds
 * to `a` and is accepted rather than reported as a disallowed character; and the
 * charset is checked before the positional rules, so a Cyrillic `а` — a letter,
 * but not one of ours — is reported as a charset failure instead of being told
 * "must start with a letter", which it satisfies.
 *
 * A `valid` result does not mean the handle can be registered: it may be taken or
 * reserved. Ask {@link AuthnClient.checkUsername} for that.
 */
export function checkUsernameFormat(raw: unknown): UsernameFormat {
  if (typeof raw !== "string") return invalid("empty");

  const trimmed = raw.trim();
  if (trimmed === "") return invalid("empty");
  if (new TextEncoder().encode(trimmed).length > USERNAME_MAX_INPUT_BYTES) {
    return invalid("too_long");
  }

  const folded = trimmed.normalize("NFKC").toLowerCase();
  // Spread rather than .length: String.length counts UTF-16 units, so a handle
  // built from astral characters would read as twice its length. Those are
  // rejected by the charset rule below, but reporting them as too long first
  // would send the user to shorten input whose problem is the characters in it.
  const chars = [...folded];
  if (chars.length < USERNAME_MIN_LENGTH) return invalid("too_short");
  if (chars.length > USERNAME_MAX_LENGTH) return invalid("too_long");

  for (const char of chars) {
    if (!isAllowed(char)) return invalid("charset");
  }
  if (!isLetter(chars[0]!)) return invalid("leading_char");
  if (chars[chars.length - 1] === "_") return invalid("trailing_char");

  return { valid: true, canonical: folded };
}

/** Whether a handle's shape is allowed, for a caller that needs only the verdict. */
export function isValidUsernameFormat(raw: unknown): boolean {
  return checkUsernameFormat(raw).valid;
}
