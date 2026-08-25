import { describe, expect, it } from "vitest";
import {
  USERNAME_MAX_INPUT_BYTES,
  USERNAME_MAX_LENGTH,
  checkUsernameFormat,
} from "../core/username";
import { validateLoginIdentifier } from "../core/validation";

/**
 * These rules are a mirror of the engine's pkg/username, and a mirror is only
 * useful while it agrees. Each case below fixes one point where the two could
 * drift apart and produce a form that accepts what the server refuses, or refuses
 * what it accepts.
 *
 * Non-ASCII spellings are written as escapes: a fullwidth "ａ" and a Cyrillic "а"
 * are indistinguishable from their Latin lookalikes in a source file, and a
 * literal would make the test vacuous.
 */
describe("checkUsernameFormat — normalization", () => {
  it("keeps the display form and reports the canonical one", () => {
    const result = checkUsernameFormat("AlexSmith");

    expect(result.valid).toBe(true);
    expect(result.canonical).toBe("alexsmith");
  });

  it("folds a fullwidth letter to ASCII rather than refusing it", () => {
    // U+FF41 FULLWIDTH LATIN SMALL LETTER A, which NFKC maps to "a". Checking the
    // charset before normalizing would reject input that is valid once composed.
    const result = checkUsernameFormat("ａlexsmith");

    expect(result.valid).toBe(true);
    expect(result.canonical).toBe("alexsmith");
  });

  it("composes a decomposed sequence before measuring it", () => {
    // "a" + combining diaeresis composes to "ä", which is outside the charset.
    // Measuring before composing would have counted four characters here.
    const result = checkUsernameFormat("äbc");

    expect([...("äbc".normalize("NFKC"))].length).toBe(3);
    expect(result.valid).toBe(false);
    expect(result.problem).toBe("charset");
  });

  it("trims surrounding whitespace", () => {
    expect(checkUsernameFormat("  alexsmith  ").canonical).toBe("alexsmith");
  });
});

describe("checkUsernameFormat — the rules", () => {
  it("refuses a Cyrillic lookalike as a charset failure, not a leading one", () => {
    // U+0430 is a letter and renders identically to Latin "a". Reporting "must
    // start with a letter" would tell the user their input satisfies the rule it
    // just failed.
    const result = checkUsernameFormat("аlexsmith");

    expect(result.valid).toBe(false);
    expect(result.problem).toBe("charset");
    expect(result.message).toMatch(/letters, digits and underscores/);
  });

  it("requires a letter first, so a digit and an underscore both fail", () => {
    expect(checkUsernameFormat("1alex").problem).toBe("leading_char");
    expect(checkUsernameFormat("_alex").problem).toBe("leading_char");
  });

  it("refuses a trailing underscore", () => {
    expect(checkUsernameFormat("alex_").problem).toBe("trailing_char");
    expect(checkUsernameFormat("alex_smith").valid).toBe(true);
  });

  it("holds both length bounds", () => {
    expect(checkUsernameFormat("ab").problem).toBe("too_short");
    expect(checkUsernameFormat("abc").valid).toBe(true);
    expect(checkUsernameFormat("a".repeat(USERNAME_MAX_LENGTH)).valid).toBe(true);
    expect(checkUsernameFormat("a".repeat(USERNAME_MAX_LENGTH + 1)).problem).toBe(
      "too_long",
    );
  });

  it("refuses an over-long value before normalizing it", () => {
    // Past the byte ceiling, so it is rejected without NFKC being asked to expand
    // it. The characters are astral, which is where an unbounded normalize costs.
    const wide = "\u{1f600}".repeat(USERNAME_MAX_INPUT_BYTES);

    expect(checkUsernameFormat(wide).problem).toBe("too_long");
  });

  it("counts characters rather than UTF-16 units", () => {
    // Two astral characters: two characters, four UTF-16 units. Below the floor
    // either way, but the reason must be the charset, not the length — a length
    // message would send the user to type more of what is not allowed.
    const astral = "\u{1f600}\u{1f601}";

    expect(astral.length).toBe(4);
    expect(checkUsernameFormat(astral).problem).toBe("too_short");
  });

  it("treats a non-string and an empty string alike", () => {
    expect(checkUsernameFormat(undefined).problem).toBe("empty");
    expect(checkUsernameFormat("").problem).toBe("empty");
    expect(checkUsernameFormat("   ").problem).toBe("empty");
  });
});

/**
 * The login identifier is deliberately unvalidated past presence and a ceiling.
 * A shape check here would answer a mistyped handle with a message about email
 * format, and would tell anyone probing which shapes the engine can resolve.
 */
describe("validateLoginIdentifier", () => {
  it("accepts an address, a handle, and something that is neither", () => {
    expect(validateLoginIdentifier("user@example.com").valid).toBe(true);
    expect(validateLoginIdentifier("alexsmith").valid).toBe(true);
    expect(validateLoginIdentifier("not an address or a handle").valid).toBe(true);
  });

  it("refuses an absent identifier", () => {
    expect(validateLoginIdentifier("").valid).toBe(false);
    expect(validateLoginIdentifier("   ").valid).toBe(false);
    expect(validateLoginIdentifier(undefined).valid).toBe(false);
  });

  it("holds the engine's ceiling in the engine's unit", () => {
    // The engine counts UTF-8 bytes. 320 astral characters are 1280 bytes, so a
    // character count would pass a value the engine answers 400 for.
    const wide = "\u{1f600}".repeat(320);

    expect([...wide].length).toBe(320);
    expect(validateLoginIdentifier(wide).valid).toBe(false);
    expect(validateLoginIdentifier("a".repeat(320)).valid).toBe(true);
    expect(validateLoginIdentifier("a".repeat(321)).valid).toBe(false);
  });
});
