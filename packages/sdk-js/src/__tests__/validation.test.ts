import { describe, expect, it } from "vitest";
import { validatePassword } from "../core/validation";

/**
 * The engine's password floor is eight characters after NFKC normalization, and
 * the client's pre-flight check has to agree with it in the same unit. Two units
 * were wrong before and each failed in a different direction: UTF-16 units
 * refuse a password the engine accepts, and UTF-8 bytes accept one the engine
 * refuses.
 *
 * Spellings are written as escapes, because a composed and a decomposed "é" are
 * indistinguishable in a source file and a literal would make these vacuous.
 */
describe("validatePassword — the length unit", () => {
  it("refuses a password that only reaches eight in bytes", () => {
    // Five characters, eleven UTF-8 bytes, seven UTF-16 units. The engine counts
    // five and refuses; a byte count reads eleven and would have let it through.
    const password = "AA1\u{1f600}\u{1f601}";

    expect([...password].length).toBe(5);
    expect(new TextEncoder().encode(password).length).toBe(11);

    expect(validatePassword(password).valid).toBe(false);
  });

  it("refuses four characters even though they fill eight UTF-16 units", () => {
    // Four astral characters: four characters, eight UTF-16 units.
    const password = "\u{1f600}\u{1f601}\u{1f602}\u{1f603}";

    expect(password.length).toBe(8);
    expect(validatePassword(password).valid).toBe(false);
  });

  it("counts a decomposed sequence as the character it composes into", () => {
    // Eight bases each followed by U+0308, so sixteen characters as typed and
    // eight once composed — exactly the floor, and accepted.
    const composedToEight = "a\u0308e\u0308i\u0308o\u0308u\u0308y\u0308A\u0308E\u0308";

    expect([...composedToEight].length).toBe(16);
    expect([...composedToEight.normalize("NFKC")].length).toBe(8);

    expect(validatePassword(composedToEight).valid).toBe(true);
  });

  it("refuses a decomposed sequence that composes below the floor", () => {
    // Seven bases plus their marks: fourteen characters as typed, seven composed.
    const composedToSeven = "a\u0308e\u0308i\u0308o\u0308u\u0308y\u0308A\u0308";

    expect([...composedToSeven.normalize("NFKC")].length).toBe(7);

    expect(validatePassword(composedToSeven).valid).toBe(false);
  });

  it("still accepts and refuses plain ASCII at the boundary", () => {
    expect(validatePassword("Pass1234").valid).toBe(true);
    expect(validatePassword("Pass123").valid).toBe(false);
  });

  it("separates a missing password from a short one", () => {
    expect(validatePassword("").message).toMatch(/required/i);
    expect(validatePassword("short").message).toMatch(/at least 8/i);
  });
});
