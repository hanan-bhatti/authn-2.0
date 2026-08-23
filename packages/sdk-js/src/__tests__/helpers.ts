/**
 * @authn/js — Test helpers
 *
 * Accessors for inspecting what a fetch mock was called with.
 *
 * They exist because `noUncheckedIndexedAccess` makes every
 * `mock.calls[0][1].body` a three-step narrowing exercise, and the obvious way
 * out — a `!` on each step — silences the one case worth reporting: a test
 * asserting on a request that was never made. These throw instead, naming the
 * call index, so that failure reads as itself rather than as
 * "Cannot read properties of undefined".
 */

import type { AuthResult, AuthnSession } from "../types";

/** FetchMock is the shape vi.fn() exposes, whatever its parameters are typed as. */
interface FetchMock {
  mock: { calls: readonly unknown[][] };
}

function call(mock: FetchMock, index: number): readonly unknown[] {
  const calls = mock.mock.calls;
  const found = calls[index];
  if (!found) {
    throw new Error(
      `expected a fetch call at index ${index}, but only ${calls.length} were made`,
    );
  }
  return found;
}

/** callUrl returns the URL the nth fetch was made against. */
export function callUrl(mock: FetchMock, index = 0): string {
  return String(call(mock, index)[0]);
}

/** callInit returns the RequestInit the nth fetch was made with. */
export function callInit(mock: FetchMock, index = 0): RequestInit {
  const init = call(mock, index)[1];
  if (!init || typeof init !== "object") {
    throw new Error(`fetch call ${index} carried no request options`);
  }
  return init as RequestInit;
}

/** callHeaders returns the headers the nth fetch carried, as a plain object. */
export function callHeaders(
  mock: FetchMock,
  index = 0,
): Record<string, string> {
  return (callInit(mock, index).headers ?? {}) as Record<string, string>;
}

/** callBody parses the JSON body the nth fetch carried. */
export function callBody<T = Record<string, unknown>>(
  mock: FetchMock,
  index = 0,
): T {
  const body = callInit(mock, index).body;
  if (typeof body !== "string") {
    throw new Error(`fetch call ${index} carried no JSON body`);
  }
  return JSON.parse(body) as T;
}

/**
 * nth returns one element of a list, throwing rather than yielding undefined
 * when the list is shorter than the assertion assumes.
 */
export function nth<T>(items: readonly T[], index: number): T {
  const found = items[index];
  if (found === undefined) {
    throw new Error(
      `expected an element at index ${index}, but the list holds ${items.length}`,
    );
  }
  return found;
}

/**
 * sessionOf pulls the session out of an AuthResult.
 *
 * `AuthResult` has three arms and only one of them carries a session, so a test
 * that wants the session has to rule out both a refusal and a 2FA challenge
 * first. Doing that with `if (result.ok) { … }` would let the challenge arm skip
 * every assertion in silence; this names which arm arrived instead.
 */
export function sessionOf(result: AuthResult): AuthnSession {
  if (!result.ok) {
    throw new Error(`expected a session, got error ${result.error.code}`);
  }
  if (result.mfaRequired) {
    throw new Error("expected a session, got a 2FA challenge");
  }
  return result.session;
}
