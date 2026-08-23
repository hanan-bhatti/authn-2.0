/**
 * Authn Platform — Turning an AuthnError into copy for an emailed-link landing
 * File: apps/web-account/src/lib/linkError.ts
 *
 * A landing page has no fields, so unlike a form it cannot put a refusal next to
 * the thing that caused it. What it can do is say which of a small number of
 * situations the user is in, and offer the one action that gets them out.
 */

import { AuthnErrorCode, type AuthnError } from "@authn/js";

/**
 * The single way out of a failed landing.
 *
 * One remedy, not a list: a page that offers both "try again" and "send me a new
 * link" makes the user choose between two things they cannot tell apart.
 */
export type LinkRemedy =
  /** The token is spent or stale. A fresh one is the only way forward. */
  | "request-another"
  /** Nothing reached the engine, so the token in hand is still good. */
  | "retry"
  /** A throttle. Time is the remedy, and a new link would hit the same limit. */
  | "wait"
  /** The account itself is barred, which no link changes. */
  | "contact-support"
  /** The page is misconfigured, or something unknown went wrong. */
  | "none";

export interface PresentedLinkFailure {
  title: string;
  description: string;
  remedy: LinkRemedy;
}

/**
 * The kind of link that was clicked, which decides only the wording.
 *
 * Every branch below is shared: the two flows fail in the same ways, and the
 * difference is that one confirms an address while the other signs someone in.
 */
export type LinkKind = "verification" | "sign-in";

function retryHint(details: Record<string, unknown> | undefined): string | undefined {
  const after = details?.["retry_after"];
  if (typeof after !== "number" || after <= 0) return undefined;
  return after < 60
    ? `Try again in ${after} seconds.`
    : `Try again in ${Math.ceil(after / 60)} minutes.`;
}

/**
 * Decides what a landing page says about a refused token.
 *
 * As with the sign-up form, the engine's own prose is not shown. It documents
 * `code` as the only field meant to be branched on, and these messages have to
 * name a remedy the engine knows nothing about.
 */
export function presentLinkError(error: AuthnError, kind: LinkKind): PresentedLinkFailure {
  const isSignIn = kind === "sign-in";

  switch (error.code) {
    // A spent, revoked or unrecognised token, and an expired one. The engine
    // separates the two; the page deliberately does not, because it cannot tell
    // the user which without also telling anyone holding a stolen token whether
    // it was ever real.
    case AuthnErrorCode.UNAUTHORIZED:
    case AuthnErrorCode.MAGIC_LINK_EXPIRED:
    case AuthnErrorCode.NOT_FOUND:
      return {
        title: isSignIn ? "This sign-in link no longer works" : "This link no longer works",
        description:
          "Links expire, and each one works only once — so this can also mean it has already been opened.",
        remedy: "request-another",
      };

    // The SDK's own token check, which runs before anything is sent. What reaches
    // it is a URL that lost part of its query string on the way — mail clients
    // wrap long lines, and some rewrite links entirely.
    case AuthnErrorCode.INVALID_PARAMS:
    case AuthnErrorCode.VALIDATION_ERROR:
      return {
        title: "This link is incomplete",
        description:
          "Part of it was cut off. Copying the whole address out of the email usually fixes it.",
        remedy: "request-another",
      };

    case AuthnErrorCode.ACCOUNT_DISABLED:
      return {
        title: "This account cannot be used",
        description: "Contact support to have it reviewed.",
        remedy: "contact-support",
      };

    case AuthnErrorCode.RATE_LIMITED:
      return {
        title: "Too many attempts",
        description: retryHint(error.details) ?? "Wait a moment before trying again.",
        remedy: "wait",
      };

    case AuthnErrorCode.NETWORK_ERROR:
    case AuthnErrorCode.TIMEOUT:
      return {
        title: "Could not reach the server",
        // The one family where the link is still good: the request never arrived,
        // so nothing consumed the token.
        description: "Your link is still valid. Check your connection and try again.",
        remedy: "retry",
      };

    // The request was dropped on this side — the page was left, or the SDK client
    // it was made on was torn down. As with a network failure the token is
    // untouched, but the connection is not the thing to check.
    case AuthnErrorCode.CANCELLED:
      return {
        title: isSignIn ? "Sign-in did not finish" : "Verification did not finish",
        description: "Your link is still valid.",
        remedy: "retry",
      };

    case AuthnErrorCode.SERVER_ERROR:
      return {
        title: "Something went wrong on our side",
        description: "This is usually temporary.",
        remedy: "retry",
      };

    // The key this page holds is for another tenant, or this origin is not on the
    // application's allowlist. The link is fine; the page is not, so a new link
    // would fail identically.
    case AuthnErrorCode.INVALID_CONFIG:
    case AuthnErrorCode.INVALID_PUBLISHABLE_KEY:
      return {
        title: isSignIn ? "Sign-in is unavailable" : "Verification is unavailable",
        description: "This page is misconfigured. The site owner has been given the details.",
        remedy: "none",
      };

    default:
      return {
        title: isSignIn ? "Could not sign you in" : "Could not verify your email",
        description: error.isRetryable ? "Try again in a moment." : "Request a new link to try again.",
        remedy: error.isRetryable ? "retry" : "request-another",
      };
  }
}
