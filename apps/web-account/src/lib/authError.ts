/**
 * Authn Platform — Turning an AuthnError into something a form can show
 * File: apps/web-account/src/lib/authError.ts
 */

import { AuthnErrorCode, type AuthnError } from "@authn/js";

export type FieldName = "email" | "password" | "name";

/**
 * Presented carries exactly one destination.
 *
 * A refusal shown twice — inline under the field and again in a toast — reads as
 * two separate failures, and the user goes looking for a second thing to fix.
 * So `field` and `toast` are mutually exclusive by construction: something the
 * user can correct in a field goes to that field, and everything else, which is
 * to say everything they cannot act on, goes to the toast.
 */
export type Presented =
  | { field: FieldName; message: string; missingCriteria?: string[] }
  | { toast: { title: string; description?: string } };

function asStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const names = value.filter((v): v is string => typeof v === "string");
  return names.length > 0 ? names : undefined;
}

function retryHint(details: Record<string, unknown> | undefined): string | undefined {
  const after = details?.["retry_after"];
  if (typeof after !== "number" || after <= 0) return undefined;
  return after < 60
    ? `Try again in ${after} seconds.`
    : `Try again in ${Math.ceil(after / 60)} minutes.`;
}

/**
 * Decides where a sign-up refusal belongs.
 *
 * The engine's own prose is deliberately not read. It documents `code` as the
 * only field meant to be branched on, and rewording an error message should not
 * silently move it from a field to a toast.
 */
export function presentSignUpError(error: AuthnError): Presented {
  const details = error.details;
  const missingCriteria = asStringArray(details?.["missing_criteria"]);

  // The SDK validates before sending and names the field it rejected. That is
  // the most specific signal available, so it wins.
  const declaredField = details?.["field"];
  if (typeof declaredField === "string" && isFieldName(declaredField)) {
    return { field: declaredField, message: error.message };
  }

  switch (error.code) {
    case AuthnErrorCode.VALIDATION_ERROR:
      if (missingCriteria) {
        return {
          field: "password",
          message: "This password does not meet the requirements below.",
          missingCriteria,
        };
      }
      // Sign-up's other validation failures are an over-long name, which the
      // form caps locally so it cannot arrive; a bad client type, which the SDK
      // sets; and an unprovisioned tenant, which no user can act on. What is
      // left is an address the SDK's loose regex passes and the engine's stricter
      // parse rejects — `user@host.c`, a one-character TLD — so the field is the
      // right destination for the only one of these a user can still cause.
      //
      // The engine does not name the field it refused. Once it does, this branch
      // reads that instead of reasoning from what is left.
      return { field: "email", message: "Enter a valid email address." };

    case AuthnErrorCode.EMAIL_ALREADY_EXISTS:
      return {
        field: "email",
        message: "An account already uses this address. Sign in instead.",
      };

    case AuthnErrorCode.RATE_LIMITED:
      return {
        toast: {
          title: "Too many attempts",
          description: retryHint(details) ?? "Wait a moment before trying again.",
        },
      };

    case AuthnErrorCode.NETWORK_ERROR:
    case AuthnErrorCode.TIMEOUT:
      return {
        toast: {
          title: "Could not reach the server",
          description: "Check your connection and try again.",
        },
      };

    case AuthnErrorCode.ACCOUNT_DISABLED:
      return {
        toast: {
          title: "This account cannot be used",
          description: "Contact support to have it reviewed.",
        },
      };

    // Both mean the page itself is misconfigured — a publishable key for another
    // tenant, an origin the application does not allow. Nothing the user types
    // changes it, so it must not be attached to a field they will keep editing.
    case AuthnErrorCode.INVALID_CONFIG:
    case AuthnErrorCode.INVALID_PUBLISHABLE_KEY:
      return {
        toast: {
          title: "Sign-up is unavailable",
          description: "This page is misconfigured. The site owner has been given the details.",
        },
      };

    case AuthnErrorCode.TEST_QUOTA_EXCEEDED:
      return {
        toast: {
          title: "This test environment is full",
          description: "Delete some records or switch to live keys.",
        },
      };

    default:
      return {
        toast: {
          title: "Could not create your account",
          description: error.isRetryable ? "Try again in a moment." : undefined,
        },
      };
  }
}

function isFieldName(value: string): value is FieldName {
  return value === "email" || value === "password" || value === "name";
}
