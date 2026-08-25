/**
 * Authn Platform — Turning an AuthnError into something a form can show
 * File: apps/web-account/src/lib/authError.ts
 */

import { AuthnErrorCode, type AuthnError } from "@authn/js";

export type FieldName = "email" | "password" | "name" | "username" | "identifier";

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
  | { field: FieldName; message: string; missingCriteria?: string[]; suggestions?: string[] }
  | { toast: { title: string; description?: string } };

/**
 * Sign-in adds a third destination: a message about the submission as a whole.
 *
 * Wrong credentials are the case that needs it. Which of the two fields was wrong
 * is not knowable — deliberately, since answering it would confirm that an
 * account exists — so pinning the message to either one states something the
 * engine did not say and sends the user to re-type a value that may be correct.
 */
export type PresentedSignIn = Presented | { form: string };

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
  // the most specific signal available, so it wins. The engine names one too —
  // a taken handle is a conflict on `username` rather than on the registration —
  // and sends alternatives with it.
  const declaredField = details?.["field"];
  if (typeof declaredField === "string" && isFieldName(declaredField)) {
    return {
      field: declaredField,
      message: error.message,
      suggestions: asStringArray(details?.["suggestions"]),
    };
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

/**
 * Decides where a sign-in refusal belongs.
 *
 * The set of things that can go wrong here barely overlaps sign-up's, which is
 * why this is a second function rather than a flag on the first. Nothing is a
 * conflict, nothing names a password rule, and the one case that dominates in
 * practice — wrong credentials — belongs to neither field.
 */
export function presentSignInError(error: AuthnError): PresentedSignIn {
  const details = error.details;

  const declaredField = details?.["field"];
  if (typeof declaredField === "string" && isFieldName(declaredField)) {
    return { field: declaredField, message: error.message };
  }

  switch (error.code) {
    case AuthnErrorCode.INVALID_CREDENTIALS:
      return { form: "That email or username and password do not match an account." };

    // The password was right. Saying so is safe — the account holder is standing
    // there — and saying anything vaguer sends them into a password reset that
    // will succeed and change nothing about why they cannot get in.
    case AuthnErrorCode.EMAIL_VERIFICATION_REQUIRED:
      return {
        form: "Verify your email address before signing in. Open the link we sent you.",
      };

    case AuthnErrorCode.VALIDATION_ERROR:
      return { form: "Check your details and try again." };

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

    case AuthnErrorCode.INVALID_CONFIG:
    case AuthnErrorCode.INVALID_PUBLISHABLE_KEY:
      return {
        toast: {
          title: "Sign-in is unavailable",
          description: "This page is misconfigured. The site owner has been given the details.",
        },
      };

    default:
      return {
        toast: {
          title: "Could not sign you in",
          description: error.isRetryable ? "Try again in a moment." : undefined,
        },
      };
  }
}

function isFieldName(value: string): value is FieldName {
  return (
    value === "email" ||
    value === "password" ||
    value === "name" ||
    value === "username" ||
    value === "identifier"
  );
}

/**
 * Where a second-factor refusal belongs.
 *
 * This step has a destination the other two do not: the challenge itself can die
 * while the screen is open. The token lives minutes, not hours, and once it has
 * expired nothing on the page can revive it — a message under the code field
 * would invite the user to retype a code that was never the problem. So an
 * expired challenge is its own outcome, and the panel it goes to offers the way
 * back to the password rather than another attempt.
 */
export type PresentedSecondFactor =
  | { code: string }
  | { restart: { title: string; description: string } }
  | { toast: { title: string; description?: string } };

/**
 * @param method Which factor was being answered, because the same engine code
 * means different things per method: `not_found` is a missing phone number for
 * `sms` and a spent code for `backup_code`.
 */
export function presentSecondFactorError(
  error: AuthnError,
  method: "totp" | "sms" | "backup_code" | "passkey",
): PresentedSecondFactor {
  const details = error.details;

  switch (error.code) {
    case AuthnErrorCode.INVALID_MFA_CODE:
      if (method === "backup_code") {
        return { code: "That recovery code is not valid, or it has already been used." };
      }
      if (method === "sms") {
        return { code: "That code is not right. Check the last message you received." };
      }
      return { code: "That code is not right. Check your authenticator app and try the current code." };

    // `invalid_token` on this screen always means the challenge, not the code:
    // the code is checked only after the token has been opened.
    case AuthnErrorCode.UNAUTHORIZED:
    case AuthnErrorCode.SESSION_EXPIRED:
      return {
        restart: {
          title: "This sign-in attempt expired",
          description:
            "Two-step verification has a short window and this one has closed. Enter your password again to start a new attempt.",
        },
      };

    // The engine checks the requested method against the sealed list inside the
    // challenge token, not against the account's factors now. So this is reachable
    // by a factor removed on another device mid-sign-in, and starting over is the
    // fix — the new challenge will list what the account actually has.
    case AuthnErrorCode.VALIDATION_ERROR:
      return {
        restart: {
          title: "That method is no longer available",
          description:
            "The ways to verify this account have changed since this attempt started. Enter your password again to see the current options.",
        },
      };

    case AuthnErrorCode.NOT_FOUND:
      if (method === "sms") {
        return {
          toast: {
            title: "No confirmed phone number",
            description: "Text messages are not set up on this account. Use another method below.",
          },
        };
      }
      return {
        toast: {
          title: "That method is not set up",
          description: "Choose another way to verify below.",
        },
      };

    case AuthnErrorCode.RATE_LIMITED:
      return {
        toast: {
          title: "Too many attempts",
          description: retryHint(details) ?? "Wait a few minutes before trying again.",
        },
      };

    // The passkey prompt was dismissed or timed out. Not a failure, and saying
    // nothing at all leaves the button looking broken, so this is the one case
    // that reports as information rather than as a refusal.
    case AuthnErrorCode.CANCELLED:
      return {
        toast: {
          title: "Passkey not used",
          description: "The prompt closed before it finished. Try again when you are ready.",
        },
      };

    case AuthnErrorCode.INVALID_PARAMS:
      return {
        toast: {
          title: "This device cannot use your passkey",
          description: typeof error.message === "string" ? error.message : undefined,
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

    // `service_unavailable` lands here, which on this screen means the SMS
    // provider refused the send. There is deliberately no email fallback during a
    // login challenge, so the honest advice is another method.
    case AuthnErrorCode.SERVER_ERROR:
      return {
        toast: {
          title: method === "sms" ? "Could not send the code" : "Something went wrong",
          description:
            method === "sms"
              ? "Text messages are not getting through right now. Use another method below."
              : "Try again in a moment.",
        },
      };

    default:
      return {
        toast: {
          title: "Could not verify that",
          description: error.isRetryable ? "Try again in a moment." : undefined,
        },
      };
  }
}

/**
 * The sentence to show when a saved change was refused.
 *
 * Written for a control that already says what it was changing — a row that sends
 * one field, a dialog with one purpose — so the message carries the reason and
 * lets the surrounding page carry the subject. That is what makes a per-row save
 * worth having: the engine answers a bad name, a bad locale and a bad avatar URL
 * with the same "one or more fields are invalid", and the only thing that knows
 * which field it sent is the row that sent it.
 *
 * @param subject What was being changed, lower case and singular: "username",
 * "display name". Used where the engine's own prose is too generic to repeat.
 */
export function presentSaveError(error: AuthnError, subject: string): string {
  switch (error.code) {
    // The engine names the rule that was broken — a handle's shape, a reserved
    // metadata key — so its own sentence is more use than anything written here.
    case AuthnErrorCode.VALIDATION_ERROR:
      return error.message;

    // `already_exists` is what a taken handle arrives as, the engine having one
    // conflict code for every kind of collision.
    case AuthnErrorCode.EMAIL_ALREADY_EXISTS:
    case AuthnErrorCode.CONFLICT:
      return error.message;

    case AuthnErrorCode.INVALID_PARAMS:
      return error.message;

    case AuthnErrorCode.RATE_LIMITED:
      return retryHint(error.details) ?? "Too many changes too quickly. Wait a moment.";

    // The access token expired between opening the row and saving it. Said plainly
    // because the fix is a page reload, and a reader told only "could not save"
    // will retype the value instead.
    case AuthnErrorCode.UNAUTHORIZED:
    case AuthnErrorCode.SESSION_EXPIRED:
    case AuthnErrorCode.REFRESH_FAILED:
      return "Your session ended. Reload the page and sign in again.";

    case AuthnErrorCode.FORBIDDEN:
      return `You are not allowed to change your ${subject}.`;

    case AuthnErrorCode.NETWORK_ERROR:
    case AuthnErrorCode.TIMEOUT:
      return "Could not reach the server. Check your connection and try again.";

    case AuthnErrorCode.SERVER_ERROR:
      return "The server could not save that. Nothing has changed — try again in a moment.";

    default:
      return `Could not save your ${subject}.`;
  }
}
