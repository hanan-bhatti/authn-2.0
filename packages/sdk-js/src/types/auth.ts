/**
 * @authn/js — Authentication Parameters Types
 *
 * @packageDocumentation
 */

export interface SignUpParams {
  email: string;
  /**
   * Required. The engine refuses a blank one with `missing_parameter`, and this
   * call rejects it before sending, so declaring it optional only defers a
   * certain failure to runtime. Passwordless registration is
   * {@link AuthnClient.sendMagicLink}, which provisions the account itself.
   */
  password: string;
  name?: string;
  /**
   * Optional public handle, unique within the tenant and environment. An account
   * registered without one is a complete account: it signs in by address, and a
   * handle can be claimed later from the profile endpoint.
   *
   * Capitalisation is kept for display and ignored for identity, so `AlexSmith`
   * and `alexsmith` are the same handle and only one of them can exist. Test a
   * handle with {@link AuthnClient.checkUsername} before submitting; sign-up
   * answers 409 `already_exists` when it was claimed in between.
   */
  username?: string;
  tenantId?: string;
  environment?: "test" | "live";
  metadata?: Record<string, unknown>;
}

interface LoginCredentials {
  /** Required, for the same reason as {@link SignUpParams.password}. */
  password: string;
  tenantId?: string;
  environment?: "test" | "live";
}

/**
 * LoginParams names the account by either field, and requires one of them.
 *
 * `identifier` is the field to use: it accepts an email address or a username,
 * which is what a sign-in form with one input box collects. `email` remains as an
 * alias so code written against the address-only form keeps compiling and
 * working; when both are given the engine reads `identifier`.
 *
 * The union is what makes "one of the two" a compile-time rule. A single
 * interface with both optional would accept `login({ password })`, which cannot
 * succeed.
 *
 * @example
 * ```ts
 * await authn.login({ identifier: form.identifier, password: form.password });
 * await authn.login({ email: "user@example.com", password: "SuperSecret123!" });
 * ```
 */
export type LoginParams = LoginCredentials &
  (
    | { identifier: string; email?: string }
    | { identifier?: string; email: string }
  );

export interface CheckUsernameParams {
  username: string;
  /**
   * The person's display name, used only to shape suggestions when the handle is
   * unavailable: it is what turns `alexsmith` into `alex_smith` rather than
   * `alexsmith4821`. Never stored by this call.
   */
  name?: string;
}

/**
 * Why a handle cannot be registered.
 *
 * `invalid` means no account could ever hold it — it breaks a structural rule.
 * `reserved` means it is well-formed but withheld from allocation. `taken` means
 * another account in this tenant and environment already holds it. Only `taken`
 * and `reserved` carry suggestions.
 */
export type UsernameUnavailableReason = "invalid" | "reserved" | "taken";

export interface UsernameAvailability {
  /** Echoed back as submitted, so a stale response can be discarded. */
  username: string;
  available: boolean;
  reason?: UsernameUnavailableReason;
  /** Sentence to show the person who typed it. Absent when available. */
  message?: string;
  /** Free alternatives, already checked against the same tenant. */
  suggestions?: string[];
}

export type UsernameAvailabilityResult =
  | { ok: true; availability: UsernameAvailability }
  | { ok: false; error: import("./errors").AuthnError };

export interface MagicLinkParams {
  email: string;
  /** Names the account when the address has none yet; the link auto-provisions one. */
  name?: string;
  tenantId?: string;
  environment?: "test" | "live";
}

export interface VerifyMagicLinkParams {
  token: string;
  tenantId?: string;
  environment?: "test" | "live";
}

export interface VerifyEmailParams {
  token: string;
  tenantId?: string;
  environment?: "test" | "live";
}

export interface ResendVerificationParams {
  email: string;
  tenantId?: string;
  environment?: "test" | "live";
}

export type AuthStateCallback = (
  user: import("./common").AuthnUser | null,
  session: import("./common").AuthnSession | null,
) => void;
