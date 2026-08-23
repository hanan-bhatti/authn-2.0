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
  tenantId?: string;
  environment?: "test" | "live";
  metadata?: Record<string, unknown>;
}

export interface LoginParams {
  email: string;
  /** Required, for the same reason as {@link SignUpParams.password}. */
  password: string;
  tenantId?: string;
  environment?: "test" | "live";
}

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
