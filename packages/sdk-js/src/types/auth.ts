/**
 * @authn/js — Authentication Parameters Types
 *
 * @packageDocumentation
 */

export interface SignUpParams {
  email: string;
  password?: string;
  name?: string;
  tenantId?: string;
  environment?: "test" | "live";
  metadata?: Record<string, unknown>;
}

export interface LoginParams {
  email: string;
  password?: string;
  tenantId?: string;
  environment?: "test" | "live";
}

export interface MagicLinkParams {
  email: string;
  name?: string;
  redirectUrl?: string;
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
