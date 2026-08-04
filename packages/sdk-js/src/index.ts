/**
 * @authn/js — Public API
 *
 * Everything exported from this barrel is the public contract of the SDK.
 * Internal modules (http, validation, logger) are NOT re-exported.
 *
 * @packageDocumentation
 */

// Client
export { AuthnClient } from "./client";

// Types
export type {
  AuthnClientConfig,
  AuthnLogger,
  AuthnUser,
  AuthnSession,
  PolicyWarning,
  AuthResult,
  SessionResult,
  VoidResult,
  SignUpParams,
  LoginParams,
  MagicLinkParams,
  VerifyMagicLinkParams,
  VerifyEmailParams,
  ResendVerificationParams,
  AuthStateCallback,
} from "./types";

// Error system
export { AuthnError, AuthnErrorCode, isAuthnError } from "./types";

// SDK version — injected at build time by tsup/esbuild
export const SDK_VERSION = "0.1.0";

// SDK name constant
export const SDK_NAME = "@authn/js";
