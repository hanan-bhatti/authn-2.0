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

// Domain 1 — Active Session Management
export type {
  AuthnDeviceInfo,
  AuthnDeviceSession,
  SessionListResult,
  RevokeSessionsResult,
} from "./types";

// Domain 2 — User Profile & Account Settings
export type {
  AuthnProfile,
  AuthnSocialAccount,
  AuthnRecoveryEmail,
  UpdateProfileParams,
  ProfileResult,
  RecoveryEmailResult,
  SocialAccountsResult,
} from "./types";

// Domain 3 — 2FA & Multi-Factor Authentication
export type {
  EnrollTOTPResult,
  ConfirmTOTPParams,
  Confirm2FAData,
  Confirm2FAResult,
  DisableTOTPParams,
  VerifyTOTPParams,
  VerifyTOTPResult,
  EnrollSMSParams,
  EnrollSMSResult,
  ConfirmSMSParams,
  DisableSMSParams,
  RegenerateRecoveryCodesParams,
  RegenerateRecoveryCodesResult,
  RecoveryCodesStatus,
  RecoveryCodesStatusResult,
  WebAuthnPasskey,
  ListWebAuthnCredentialsResult,
  RevokeWebAuthnCredentialParams,
  BeginPasskeyRegistrationResult,
  FinishPasskeyRegistrationParams,
  BeginPasskeyLoginParams,
  BeginPasskeyLoginResult,
  FinishPasskeyLoginParams,
  FinishPasskeyLoginResult,
} from "./types";

// Domain 4 — B2B Organizations & Team Member Invitations
export * from "./types/org";

// WebAuthn Helpers
export {
  bufferToBase64Url,
  base64UrlToBuffer,
  prepareCreationOptions,
  formatCreationCredential,
  prepareRequestOptions,
  formatRequestCredential,
} from "./webauthn";

// Error system
export { AuthnError, AuthnErrorCode, isAuthnError } from "./types";

// SDK version — injected at build time by tsup/esbuild
export const SDK_VERSION = "0.1.0";

// SDK name constant
export const SDK_NAME = "@authn/js";
