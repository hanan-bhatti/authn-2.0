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
  TwoFactorMethod,
  SessionResult,
  VoidResult,
  SignUpParams,
  LoginParams,
  CheckUsernameParams,
  UsernameAvailability,
  UsernameAvailabilityResult,
  UsernameUnavailableReason,
  MagicLinkParams,
  VerifyMagicLinkParams,
  VerifyEmailParams,
  ResendVerificationParams,
  AuthStateCallback,
} from "./types";

// Bootstrap — the document a sign-in page renders itself from
export type {
  AppConfig,
  AppConfigResult,
  AppConfigApplication,
  AppConfigTenant,
  AppConfigBranding,
  SignInMethods,
  SecondFactors,
  PasswordRules,
  EmailVerificationPolicy,
  AccountRecoveryOptions,
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
  DeleteAccountParams,
  BlockingOrganization,
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
  SendSMSChallengeParams,
  SendSMSChallengeResult,
  ConfirmSMSParams,
  DisableSMSParams,
  RegenerateRecoveryCodesParams,
  RegenerateRecoveryCodesResult,
  RecoveryCodesStatus,
  RecoveryCodesStatusResult,
  TwoFactorMethodState,
  SMSMethodState,
  TwoFactorMethods,
  TwoFactorMethodsResult,
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

// Domain 5 — Guardian Roster & Account Recovery
export * from "./types/guardians";
export * from "./types/recovery";
export * from "./types/securityquestions";

// WebAuthn Helpers
export {
  bufferToBase64Url,
  base64UrlToBuffer,
  prepareCreationOptions,
  formatCreationCredential,
  prepareRequestOptions,
  formatRequestCredential,
  isPasskeySupported,
  mapCeremonyError,
} from "./webauthn";
export type { PasskeyCeremonyOutcome } from "./webauthn";

// Username handle rules — shared with the engine, so a form can validate the
// shape of a handle without a round trip and word the failure the same way.
export {
  checkUsernameFormat,
  isValidUsernameFormat,
  USERNAME_MIN_LENGTH,
  USERNAME_MAX_LENGTH,
  USERNAME_MAX_INPUT_BYTES,
  USERNAME_RULE_HINT,
} from "./core/username";
export type { UsernameFormat, UsernameProblem } from "./core/username";

// Error system
export { AuthnError, AuthnErrorCode, isAuthnError } from "./types";

// Admin types
export * from "./types/admin";

/**
 * __SDK_VERSION__ is replaced with package.json's version at build time. It is
 * absent when the source is consumed directly — vitest, or a consumer compiling
 * from src — and `typeof` on an undeclared identifier is the one test that does
 * not throw there.
 */
declare const __SDK_VERSION__: string | undefined;

/** The published package version, or `0.0.0-dev` when running from source. */
export const SDK_VERSION: string =
  typeof __SDK_VERSION__ === "string" ? __SDK_VERSION__ : "0.0.0-dev";

// SDK name constant
export const SDK_NAME = "@authn/js";
