import type { ReactNode } from "react";
import type {
  AuthnClient,
  AuthnClientConfig,
  AuthnError,
  AuthnSession,
  AuthnUser,
  AuthResult,
  BeginPasskeyLoginParams,
  BeginPasskeyLoginResult,
  BeginPasskeyRegistrationResult,
  Confirm2FAResult,
  ConfirmSMSParams,
  ConfirmTOTPParams,
  DisableSMSParams,
  DisableTOTPParams,
  EnrollSMSParams,
  EnrollSMSResult,
  EnrollTOTPResult,
  FinishPasskeyLoginParams,
  FinishPasskeyLoginResult,
  FinishPasskeyRegistrationParams,
  ListWebAuthnCredentialsResult,
  LoginParams,
  MagicLinkParams,
  RecoveryCodesStatusResult,
  RegenerateRecoveryCodesParams,
  RegenerateRecoveryCodesResult,
  RevokeWebAuthnCredentialParams,
  SignUpParams,
  VerifyMagicLinkParams,
  VerifyTOTPParams,
  VerifyTOTPResult,
  VoidResult,
  WebAuthnPasskey,
} from "@authn/js";

/**
 * Props for `<AuthnProvider>`.
 *
 * Enforces at the type level that either `publishableKey` (with optional config overrides)
 * OR an explicit pre-constructed `client` instance is provided — never both, and never neither.
 */
export type AuthnProviderProps = { children: ReactNode } & (
  | (Partial<Omit<AuthnClientConfig, "publishableKey">> & {
      publishableKey: string;
      client?: never;
    })
  | { client: AuthnClient; publishableKey?: never }
);

export interface AuthnContextValue {
  client: AuthnClient;
  user: AuthnUser | null;
  session: AuthnSession | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

export interface UseAuthReturn extends AuthnContextValue {}

export interface UseSignInReturn {
  signIn: (params: LoginParams) => Promise<AuthResult>;
  isLoading: boolean;
  error: AuthnError | null;
  reset: () => void;
}

export interface UseSignUpReturn {
  signUp: (params: SignUpParams) => Promise<AuthResult>;
  isLoading: boolean;
  error: AuthnError | null;
  reset: () => void;
}

export interface UseSignOutReturn {
  signOut: () => Promise<VoidResult>;
  isLoading: boolean;
  error: AuthnError | null;
  reset: () => void;
}

export interface UseMagicLinkReturn {
  sendMagicLink: (params: MagicLinkParams) => Promise<VoidResult>;
  verifyMagicLink: (params: VerifyMagicLinkParams) => Promise<AuthResult>;
  isLoading: boolean;
  error: AuthnError | null;
  reset: () => void;
}

export interface UseTOTPReturn {
  enrollTOTP: () => Promise<EnrollTOTPResult>;
  confirmTOTP: (params: ConfirmTOTPParams) => Promise<Confirm2FAResult>;
  disableTOTP: (params: DisableTOTPParams) => Promise<VoidResult>;
  verifyTOTP: (params: VerifyTOTPParams) => Promise<VerifyTOTPResult>;
  enrollSMS: (params: EnrollSMSParams) => Promise<EnrollSMSResult>;
  confirmSMS: (params: ConfirmSMSParams) => Promise<Confirm2FAResult>;
  disableSMS: (params: DisableSMSParams) => Promise<VoidResult>;
  regenerateRecoveryCodes: (
    params: RegenerateRecoveryCodesParams,
  ) => Promise<RegenerateRecoveryCodesResult>;
  getRecoveryCodesStatus: () => Promise<RecoveryCodesStatusResult>;
  isLoading: boolean;
  error: AuthnError | null;
  reset: () => void;
}

export interface UsePasskeysReturn {
  registerPasskey: (name?: string) => Promise<Confirm2FAResult>;
  loginWithPasskey: (mfaToken: string) => Promise<FinishPasskeyLoginResult>;
  listCredentials: () => Promise<ListWebAuthnCredentialsResult>;
  revokeCredential: (
    params: RevokeWebAuthnCredentialParams,
  ) => Promise<VoidResult>;
  beginRegistration: () => Promise<BeginPasskeyRegistrationResult>;
  finishRegistration: (
    params: FinishPasskeyRegistrationParams,
  ) => Promise<Confirm2FAResult>;
  beginLogin: (
    params: BeginPasskeyLoginParams,
  ) => Promise<BeginPasskeyLoginResult>;
  finishLogin: (
    params: FinishPasskeyLoginParams,
  ) => Promise<FinishPasskeyLoginResult>;
  credentials: WebAuthnPasskey[];
  isLoading: boolean;
  error: AuthnError | null;
  reset: () => void;
}

export type { UseOrganizationReturn } from "./hooks/useOrganization";
export type { UseOrgMembersReturn } from "./hooks/useOrgMembers";
