import type { ReactNode } from "react";
import type {
  AuthnClient,
  AuthnClientConfig,
  AuthnError,
  AuthnSession,
  AuthnUser,
  AuthResult,
  LoginParams,
  MagicLinkParams,
  SignUpParams,
  VerifyMagicLinkParams,
  VoidResult,
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
