"use client";

/**
 * @authn/react — Public API
 *
 * Official React SDK for the Authn Platform.
 *
 * @packageDocumentation
 */

export { AuthnProvider } from "./provider";
export {
  useAuth,
  useAppConfig,
  useUser,
  useSignIn,
  useSignUp,
  useSignOut,
  useMagicLink,
  useTOTP,
  usePasskeys,
  useOrganization,
  useOrgMembers,
  useGuardians,
  useAccountRecovery,
  useRBAC,
  useImpersonation,
  useWebhooks,
  useSAML,
  useAPIKeys,
  useAuditLogs,
  useTenantPolicies,
} from "./hooks";
export type {
  AuthnProviderProps,
  AuthnContextValue,
  UseAuthReturn,
  UseSignInReturn,
  UseSignUpReturn,
  UseSignOutReturn,
  UseMagicLinkReturn,
  UseTOTPReturn,
  UsePasskeysReturn,
  UseOrganizationReturn,
  UseOrgMembersReturn,
  UseGuardiansReturn,
  UseAccountRecoveryReturn,
} from "./types";
export type { UseAppConfigReturn } from "./hooks/useAppConfig";
