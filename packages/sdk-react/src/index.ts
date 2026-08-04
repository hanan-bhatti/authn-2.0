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
  useUser,
  useSignIn,
  useSignUp,
  useSignOut,
  useMagicLink,
} from "./hooks";
export type {
  AuthnProviderProps,
  AuthnContextValue,
  UseAuthReturn,
  UseSignInReturn,
  UseSignUpReturn,
  UseSignOutReturn,
  UseMagicLinkReturn,
} from "./types";
