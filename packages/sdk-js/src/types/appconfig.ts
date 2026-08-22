/**
 * @authn/js — Application Bootstrap Configuration
 *
 * Mirrors `internal/appconfig` in the auth engine. Field names are camelCased
 * here; the wire format is snake_case and the client maps between them.
 *
 * @packageDocumentation
 */

import type { AuthnError } from "./errors";

/**
 * AppConfig is what a sign-in page fetches once, before it renders, to learn how
 * it should look, which options to offer, and what it may accept as a password.
 *
 * Two of those three are policies the page must agree with the server about: a
 * form enforcing a weaker password rule than the API produces a field that
 * accepts input the request then rejects, which reads to the user as a broken
 * site rather than a rule they broke.
 */
export interface AppConfig {
  /** The application the presented publishable key belongs to. */
  application: AppConfigApplication;
  /** The owning workspace's public identity. */
  tenant: AppConfigTenant;
  /** The tenant's presentational configuration. */
  branding: AppConfigBranding;
  /** What to offer as a way in. */
  signInMethods: SignInMethods;
  /** What to offer once a first factor succeeds. */
  secondFactors: SecondFactors;
  /** The password policy as the engine will actually enforce it. */
  passwordRules: PasswordRules;
  /** How the tenant treats an unverified address. */
  emailVerification: EmailVerificationPolicy;
  /** Which recovery proofs a locked-out user may offer. */
  accountRecovery: AccountRecoveryOptions;
}

export interface AppConfigApplication {
  id: string;
  name: string;
  /**
   * Taken from the key rather than the request, so a test-mode banner rendered
   * from this cannot be talked out of appearing by the page it warns about.
   */
  environment: "test" | "live";
}

export interface AppConfigTenant {
  name: string;
  slug: string;
}

/**
 * AppConfigBranding is the tenant's own styling. Every field may be empty,
 * meaning "inherit the client's default" rather than "render nothing".
 */
export interface AppConfigBranding {
  /** Product name for the sign-in card. Empty falls back to the app or tenant name. */
  appName: string;
  logoUrl: string;
  logoDarkUrl: string;
  faviconUrl: string;
  /** Hex colours. Applying these to CSS custom properties is what themes a page. */
  primaryColor: string;
  backgroundColor: string;
  textColor: string;
  buttonTextColor: string;
  /** A CSS font-family list, without the property name or terminating semicolon. */
  fontFamily: string;
  /** Footer links. An empty one means no such link, not a broken one. */
  supportUrl: string;
  termsUrl: string;
  privacyUrl: string;
  /** Appended to the hosted stylesheet. */
  customCss: string;
}

/**
 * SignInMethods is the set of first factors to offer.
 *
 * `password` and `passkey` are always true — they describe the surface the
 * engine compiles in. They are reported rather than assumed so a client reads
 * every capability from one place instead of hardcoding half of them.
 */
export interface SignInMethods {
  password: boolean;
  magicLink: boolean;
  passkey: boolean;
  /**
   * True when the tenant has at least one SAML connection. Which connection
   * serves a given user is resolved per email domain by a separate call, because
   * it depends on an address the user has not typed yet.
   */
  enterpriseSso: boolean;
  /** Enabled provider names, sorted, so buttons render in a stable order. */
  socialProviders: string[];
}

/**
 * SecondFactors is what a tenant's users may hold, which lets a page label an
 * MFA challenge before it knows which factor the user actually enrolled.
 */
export interface SecondFactors {
  totp: boolean;
  sms: boolean;
  passkey: boolean;
  recoveryCodes: boolean;
  push: boolean;
}

/**
 * PasswordRules is the effective policy — the bounds the engine will enforce,
 * not the ones the tenant stored. A tenant may store a minimum below the
 * engine's own floor; the floor still wins.
 */
export interface PasswordRules {
  minLength: number;
  maxLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumeric: boolean;
  requireSpecial: boolean;
  /**
   * Whether a non-compliant password is refused. When false the tenant is in
   * notify mode: the password is accepted and the unmet criteria come back as a
   * `policyWarning`, so a page should warn rather than block.
   */
  enforced: boolean;
}

export interface EmailVerificationPolicy {
  required: boolean;
  /**
   * `hard` refuses an unverified user access; `soft` admits them with the
   * unverified state flagged. A page shows a blocking screen for the first and a
   * dismissible banner for the second.
   */
  mode: "hard" | "soft";
}

export interface AccountRecoveryOptions {
  guardians: boolean;
  phoneOtp: boolean;
  emailOtp: boolean;
  oldPassword: boolean;
  securityQuestions: boolean;
  /** Bounds on how many guardians a user enrols, for validating before submit. */
  minGuardians: number;
  maxGuardians: number;
}

export type AppConfigResult =
  | { ok: true; config: AppConfig }
  | { ok: false; error: AuthnError };
