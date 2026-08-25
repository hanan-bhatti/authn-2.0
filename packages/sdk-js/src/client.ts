/**
 * @authn/js — AuthnClient
 *
 * The primary SDK class. Handles sign-up, login, magic links, email
 * verification, session management, and automatic silent token refresh.
 *
 * @example
 * ```ts
 * import { AuthnClient } from "@authn/js";
 *
 * const authn = new AuthnClient({
 *   publishableKey: "pk_test_abc123def456ghi789jkl012mno345pq",
 *   endpoint: "http://localhost:8080",
 * });
 *
 * const result = await authn.login({ email: "user@example.com", password: "Secret123!" });
 * if (result.ok) {
 *   console.log("Welcome,", result.session.user.name);
 * } else {
 *   console.error(result.error.code, result.error.message);
 * }
 * ```
 *
 * @packageDocumentation
 */

import { HttpClient } from "./core/http";
import { DefaultLogger } from "./core/logger";
import type {
  AcceptGuardianInviteParams,
  AcceptGuardianInviteResult,
  AcceptOrgInvitationParams,
  AcceptOrgInvitationResult,
  AppConfig,
  AppConfigResult,
  AuthnClientConfig,
  AuthnDeviceSession,
  AuthnGuardian,
  AuthnLogger,
  AuthnOrg,
  AuthnOrgInvitation,
  AuthnOrgMember,
  AuthnProfile,
  AuthnSession,
  AuthnUser,
  AuthResult,
  AuthStateCallback,
  BeginPasskeyLoginParams,
  BeginPasskeyLoginResult,
  BeginPasskeyRegistrationResult,
  CancelRecoveryParams,
  CancelRecoveryResult,
  CancelRecoveryTokenParams,
  CancelRecoveryTokenResult,
  CheckUsernameParams,
  ClaimAccountParams,
  ClaimAccountResult,
  Confirm2FAResult,
  ConfirmSMSParams,
  ConfirmTOTPParams,
  CreateOrgParams,
  CreateOrgResult,
  DeleteAccountParams,
  DeleteOrgResult,
  DeleteSecurityQuestionsParams,
  DisableSMSParams,
  DisableTOTPParams,
  EnrollSMSParams,
  EnrollSMSResult,
  EnrollTOTPResult,
  FinishPasskeyLoginParams,
  FinishPasskeyLoginResult,
  FinishPasskeyRegistrationParams,
  GetOrgResult,
  InitiateRecoveryParams,
  InitiateRecoveryResult,
  InviteGuardiansParams,
  InviteGuardiansResult,
  InviteOrgMemberParams,
  InviteOrgMemberResult,
  ListGuardiansResult,
  ListInvitationsResult,
  ListOrgMembersResult,
  ListOrgsResult,
  ListWebAuthnCredentialsResult,
  LoginParams,
  MagicLinkParams,
  PolicyWarning,
  ProfileResult,
  RecoveryCodesStatusResult,
  TwoFactorMethodState,
  TwoFactorMethodsResult,
  RecoveryEmailResult,
  RegenerateRecoveryCodesParams,
  RegenerateRecoveryCodesResult,
  ResendVerificationParams,
  RemoveOrgMemberResult,
  RevokeGuardianResult,
  RevokeSessionsResult,
  RevokeWebAuthnCredentialParams,
  SessionListResult,
  SecurityQuestion,
  SecurityQuestionsResult,
  SendSMSChallengeParams,
  SendSMSChallengeResult,
  SessionResult,
  SetSecurityQuestionsParams,
  SignUpParams,
  SocialAccountsResult,
  SubmitGuardianProofParams,
  SubmitGuardianProofResult,
  SubmitOldPasswordProofParams,
  SubmitOldPasswordProofResult,
  SubmitSecurityQuestionsProofParams,
  SubmitSecurityQuestionsProofResult,
  TwoFactorMethod,
  UpdateOrgMemberRoleParams,
  UpdateOrgMemberRoleResult,
  UpdateOrgParams,
  UpdateOrgResult,
  UpdateProfileParams,
  UsernameAvailabilityResult,
  UsernameUnavailableReason,
  VerifyEmailParams,
  VerifyMagicLinkParams,
  VerifyTOTPParams,
  VerifyTOTPResult,
  VoidResult,
  WebAuthnPasskey,
} from "./types";
import { AuthnError, AuthnErrorCode } from "./types";
import { checkUsernameFormat } from "./core/username";
import {
  assertValid,
  validateEmail,
  validateEnvironment,
  validateLoginIdentifier,
  validatePassword,
  validatePhoneNumber,
  validatePublishableKey,
  validateRecoveryCode,
  validateTenantId,
  validateToken,
  validateTOTPCode,
  validateUsername,
  validateWebAuthnCredential,
} from "./core/validation";
import {
  formatCreationCredential,
  formatRequestCredential,
  mapCeremonyError,
  prepareCreationOptions,
  prepareRequestOptions,
} from "./webauthn/webauthn-helpers";

// ---------------------------------------------------------------------------
// Server response shapes (internal — never exported)
// ---------------------------------------------------------------------------

interface ServerAuthResponse {
  user: {
    id: string;
    email: string;
    email_verified: boolean;
    name?: string;
    username?: string;
    status: string;
    created_at: string;
  };
  access_token: string;
  refresh_token?: string;
  expires_at?: number;
  policy_warning?: {
    requires_password_upgrade?: boolean;
    requires_email_verification?: boolean;
    missing_criteria?: string[];
  };
  /**
   * Set when the password was accepted but a second factor is outstanding. The
   * response then carries mfa_token in place of access_token, so a caller that
   * reads it as a session builds one with no credential in it.
   */
  mfa_required?: boolean;
  mfa_token?: string;
  methods?: string[];
}

/** Mirrors auth.UsernameAvailabilityResponse in the Go backend. */
interface ServerUsernameAvailabilityResponse {
  username?: string;
  available?: boolean;
  reason?: string;
  message?: string;
  suggestions?: string[];
}

/** Mirrors appconfig.AppConfig in the Go backend. */
interface ServerAppConfigResponse {
  application: { id: string; name: string; environment: string };
  tenant: { name: string; slug: string };
  branding: {
    app_name: string;
    logo_url: string;
    logo_dark_url: string;
    favicon_url: string;
    primary_color: string;
    background_color: string;
    text_color: string;
    button_text_color: string;
    font_family: string;
    support_url: string;
    terms_url: string;
    privacy_url: string;
    custom_css: string;
  };
  sign_in_methods: {
    password: boolean;
    magic_link: boolean;
    passkey: boolean;
    enterprise_sso: boolean;
    social_providers: string[];
  };
  second_factors: {
    totp: boolean;
    sms: boolean;
    passkey: boolean;
    recovery_codes: boolean;
    push: boolean;
  };
  password_rules: {
    min_length: number;
    max_length: number;
    require_uppercase: boolean;
    require_lowercase: boolean;
    require_numeric: boolean;
    require_special: boolean;
    enforced: boolean;
  };
  email_verification: { required: boolean; mode: string };
  account_recovery: {
    guardians: boolean;
    phone_otp: boolean;
    email_otp: boolean;
    old_password: boolean;
    security_questions: boolean;
    min_guardians: number;
    max_guardians: number;
  };
}

interface ServerMessageResponse {
  message: string;
}

/** Mirrors `session.SessionResponse` in the Go backend. */
interface ServerSessionResponse {
  id: string;
  device: {
    browser: string;
    os: string;
    device: string;
    label: string;
  };
  ip_address: string;
  location: string;
  last_active_at?: string;
  created_at: string;
  is_current: boolean;
}

/** Mirrors `user.UserProfileResponse` in the Go backend. */
interface ServerProfileResponse {
  id: string;
  tenant_id: string;
  email: string;
  email_verified: boolean;
  /** Absent on an account that has claimed no handle, which is a valid state. */
  username?: string;
  name?: string;
  phone_number?: string;
  phone_verified: boolean;
  recovery_email?: string;
  recovery_email_verified: boolean;
  avatar_url?: string;
  locale?: string;
  status?: "active" | "suspended" | "banned";
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

/** Mirrors `user.LinkedSocialAccount` in the Go backend. */
interface ServerSocialAccount {
  provider: string;
  provider_user_id: string;
  email?: string;
  connected_at: string;
}

interface ServerEnrollTOTPResponse {
  secret: string;
  uri: string;
}

interface ServerConfirmTOTPResponse {
  message: string;
  recovery_codes?: string[];
  recovery_codes_created: boolean;
}

interface ServerEnrollSMSResponse {
  message: string;
  expires_in_seconds: number;
}

interface ServerSMSChallengeResponse {
  message: string;
  phone_number: string;
  expires_in_seconds: number;
}

interface ServerRegenerateRecoveryCodesResponse {
  message: string;
  recovery_codes: string[];
}

interface ServerRecoveryCodesStatusResponse {
  remaining_count: number;
  total_count: number;
  has_recovery_codes: boolean;
}

interface ServerTwoFactorMethodState {
  enabled: boolean;
  created_at?: string;
  last_used_at?: string;
}

interface ServerTwoFactorMethodsResponse {
  methods: string[];
  totp: ServerTwoFactorMethodState;
  sms: ServerTwoFactorMethodState & { phone_number?: string };
}

interface ServerBeginPasskeyRegistrationResponse {
  options: Record<string, unknown>;
  session_id: string;
}

interface ServerBeginPasskeyLoginResponse {
  options: Record<string, unknown>;
  session_id: string;
  user_id: string;
}

/** Mirrors `auth.PasskeyDTO` in the Go backend. */
interface ServerPasskey {
  id: string;
  name: string;
  credential_id: string;
  sign_count: number;
  created_at: string;
  last_used_at?: string;
  /**
   * The AAGUID, attestation type, transports and authenticator flags captured
   * during the ceremony. Untyped because it is a free-form bag on the server and
   * an authenticator that reports nothing leaves it empty.
   */
  metadata?: Record<string, unknown>;
}

interface ServerListPasskeysResponse {
  credentials: ServerPasskey[];
}

/** Mirrors org.OrgResponse in the Go backend. */
interface ServerOrgResponse {
  id: string;
  tenant_id: string;
  name: string;
  slug: string;
  logo_url?: string;
  metadata?: Record<string, unknown>;
  is_admin?: boolean;
  created_at: string;
}

/** Mirrors org.OrgMemberResponse in the Go backend. */
interface ServerOrgMemberResponse {
  id: string;
  organization_id: string;
  user_id: string;
  role_id: string;
  role_slug?: string;
  role_name?: string;
  is_admin?: boolean;
  assigned_by_user_id?: string;
  created_at: string;
  updated_at: string;
}

/** Mirrors org.OrgInvitationResponse in the Go backend. */
interface ServerOrgInvitationResponse {
  id: string;
  organization_id: string;
  organization_name?: string;
  email: string;
  role_id: string;
  invited_by_user_id?: string;
  invitation_token?: string;
  status: string;
  expires_at: string;
  created_at: string;
}

/** Mirrors auth.GuardianDTO in the Go backend. */
interface ServerGuardianResponse {
  id: string;
  guardian_email: string;
  guardian_name: string;
  share_index: number;
  status: string;
  created_at: string;
}

function mapGuardian(raw: ServerGuardianResponse): AuthnGuardian {
  return {
    id: raw.id,
    guardianEmail: raw.guardian_email,
    guardianName: raw.guardian_name,
    shareIndex: raw.share_index,
    status: raw.status,
    createdAt: raw.created_at,
  };
}

// ---------------------------------------------------------------------------
// Org response mappers (snake_case → camelCase)
// ---------------------------------------------------------------------------

function mapOrg(raw: ServerOrgResponse): AuthnOrg {
  return {
    id: raw.id,
    tenantId: raw.tenant_id,
    name: raw.name,
    slug: raw.slug,
    logoUrl: raw.logo_url,
    metadata: raw.metadata,
    // Defaulted to false rather than left undefined: the field decides whether an
    // administrative control is shown, and an absent value must fail closed.
    isAdmin: raw.is_admin ?? false,
    createdAt: raw.created_at,
  };
}

function mapMember(raw: ServerOrgMemberResponse): AuthnOrgMember {
  return {
    id: raw.id,
    organizationId: raw.organization_id,
    userId: raw.user_id,
    roleId: raw.role_id,
    roleSlug: raw.role_slug,
    roleName: raw.role_name,
    isAdmin: raw.is_admin ?? false,
    assignedByUserId: raw.assigned_by_user_id,
    createdAt: raw.created_at,
    updatedAt: raw.updated_at,
  };
}

function mapInvitation(raw: ServerOrgInvitationResponse): AuthnOrgInvitation {
  return {
    id: raw.id,
    organizationId: raw.organization_id,
    organizationName: raw.organization_name,
    email: raw.email,
    roleId: raw.role_id,
    invitedByUserId: raw.invited_by_user_id,
    invitationToken: raw.invitation_token,
    status: raw.status as AuthnOrgInvitation["status"],
    expiresAt: raw.expires_at,
    createdAt: raw.created_at,
  };
}

/**
 * newAbortController builds the controller a client's lifetime hangs off, or
 * undefined where the runtime has no AbortController.
 *
 * The SDK supports environments older than the API — React Native releases and
 * long-lived embedded WebViews among them — and construction is not the place to
 * fail over a capability that only makes teardown tidier.
 */
function newAbortController(): AbortController | undefined {
  try {
    return new AbortController();
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// AuthnClient
// ---------------------------------------------------------------------------

export class AuthnClient {
  private readonly http: HttpClient;
  private readonly logger: AuthnLogger;
  private readonly config: Required<
    Pick<AuthnClientConfig, "endpoint" | "timeout" | "autoRefresh">
  > &
    AuthnClientConfig;

  private currentSession: AuthnSession | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly stateListeners = new Set<AuthStateCallback>();
  private refreshInProgress: Promise<SessionResult> | null = null;
  private destroyed = false;

  /**
   * Aborted by {@link destroy}, cancelling every request this client has in
   * flight along with any retry still backing off.
   *
   * Undefined where AbortController is unavailable; the client then still
   * refuses new calls after destruction, it simply cannot recall the ones
   * already sent.
   */
  private readonly lifetime: AbortController | undefined = newAbortController();

  constructor(config: AuthnClientConfig) {
    const publishableKey =
      config.publishableKey ||
      (typeof process !== "undefined" && process.env
        ? process.env["NEXT_PUBLIC_AUTHN_PUBLISHABLE_KEY"] ||
          process.env["AUTHN_PUBLISHABLE_KEY"]
        : undefined);

    // Validate configuration upfront
    assertValid(validatePublishableKey(publishableKey));

    if (config.endpoint !== undefined && typeof config.endpoint !== "string") {
      throw AuthnError.invalidConfig("endpoint", "Must be a string URL.");
    }
    if (
      config.timeout !== undefined &&
      (typeof config.timeout !== "number" || config.timeout < 0)
    ) {
      throw AuthnError.invalidConfig(
        "timeout",
        "Must be a positive number (milliseconds).",
      );
    }

    const endpoint = (config.endpoint ?? "https://api.authn.com").replace(
      /\/+$/,
      "",
    );
    const timeout = config.timeout ?? 10_000;
    const autoRefresh = config.autoRefresh !== false;
    const logger = config.logger ?? new DefaultLogger();

    // Infer environment from key prefix
    const inferredEnv = publishableKey!.startsWith("pk_live_")
      ? "live"
      : "test";

    this.config = {
      ...config,
      publishableKey: publishableKey!,
      endpoint,
      timeout,
      autoRefresh,
      environment: config.environment ?? inferredEnv,
    };
    this.logger = logger;

    this.http = new HttpClient({
      baseUrl: endpoint,
      apiKey: publishableKey!,
      timeout,
      logger,
      customFetch: config.fetch,
      getAccessToken: () => this.getToken(),
      onRefreshToken: () => this.refreshSession(),
      lifetimeSignal: this.lifetime?.signal,
    });

    this.logger.info("AuthnClient initialized", {
      endpoint,
      environment: this.config.environment,
      autoRefresh,
    });
  }

  // -----------------------------------------------------------------------
  // Bootstrap
  // -----------------------------------------------------------------------

  /**
   * Fetch the configuration a sign-in or sign-up page needs before it renders:
   * branding, which methods to offer, and the password policy it must agree with.
   *
   * Call this first and render from the answer. Hardcoding the form instead
   * produces a page that offers methods the tenant disabled and a password field
   * whose rules disagree with the ones the request is judged against.
   *
   * The response is cacheable and the engine says so, so a browser serves
   * repeat calls without a round trip.
   *
   * @returns `{ ok: true, config }` on success, `{ ok: false, error }` on failure.
   *
   * @example
   * ```ts
   * const bootstrap = await authn.getAppConfig();
   * if (bootstrap.ok && bootstrap.config.signInMethods.magicLink) {
   *   showMagicLinkButton();
   * }
   * ```
   */
  async getAppConfig(): Promise<AppConfigResult> {
    this.guardDestroyed();

    try {
      const res = await this.http.get<ServerAppConfigResponse>(
        "/v1/client/app-config",
      );

      return { ok: true, config: mapAppConfig(res.data) };
    } catch (err) {
      return this.handleError(err, "getAppConfig");
    }
  }

  // -----------------------------------------------------------------------
  // Sign Up
  // -----------------------------------------------------------------------

  /**
   * Create a new user account with email and password.
   *
   * @param params - Sign-up parameters.
   * @returns `{ ok: true, session }` on success, `{ ok: false, error }` on failure.
   *
   * @example
   * ```ts
   * const result = await authn.signUp({
   *   email: "user@example.com",
   *   password: "SuperSecret123!",
   *   name: "Alex Smith",
   *   username: "alexsmith",
   * });
   * ```
   */
  async signUp(params: SignUpParams): Promise<AuthResult> {
    this.guardDestroyed();

    // Validate inputs before network call
    assertValid(validateEmail(params.email));
    assertValid(validatePassword(params.password));
    // Only when one was given: an account without a handle is a valid account,
    // so an absent username is not a validation failure.
    if (params.username !== undefined && params.username !== "") {
      assertValid(validateUsername(params.username));
    }
    assertValid(validateTenantId(params.tenantId));
    assertValid(validateEnvironment(params.environment));

    try {
      const res = await this.http.post<ServerAuthResponse>(
        "/v1/client/auth/signup",
        {
          email: params.email,
          password: params.password,
          name: params.name,
          username: params.username,
          tenant_id: this.resolveTenantId(params.tenantId),
          environment: this.resolveEnvironment(params.environment),
        },
      );

      return this.resolveAuthResponse(res.data, "Sign-up");
    } catch (err) {
      return this.handleError(err, "signUp");
    }
  }

  /**
   * Ask whether a username can be registered, and what to use instead if not.
   *
   * Intended to be called while the field is being typed, behind a debounce of
   * around 300ms. It creates nothing and reserves nothing: a handle reported free
   * can be claimed by somebody else a moment later, and sign-up answers 409
   * `already_exists` when that happens. Treat this as guidance, and the sign-up
   * response as the verdict.
   *
   * Shape problems are answered here without a request, using the same rules and
   * the same wording the engine uses. Everything else — taken, reserved, and the
   * suggestions — needs the server.
   *
   * @returns `{ ok: true, availability }` including when the handle is unavailable;
   * `ok: false` means the question could not be asked, not that the answer was no.
   *
   * @example
   * ```ts
   * const res = await authn.checkUsername({ username: "alex", name: "Alex Smith" });
   * if (res.ok && !res.availability.available) {
   *   showError(res.availability.message, res.availability.suggestions);
   * }
   * ```
   */
  async checkUsername(
    params: CheckUsernameParams,
  ): Promise<UsernameAvailabilityResult> {
    this.guardDestroyed();

    const format = checkUsernameFormat(params.username);
    if (!format.valid) {
      return {
        ok: true,
        availability: {
          username: params.username,
          available: false,
          reason: "invalid",
          message: format.message,
        },
      };
    }

    try {
      const res = await this.http.get<ServerUsernameAvailabilityResponse>(
        "/v1/client/auth/username-available",
        { username: params.username, name: params.name ?? "" },
      );

      return {
        ok: true,
        availability: {
          username: res.data.username ?? params.username,
          available: res.data.available === true,
          reason: res.data.reason as UsernameUnavailableReason | undefined,
          message: res.data.message,
          suggestions: res.data.suggestions,
        },
      };
    } catch (err) {
      return this.handleError(err, "checkUsername");
    }
  }

  // -----------------------------------------------------------------------
  // Login
  // -----------------------------------------------------------------------

  /**
   * Authenticate an existing user with an email address or a username.
   *
   * @param params - Login parameters. Pass `identifier` for either kind of
   * handle; `email` is accepted as an alias and used when `identifier` is absent.
   * @returns `{ ok: true, session }` on success, `{ ok: false, error }` on failure.
   *
   * @example
   * ```ts
   * const result = await authn.login({
   *   identifier: "alexsmith",
   *   password: "SuperSecret123!",
   * });
   * if (!result.ok && result.error.code === AuthnErrorCode.INVALID_CREDENTIALS) {
   *   showError("Wrong email, username or password");
   * }
   * ```
   */
  async login(params: LoginParams): Promise<AuthResult> {
    this.guardDestroyed();

    const identifier = (params.identifier ?? params.email ?? "").trim();

    // The identifier's shape is deliberately unchecked past a length ceiling. It
    // may be an address or a handle, and refusing one that is neither would
    // answer a mistyped handle with a message about email format — and would
    // reveal, before any request, which shapes the engine can resolve.
    assertValid(validateLoginIdentifier(identifier));
    assertValid(validatePassword(params.password));
    assertValid(validateTenantId(params.tenantId));
    assertValid(validateEnvironment(params.environment));

    try {
      const res = await this.http.post<ServerAuthResponse>(
        "/v1/client/auth/login",
        {
          identifier,
          password: params.password,
          tenant_id: this.resolveTenantId(params.tenantId),
          environment: this.resolveEnvironment(params.environment),
        },
      );

      return this.resolveAuthResponse(res.data, "Login");
    } catch (err) {
      return this.handleError(err, "login");
    }
  }

  // -----------------------------------------------------------------------
  // Magic Links (Passwordless)
  // -----------------------------------------------------------------------

  /**
   * Request a magic login link be sent to the provided email.
   *
   * If the email doesn't have an account, one is auto-provisioned.
   * The link is valid for 15 minutes and single-use.
   *
   * @param params - Magic link request parameters.
   * @returns `{ ok: true, message }` on success.
   */
  async sendMagicLink(params: MagicLinkParams): Promise<VoidResult> {
    this.guardDestroyed();

    assertValid(validateEmail(params.email));
    assertValid(validateTenantId(params.tenantId));
    assertValid(validateEnvironment(params.environment));

    try {
      const res = await this.http.post<ServerMessageResponse>(
        "/v1/client/auth/magic-link",
        {
          email: params.email,
          name: params.name,
          tenant_id: this.resolveTenantId(params.tenantId),
          environment: this.resolveEnvironment(params.environment),
        },
      );

      this.logger.info("Magic link sent", { email: params.email });
      return { ok: true, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "sendMagicLink");
    }
  }

  /**
   * Verify a magic link token and establish a session.
   *
   * @param params - Token and optional tenant/environment overrides.
   * @returns `{ ok: true, session }` on success.
   */
  async verifyMagicLink(params: VerifyMagicLinkParams): Promise<AuthResult> {
    this.guardDestroyed();

    assertValid(validateToken(params.token, "token"));
    assertValid(validateTenantId(params.tenantId));
    assertValid(validateEnvironment(params.environment));

    try {
      const res = await this.http.post<ServerAuthResponse>(
        "/v1/client/auth/magic-link/verify",
        {
          token: params.token,
          tenant_id: this.resolveTenantId(params.tenantId),
          environment: this.resolveEnvironment(params.environment),
        },
      );

      return this.resolveAuthResponse(res.data, "Magic link");
    } catch (err) {
      return this.handleError(err, "verifyMagicLink");
    }
  }

  // -----------------------------------------------------------------------
  // Email Verification
  // -----------------------------------------------------------------------

  /**
   * Verify a user's email address using the token from the verification email.
   *
   * @param params - Verification token.
   * @returns `{ ok: true }` on success.
   */
  async verifyEmail(params: VerifyEmailParams): Promise<VoidResult> {
    this.guardDestroyed();

    assertValid(validateToken(params.token, "token"));

    try {
      await this.http.get<ServerMessageResponse>(
        "/v1/client/auth/verify-email",
        { token: params.token },
      );

      this.logger.info("Email verified");

      // Update local session if the verified user matches
      if (this.currentSession) {
        this.currentSession = {
          ...this.currentSession,
          user: { ...this.currentSession.user, emailVerified: true },
        };
        this.notifyListeners();
      }

      return { ok: true };
    } catch (err) {
      return this.handleError(err, "verifyEmail");
    }
  }

  /**
   * Request a new verification email be sent.
   *
   * @param params - Email address and optional tenant/environment.
   * @returns `{ ok: true }` on success.
   */
  async resendVerification(
    params: ResendVerificationParams,
  ): Promise<VoidResult> {
    this.guardDestroyed();

    assertValid(validateEmail(params.email));
    assertValid(validateTenantId(params.tenantId));
    assertValid(validateEnvironment(params.environment));

    try {
      await this.http.post<ServerMessageResponse>(
        "/v1/client/auth/resend-verification",
        {
          email: params.email,
          tenant_id: this.resolveTenantId(params.tenantId),
          environment: this.resolveEnvironment(params.environment),
        },
      );

      this.logger.info("Verification email resent", { email: params.email });
      return { ok: true };
    } catch (err) {
      return this.handleError(err, "resendVerification");
    }
  }

  // -----------------------------------------------------------------------
  // Session Management
  // -----------------------------------------------------------------------

  /**
   * Get the current user, or `null` if not authenticated.
   */
  getUser(): AuthnUser | null {
    return this.currentSession?.user ?? null;
  }

  /**
   * Get the current access token, or `null` if not authenticated.
   * The token is automatically refreshed before expiry when `autoRefresh` is enabled.
   */
  getToken(): string | null {
    return this.currentSession?.accessToken ?? null;
  }

  /**
   * Get the full current session, or `null` if not authenticated.
   */
  getSession(): AuthnSession | null {
    return this.currentSession;
  }

  /**
   * Check whether the user is currently authenticated.
   */
  isAuthenticated(): boolean {
    return this.currentSession !== null;
  }

  /**
   * Silently refresh the access token using the refresh token cookie.
   *
   * Called automatically when `autoRefresh` is enabled. Can also be called
   * manually to force a refresh.
   *
   * Uses request deduplication — concurrent calls return the same promise.
   */
  async refreshSession(): Promise<SessionResult> {
    this.guardDestroyed();

    // Deduplicate concurrent refresh calls
    if (this.refreshInProgress) {
      this.logger.debug("Refresh already in progress, deduplicating…");
      return this.refreshInProgress;
    }

    this.refreshInProgress = this.executeRefresh();

    try {
      return await this.refreshInProgress;
    } finally {
      this.refreshInProgress = null;
    }
  }

  // -----------------------------------------------------------------------
  // Auth State Listener
  // -----------------------------------------------------------------------

  /**
   * Subscribe to authentication state changes.
   *
   * The callback fires immediately with the current state, then on every
   * login, logout, sign-up, or token refresh.
   *
   * @param callback - Invoked with `(user, session)`. Both are `null` when unauthenticated.
   * @returns Unsubscribe function — call it to stop receiving updates.
   *
   * @example
   * ```ts
   * const unsubscribe = authn.onAuthStateChanged((user, session) => {
   *   if (user) {
   *     showDashboard(user);
   *   } else {
   *     showLoginPage();
   *   }
   * });
   *
   * // Later: unsubscribe();
   * ```
   */
  onAuthStateChanged(callback: AuthStateCallback): () => void {
    this.stateListeners.add(callback);

    // Fire immediately with current state
    callback(
      this.currentSession?.user ?? null,
      this.currentSession,
    );

    return () => {
      this.stateListeners.delete(callback);
    };
  }

  // -----------------------------------------------------------------------
  // Sign Out
  // -----------------------------------------------------------------------

  /**
   * Sign the user out. Clears the local session and notifies the server
   * to invalidate the refresh token.
   *
   * Server-side errors are silently caught — the local session is always cleared.
   */
  async signOut(): Promise<VoidResult> {
    this.guardDestroyed();

    try {
      await this.http.post("/v1/client/auth/logout", {}).catch(() => {
        // Best-effort server notification — local state is always cleared
      });
    } catch {
      // Swallow — we always clear the local session
    }

    this.setSession(null);
    this.logger.info("Signed out");
    return { ok: true };
  }

  // -----------------------------------------------------------------------
  // Active Session Management (Domain 1)
  // -----------------------------------------------------------------------

  /**
   * List every active login session for the current user, across all devices.
   *
   * The entry for the session this client is authenticated with is flagged
   * with `isCurrent: true`.
   *
   * Requires an authenticated session.
   *
   * @example
   * ```ts
   * const result = await authn.listSessions();
   * if (result.ok) {
   *   for (const s of result.sessions) {
   *     console.log(s.device.label, s.location, s.isCurrent ? "(this device)" : "");
   *   }
   * }
   * ```
   */
  async listSessions(): Promise<SessionListResult> {
    this.guardDestroyed();

    try {
      const res = await this.http.get<{ sessions: ServerSessionResponse[] }>(
        "/v1/client/sessions",
      );
      const sessions = (res.data.sessions ?? []).map((s) =>
        this.mapDeviceSession(s),
      );
      return { ok: true, sessions };
    } catch (err) {
      return this.handleError(err, "listSessions");
    }
  }

  /**
   * Revoke a single session by ID, signing that device out.
   *
   * Revoking the current session does not clear local state — call
   * {@link AuthnClient.signOut} for that.
   *
   * Requires an authenticated session. The server rejects attempts to revoke
   * a session belonging to another user with a `403`.
   */
  async revokeSession(sessionId: string): Promise<RevokeSessionsResult> {
    this.guardDestroyed();

    try {
      assertValid(validateToken(sessionId, "sessionId"));

      const res = await this.http.post<{ message?: string }>(
        "/v1/client/sessions/revoke",
        { session_id: sessionId },
      );
      // The server echoes the revoked session_id rather than a count.
      return { ok: true, count: 1, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "revokeSession");
    }
  }

  /**
   * Revoke every session except the one this client is using — the
   * "sign out everywhere else" action.
   *
   * Requires an authenticated session.
   */
  async revokeOtherSessions(): Promise<RevokeSessionsResult> {
    this.guardDestroyed();

    try {
      const res = await this.http.post<{ message?: string; count?: number }>(
        "/v1/client/sessions/revoke-others",
        {},
      );
      return {
        ok: true,
        count: res.data.count ?? 0,
        message: res.data.message,
      };
    } catch (err) {
      return this.handleError(err, "revokeOtherSessions");
    }
  }

  /**
   * Revoke every session for the current user, including this one.
   *
   * The local session is cleared on success, since the tokens this client
   * holds are now invalid server-side. Auth state listeners fire with `null`.
   */
  async revokeAllSessions(): Promise<RevokeSessionsResult> {
    this.guardDestroyed();

    try {
      const res = await this.http.post<{ message?: string; count?: number }>(
        "/v1/client/sessions/revoke-all",
        {},
      );

      // This client's own tokens were just invalidated server-side — reflect
      // that locally rather than leaving a session that can no longer be used.
      this.setSession(null);

      return {
        ok: true,
        count: res.data.count ?? 0,
        message: res.data.message,
      };
    } catch (err) {
      return this.handleError(err, "revokeAllSessions");
    }
  }

  // -----------------------------------------------------------------------
  // User Profile & Account Settings (Domain 2)
  // -----------------------------------------------------------------------

  /**
   * Fetch the current user's full profile.
   *
   * Richer than `getUser()`, which returns the compact user object embedded in
   * the session and does not require a network call.
   *
   * Requires an authenticated session.
   */
  async getProfile(): Promise<ProfileResult> {
    this.guardDestroyed();

    try {
      const res = await this.http.get<ServerProfileResponse>(
        "/v1/client/user/profile",
      );
      return { ok: true, profile: this.mapProfile(res.data) };
    } catch (err) {
      return this.handleError(err, "getProfile");
    }
  }

  /**
   * Update mutable profile fields. Omitted fields are left unchanged.
   *
   * Requires an authenticated session.
   *
   * @example
   * ```ts
   * await authn.updateProfile({ name: "Ada Lovelace", locale: "en-GB" });
   * ```
   */
  async updateProfile(params: UpdateProfileParams = {}): Promise<ProfileResult> {
    this.guardDestroyed();

    try {
      // Only send keys the caller actually provided — the server treats an
      // absent key as "leave unchanged" but an explicit null as invalid.
      const body: Record<string, unknown> = {};
      if (params.name !== undefined) body["name"] = params.name;
      // Sent verbatim, including the empty string, which is how a handle is
      // released. Trimming or dropping it here would make "clear my username"
      // unexpressible through the SDK.
      if (params.username !== undefined) body["username"] = params.username;
      if (params.avatarUrl !== undefined) body["avatar_url"] = params.avatarUrl;
      if (params.locale !== undefined) body["locale"] = params.locale;
      if (params.metadata !== undefined) body["metadata"] = params.metadata;

      const res = await this.http.patch<ServerProfileResponse>(
        "/v1/client/user/profile",
        body,
      );
      return { ok: true, profile: this.mapProfile(res.data) };
    } catch (err) {
      return this.handleError(err, "updateProfile");
    }
  }

  /**
   * Change the account password.
   *
   * The server returns `401` when `currentPassword` is wrong, which surfaces
   * here as an {@link AuthnError} with code `UNAUTHORIZED` — it does *not*
   * trigger the silent-refresh interceptor, because this client's access token
   * is still valid.
   *
   * Requires an authenticated session.
   */
  async changePassword(
    currentPassword: string,
    newPassword: string,
  ): Promise<VoidResult> {
    this.guardDestroyed();

    try {
      assertValid(validateToken(currentPassword, "currentPassword"));
      assertValid(validatePassword(newPassword));

      const res = await this.http.post<ServerMessageResponse>(
        "/v1/client/user/password",
        { current_password: currentPassword, new_password: newPassword },
      );
      return { ok: true, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "changePassword");
    }
  }

  /**
   * Request a change of the account's primary email address.
   *
   * Sends a verification link to the **new** address; the change takes effect
   * only once {@link AuthnClient.verifyEmailChange} is called with that token.
   *
   * Note: the backend currently also returns the raw verification token in the
   * response body. It is deliberately **not** surfaced here — relying on it
   * would defeat mailbox verification and would break once the server stops
   * returning it. Read the token from the email instead.
   *
   * Requires an authenticated session.
   */
  async requestEmailChange(newEmail: string): Promise<VoidResult> {
    this.guardDestroyed();

    try {
      assertValid(validateEmail(newEmail));

      const res = await this.http.post<ServerMessageResponse>(
        "/v1/client/user/email",
        { new_email: newEmail },
      );
      return { ok: true, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "requestEmailChange");
    }
  }

  /**
   * Complete a primary email change using the token from the verification email.
   *
   * Does not require an authenticated session — this endpoint is reachable from
   * the email link in any browser.
   */
  async verifyEmailChange(token: string): Promise<VoidResult> {
    this.guardDestroyed();

    try {
      assertValid(validateToken(token, "token"));

      const res = await this.http.get<ServerMessageResponse>(
        "/v1/client/user/email/verify",
        { token },
      );
      return { ok: true, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "verifyEmailChange");
    }
  }

  /**
   * Read the configured secondary recovery email and its verification state.
   *
   * `recoveryEmail` is an empty string when none is configured.
   *
   * Requires an authenticated session.
   */
  async getRecoveryEmail(): Promise<RecoveryEmailResult> {
    this.guardDestroyed();

    try {
      const res = await this.http.get<{
        recovery_email?: string;
        recovery_email_verified?: boolean;
      }>("/v1/client/user/recovery-email");

      return {
        ok: true,
        recoveryEmail: res.data.recovery_email ?? "",
        recoveryEmailVerified: res.data.recovery_email_verified === true,
      };
    } catch (err) {
      return this.handleError(err, "getRecoveryEmail");
    }
  }

  /**
   * Set a secondary recovery email and dispatch a verification link to it.
   *
   * As with {@link AuthnClient.requestEmailChange}, the verification token the
   * backend echoes in the response body is intentionally not exposed.
   *
   * Requires an authenticated session.
   */
  async setRecoveryEmail(email: string): Promise<VoidResult> {
    this.guardDestroyed();

    try {
      assertValid(validateEmail(email));

      const res = await this.http.post<ServerMessageResponse>(
        "/v1/client/user/recovery-email",
        { recovery_email: email },
      );
      return { ok: true, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "setRecoveryEmail");
    }
  }

  /**
   * Confirm a secondary recovery email using the token from its verification email.
   *
   * Does not require an authenticated session.
   */
  async verifyRecoveryEmail(token: string): Promise<VoidResult> {
    this.guardDestroyed();

    try {
      assertValid(validateToken(token, "token"));

      const res = await this.http.get<ServerMessageResponse>(
        "/v1/client/user/recovery-email/verify",
        { token },
      );
      return { ok: true, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "verifyRecoveryEmail");
    }
  }

  /**
   * Remove the secondary recovery email from the account.
   *
   * Requires an authenticated session.
   */
  async deleteRecoveryEmail(): Promise<VoidResult> {
    this.guardDestroyed();

    try {
      const res = await this.http.del<ServerMessageResponse>(
        "/v1/client/user/recovery-email",
      );
      return { ok: true, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "deleteRecoveryEmail");
    }
  }

  /**
   * List third-party identities linked to the account.
   *
   * Requires an authenticated session.
   */
  async listSocialAccounts(): Promise<SocialAccountsResult> {
    this.guardDestroyed();

    try {
      const res = await this.http.get<{
        social_accounts: ServerSocialAccount[];
      }>("/v1/client/user/social-accounts");

      const accounts = (res.data.social_accounts ?? []).map((a) => ({
        provider: a.provider,
        providerUserId: a.provider_user_id,
        email: a.email,
        connectedAt: a.connected_at,
      }));

      return { ok: true, accounts };
    } catch (err) {
      return this.handleError(err, "listSocialAccounts");
    }
  }

  /**
   * Unlink a social provider from the account.
   *
   * The server returns `403` if this is the only remaining way to sign in
   * (no password set and no other linked provider), and `404` if the provider
   * was never connected.
   *
   * Requires an authenticated session.
   */
  async unlinkSocialAccount(provider: string): Promise<VoidResult> {
    this.guardDestroyed();

    try {
      assertValid(validateToken(provider, "provider"));

      const res = await this.http.del<ServerMessageResponse>(
        `/v1/client/user/social-accounts/${encodeURIComponent(provider)}`,
      );
      return { ok: true, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "unlinkSocialAccount");
    }
  }

  /**
   * Permanently delete the account.
   *
   * Irreversible. The local session is cleared on success and auth state
   * listeners fire with `null`.
   *
   * Takes a password, or an authenticator code for an account that has none —
   * see {@link DeleteAccountParams}. A bare string is accepted as the password,
   * so `deleteAccount(password)` keeps working.
   *
   * Refusals worth branching on:
   * - `401` `invalid_credentials` — what was sent is wrong.
   * - `401` `totp_required` — the account has no password; ask for a code.
   * - `409` `conflict` — the account is the only administrator of organizations
   *   other people still belong to. They are listed under
   *   `error.details.organizations` as {@link BlockingOrganization} entries, so the
   *   refusal can name each one.
   *
   * Requires an authenticated session.
   */
  async deleteAccount(
    params: DeleteAccountParams | string,
  ): Promise<VoidResult> {
    this.guardDestroyed();

    const confirmation: DeleteAccountParams =
      typeof params === "string" ? { password: params } : params;

    try {
      // Exactly one of the two is required, and which one depends on the account
      // rather than the caller — so neither is validated as mandatory here. Sending
      // both empty reaches the engine, which answers with the factor it wants.
      if (confirmation.password !== undefined) {
        assertValid(validateToken(confirmation.password, "password"));
      }
      if (confirmation.totpCode !== undefined) {
        assertValid(validateToken(confirmation.totpCode, "totpCode"));
      }

      const body: Record<string, unknown> = {};
      if (confirmation.password !== undefined) {
        body["password"] = confirmation.password;
      }
      if (confirmation.totpCode !== undefined) {
        body["totp_code"] = confirmation.totpCode;
      }

      const res = await this.http.del<ServerMessageResponse>(
        "/v1/client/user/account",
        body,
      );

      // The account no longer exists — any retained session is meaningless.
      this.setSession(null);

      return { ok: true, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "deleteAccount");
    }
  }

  // -----------------------------------------------------------------------
  // Security Questions (last-resort recovery factor)
  // -----------------------------------------------------------------------

  /**
   * Read the account's enrolled security-question prompts.
   *
   * Answers `NOT_FOUND` when the account has none, which is a valid state rather
   * than an error condition — the caller asked whether this factor is set up.
   *
   * Requires an authenticated session.
   */
  async getSecurityQuestions(): Promise<SecurityQuestionsResult> {
    this.guardDestroyed();

    try {
      const res = await this.http.get<{
        security_questions: SecurityQuestion[];
        total: number;
      }>("/v1/client/account/security-questions");
      return {
        ok: true,
        questions: res.data.security_questions ?? [],
        total: res.data.total ?? 0,
      };
    } catch (err) {
      return this.handleError(err, "getSecurityQuestions");
    }
  }

  /**
   * Replace the account's security-question roster.
   *
   * The whole set is replaced, so a shorter list removes what is not in it.
   * Between three and five questions, each with a distinct prompt and an answer
   * of 3 to 100 characters.
   *
   * Needs a step-up — see {@link SetSecurityQuestionsParams}. The engine answers
   * `401` `step_up_required` naming which credential it wants, and `422`
   * `validation_failed` with a message naming the rule and the entry that broke
   * it.
   *
   * Requires an authenticated session.
   */
  async setSecurityQuestions(
    params: SetSecurityQuestionsParams,
  ): Promise<SecurityQuestionsResult> {
    this.guardDestroyed();

    try {
      const body: Record<string, unknown> = {
        questions: (params.questions ?? []).map((q) => ({
          question: q.question,
          answer: q.answer,
        })),
      };
      if (params.password !== undefined) body["password"] = params.password;
      if (params.totpCode !== undefined) body["totp_code"] = params.totpCode;

      const res = await this.http.put<{
        security_questions: SecurityQuestion[];
        total: number;
        message?: string;
      }>("/v1/client/account/security-questions", body);
      return {
        ok: true,
        questions: res.data.security_questions ?? [],
        total: res.data.total ?? 0,
        message: res.data.message,
      };
    } catch (err) {
      return this.handleError(err, "setSecurityQuestions");
    }
  }

  /**
   * Remove every security question from the account.
   *
   * Idempotent: succeeds whether or not anything was enrolled. Takes the same
   * step-up as a write, since removing a recovery factor is as consequential as
   * adding one.
   *
   * Requires an authenticated session.
   */
  async deleteSecurityQuestions(
    params: DeleteSecurityQuestionsParams = {},
  ): Promise<VoidResult> {
    this.guardDestroyed();

    try {
      const body: Record<string, unknown> = {};
      if (params.password !== undefined) body["password"] = params.password;
      if (params.totpCode !== undefined) body["totp_code"] = params.totpCode;

      const res = await this.http.del<ServerMessageResponse>(
        "/v1/client/account/security-questions",
        body,
      );
      return { ok: true, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "deleteSecurityQuestions");
    }
  }

  // -----------------------------------------------------------------------
  // Destroy
  // -----------------------------------------------------------------------

  /**
   * Permanently tear down the client instance.
   *
   * Cancels the refresh timer, clears all listeners, aborts anything in flight,
   * and refuses further API calls. Use this in SPA cleanup (e.g. React
   * `useEffect` cleanup). Safe to call more than once.
   */
  destroy(): void {
    this.destroyed = true;
    this.clearRefreshTimer();
    this.stateListeners.clear();
    this.currentSession = null;
    // Refusing new calls is not enough on its own: a request already sent has a
    // retry chain that backs off for seconds, and its callbacks would fire into
    // a caller that no longer exists.
    this.lifetime?.abort();
    this.logger.debug("AuthnClient destroyed");
  }

  /**
   * Whether {@link destroy} has been called.
   *
   * A destroyed client cannot be revived, so this is what a caller holding one
   * for longer than a single request — a framework provider across a remount,
   * say — checks before use, rather than discovering it from a thrown error.
   */
  isDestroyed(): boolean {
    return this.destroyed;
  }

  // =======================================================================
  // PRIVATE
  // =======================================================================

  private guardDestroyed(): void {
    if (this.destroyed) {
      throw new AuthnError({
        message:
          "This AuthnClient instance has been destroyed. Create a new instance with `new AuthnClient(config)`.",
        code: AuthnErrorCode.INVALID_CONFIG,
      });
    }
  }

  /**
   * Resolves the tenant a request names, or `undefined` when none is configured.
   *
   * There is deliberately no `"tnt_default"` fallback. The engine derives the
   * tenant from the publishable key's application, so omitting the field lets
   * the server decide; sending a guessed tenant instead meant a misconfigured
   * client silently read and wrote another tenant's data.
   */
  private resolveTenantId(override?: string): string | undefined {
    return override ?? this.config.tenantId;
  }

  private resolveEnvironment(override?: "test" | "live"): string {
    return override ?? this.config.environment ?? "test";
  }

  /**
   * resolveAuthResponse turns one credential-presenting response into an
   * AuthResult, and is the only place that decides whether a 200 means
   * "authenticated".
   *
   * A 2FA-gated login is answered 200 with mfa_token and no access_token, so
   * mapping every 200 to a session stores one holding no credential — the client
   * then reports an authenticated user, schedules a refresh against a token that
   * never existed, and drops the challenge the caller needed in order to
   * continue. Every caller of this shape shares that hazard, so they share the
   * decision.
   */
  private resolveAuthResponse(
    data: ServerAuthResponse,
    operation: string,
  ): AuthResult {
    if (data.mfa_required === true) {
      const methods = normaliseTwoFactorMethods(data.methods);
      this.logger.info(`${operation} requires a second factor`, {
        userId: data.user.id,
        methods,
      });

      return {
        ok: true,
        mfaRequired: true,
        mfaToken: data.mfa_token ?? "",
        methods,
        user: this.mapUser(data.user),
      };
    }

    const session = this.mapSession(data);
    const policyWarning = this.mapPolicyWarning(data.policy_warning);

    this.setSession(session);
    this.logger.info(`${operation} successful`, { userId: session.user.id });

    return { ok: true, session, policyWarning };
  }

  private mapUser(data: ServerAuthResponse["user"]): AuthnUser {
    return {
      id: data.id,
      email: data.email,
      emailVerified: data.email_verified,
      name: data.name,
      username: data.username,
      status: (data.status as AuthnUser["status"]) ?? "active",
      createdAt: data.created_at,
    };
  }

  private mapSession(data: ServerAuthResponse): AuthnSession {
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt:
        data.expires_at ?? Math.floor(Date.now() / 1000) + 15 * 60,
      user: this.mapUser(data.user),
    };
  }

  private mapDeviceSession(data: ServerSessionResponse): AuthnDeviceSession {
    return {
      id: data.id,
      device: {
        browser: data.device?.browser ?? "Unknown",
        os: data.device?.os ?? "Unknown",
        device: data.device?.device ?? "Unknown",
        label: data.device?.label ?? "Unknown Device",
      },
      ipAddress: data.ip_address ?? "",
      location: data.location ?? "",
      lastActiveAt: data.last_active_at,
      createdAt: data.created_at,
      isCurrent: data.is_current === true,
    };
  }

  private mapProfile(data: ServerProfileResponse): AuthnProfile {
    return {
      id: data.id,
      tenantId: data.tenant_id,
      email: data.email,
      emailVerified: data.email_verified === true,
      status: (data.status as "active" | "suspended" | "banned") ?? "active",
      name: data.name,
      username: data.username,
      phone: data.phone_number,
      phoneNumber: data.phone_number,
      phoneVerified: data.phone_verified === true,
      recoveryEmail: data.recovery_email,
      recoveryEmailVerified: data.recovery_email_verified === true,
      avatarUrl: data.avatar_url,
      locale: data.locale,
      metadata: data.metadata,
      createdAt: data.created_at,
      updatedAt: data.updated_at,
    };
  }

  /**
   * Turns the server's passkey row into the documented shape.
   *
   * The mapping is not cosmetic. The engine sends `created_at` and `last_used_at`,
   * and handing the row through unmapped left every consumer reading
   * `credential.createdAt` — a property that type-checked and was always
   * `undefined`, so a passkey list rendered "Added Unknown" with nothing to
   * explain why. The AAGUID and the transports live inside the metadata bag and
   * are lifted out here, so a caller naming an authenticator does not have to know
   * that.
   */
  private mapPasskey(data: ServerPasskey): WebAuthnPasskey {
    const metadata = data.metadata ?? {};

    const aaguid = typeof metadata["aaguid"] === "string" ? metadata["aaguid"] : undefined;
    const rawTransports = metadata["transports"];
    const transports = Array.isArray(rawTransports)
      ? rawTransports.filter((t): t is string => typeof t === "string")
      : undefined;

    const passkey: WebAuthnPasskey = {
      id: data.id,
      name: data.name,
      createdAt: data.created_at,
    };

    if (data.last_used_at) passkey.lastUsedAt = data.last_used_at;
    // An authenticator that declines to identify itself reports all zeroes, which
    // is not a model identifier and must not be presented as one.
    if (aaguid && !/^0+$/.test(aaguid)) passkey.aaguid = aaguid;
    if (transports && transports.length > 0) passkey.transports = transports;

    return passkey;
  }

  private mapPolicyWarning(
    pw?: ServerAuthResponse["policy_warning"],
  ): PolicyWarning | undefined {
    if (!pw) return undefined;

    const warning: PolicyWarning = {};
    if (pw.requires_password_upgrade) {
      warning.requiresPasswordUpgrade = true;
    }
    if (pw.requires_email_verification) {
      warning.requiresEmailVerification = true;
    }
    if (pw.missing_criteria && pw.missing_criteria.length > 0) {
      warning.missingCriteria = pw.missing_criteria;
    }

    return Object.keys(warning).length > 0 ? warning : undefined;
  }

  private setSession(session: AuthnSession | null): void {
    this.currentSession = session;
    this.clearRefreshTimer();

    if (session && this.config.autoRefresh) {
      this.scheduleRefresh(session);
    }

    this.notifyListeners();
  }

  private scheduleRefresh(session: AuthnSession): void {
    // Refresh 60 seconds before expiry
    const nowSec = Math.floor(Date.now() / 1000);
    const refreshInSec = session.expiresAt - nowSec - 60;

    if (refreshInSec <= 0) {
      // Token is about to expire or already expired — refresh immediately
      this.logger.warn("Token expires soon — refreshing immediately");
      void this.refreshSession();
      return;
    }

    this.logger.debug(`Scheduling token refresh in ${refreshInSec}s`);
    this.refreshTimer = setTimeout(() => {
      void this.refreshSession();
    }, refreshInSec * 1000);
  }

  private clearRefreshTimer(): void {
    if (this.refreshTimer !== null) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  private async executeRefresh(): Promise<SessionResult> {
    try {
      const res = await this.http.post<ServerAuthResponse>("/v1/oauth/token", {
        grant_type: "refresh_token",
      });

      const session = this.mapSession(res.data);
      this.setSession(session);
      this.logger.debug("Token refreshed silently");

      return { ok: true, session };
    } catch (err) {
      this.logger.warn("Silent token refresh failed — session cleared");
      this.setSession(null);

      if (err instanceof AuthnError) {
        const refreshError = new AuthnError({
          message:
            "Your session has expired. Please sign in again.",
          code: AuthnErrorCode.REFRESH_FAILED,
          statusCode: err.statusCode,
          requestId: err.requestId,
          cause: err,
        });

        this.config.onError?.(refreshError);
        return { ok: false, error: refreshError };
      }

      const unknown = new AuthnError({
        message: "Session refresh failed unexpectedly.",
        code: AuthnErrorCode.REFRESH_FAILED,
        cause: err,
      });
      this.config.onError?.(unknown);
      return { ok: false, error: unknown };
    }
  }

  // -----------------------------------------------------------------------
  // Domain 3 — 2FA, TOTP & WebAuthn / Passkeys
  // -----------------------------------------------------------------------

  /**
   * Enroll a new TOTP 2FA secret for the authenticated user.
   * Target Route: POST /v1/client/auth/2fa/totp/enroll
   */
  async enrollTOTP(): Promise<EnrollTOTPResult> {
    this.guardDestroyed();
    try {
      const res = await this.http.post<ServerEnrollTOTPResponse>("/v1/client/auth/2fa/totp/enroll");
      return {
        ok: true,
        secret: res.data.secret,
        uri: res.data.uri,
      };
    } catch (err) {
      return this.handleError(err, "enrollTOTP");
    }
  }

  /**
   * Confirm TOTP enrollment with a 6-digit verification code.
   * Target Route: POST /v1/client/auth/2fa/totp/confirm
   */
  async confirmTOTP(params: ConfirmTOTPParams): Promise<Confirm2FAResult> {
    this.guardDestroyed();
    try {
      assertValid(validateTOTPCode(params?.code));
      const res = await this.http.post<ServerConfirmTOTPResponse>("/v1/client/auth/2fa/totp/confirm", {
        code: params.code,
      });
      return {
        ok: true,
        message: res.data.message,
        recoveryCodes: res.data.recovery_codes,
        recoveryCodesCreated: res.data.recovery_codes_created,
      };
    } catch (err) {
      return this.handleError(err, "confirmTOTP");
    }
  }

  /**
   * Disable TOTP 2FA requiring password step-up confirmation.
   * Target Route: POST /v1/client/auth/2fa/totp/disable
   */
  async disableTOTP(params: DisableTOTPParams): Promise<VoidResult> {
    this.guardDestroyed();
    try {
      assertValid(validatePassword(params?.password));
      const res = await this.http.post<ServerMessageResponse>("/v1/client/auth/2fa/totp/disable", {
        password: params.password,
      });
      return {
        ok: true,
        message: res.data.message,
      };
    } catch (err) {
      return this.handleError(err, "disableTOTP");
    }
  }

  /**
   * Verify TOTP code during login challenge or inside an active session.
   * Target Route: POST /v1/client/auth/2fa/totp/verify
   */
  async verifyTOTP(params: VerifyTOTPParams): Promise<VerifyTOTPResult> {
    this.guardDestroyed();
    try {
      // A backup code is eight letters and digits, not six digits, so the shape it is checked
      // against follows the named method. Without this the recovery codes the engine issues at
      // enrollment are refused here and never reach the server.
      assertValid(
        params?.method === "backup_code"
          ? validateRecoveryCode(params?.code)
          : validateTOTPCode(params?.code),
      );
      if (params.mfaToken) {
        const res = await this.http.post<ServerAuthResponse>("/v1/client/auth/2fa/totp/verify", {
          code: params.code,
          mfa_token: params.mfaToken,
          method: params.method,
        });
        const session = this.mapSession(res.data);
        this.setSession(session);
        return { ok: true, session };
      } else {
        const res = await this.http.post<{ valid: boolean }>("/v1/client/auth/2fa/totp/verify", {
          code: params.code,
          method: params.method,
        });
        return { ok: true, valid: res.data.valid };
      }
    } catch (err) {
      return this.handleError(err, "verifyTOTP");
    }
  }

  /**
   * Enroll a phone number for SMS 2FA.
   * Target Route: POST /v1/client/auth/2fa/sms/enroll
   */
  async enrollSMS(params: EnrollSMSParams): Promise<EnrollSMSResult> {
    this.guardDestroyed();
    try {
      assertValid(validatePhoneNumber(params?.phoneNumber));
      const res = await this.http.post<ServerEnrollSMSResponse>("/v1/client/auth/2fa/sms/enroll", {
        phone_number: params.phoneNumber,
      });
      return {
        ok: true,
        message: res.data.message,
        expiresInSeconds: res.data.expires_in_seconds,
      };
    } catch (err) {
      return this.handleError(err, "enrollSMS");
    }
  }

  /**
   * Send an SMS code for a sign-in that is waiting on a second factor.
   *
   * Needed because a code only exists once it has been sent, and the login challenge holds an
   * `mfaToken` rather than a session — so `enrollSMS` cannot serve it. Call this when the sign-in
   * came back with `sms` among its `methods`, then pass the delivered code to
   * {@link AuthnClient.verifyTOTP} with `method: "sms"`.
   *
   * There is no email fallback: a failed send answers 503 rather than mailing the code, since the
   * caller has proven only the password and a second factor sent to the account address is not a
   * second factor. Offer another method from the challenge instead.
   *
   * Target Route: POST /v1/client/auth/2fa/sms/challenge
   */
  async sendSMSChallenge(params: SendSMSChallengeParams): Promise<SendSMSChallengeResult> {
    this.guardDestroyed();
    try {
      assertValid(validateToken(params?.mfaToken, "mfaToken"));
      const res = await this.http.post<ServerSMSChallengeResponse>(
        "/v1/client/auth/2fa/sms/challenge",
        { mfa_token: params.mfaToken },
      );
      return {
        ok: true,
        phoneNumber: res.data.phone_number,
        expiresInSeconds: res.data.expires_in_seconds,
        message: res.data.message,
      };
    } catch (err) {
      return this.handleError(err, "sendSMSChallenge");
    }
  }

  /**
   * Confirm SMS 2FA enrollment with the received OTP code.
   * Target Route: POST /v1/client/auth/2fa/sms/confirm
   */  async confirmSMS(params: ConfirmSMSParams): Promise<Confirm2FAResult> {
    this.guardDestroyed();
    try {
      assertValid(validateTOTPCode(params?.code));
      const res = await this.http.post<ServerConfirmTOTPResponse>("/v1/client/auth/2fa/sms/confirm", {
        code: params.code,
      });
      return {
        ok: true,
        message: res.data.message,
        recoveryCodes: res.data.recovery_codes,
        recoveryCodesCreated: res.data.recovery_codes_created,
      };
    } catch (err) {
      return this.handleError(err, "confirmSMS");
    }
  }

  /**
   * Disable SMS 2FA with password step-up confirmation.
   * Target Route: DELETE /v1/client/auth/2fa/sms/disable
   */
  async disableSMS(params: DisableSMSParams): Promise<VoidResult> {
    this.guardDestroyed();
    try {
      assertValid(validatePassword(params?.password));
      const res = await this.http.del<ServerMessageResponse>("/v1/client/auth/2fa/sms/disable", {
        password: params.password,
      });
      return {
        ok: true,
        message: res.data.message,
      };
    } catch (err) {
      return this.handleError(err, "disableSMS");
    }
  }

  /**
   * Regenerate backup recovery codes with password step-up confirmation.
   * Target Route: POST /v1/client/auth/2fa/recovery-codes/regenerate
   */
  async regenerateRecoveryCodes(
    params: RegenerateRecoveryCodesParams,
  ): Promise<RegenerateRecoveryCodesResult> {
    this.guardDestroyed();
    try {
      assertValid(validatePassword(params?.password));
      const res = await this.http.post<ServerRegenerateRecoveryCodesResponse>(
        "/v1/client/auth/2fa/recovery-codes/regenerate",
        { password: params.password },
      );
      return {
        ok: true,
        message: res.data.message,
        recoveryCodes: res.data.recovery_codes,
      };
    } catch (err) {
      return this.handleError(err, "regenerateRecoveryCodes");
    }
  }

  /**
   * Get current backup recovery codes status.
   * Target Route: GET /v1/client/auth/2fa/recovery-codes/status
   */
  async getRecoveryCodesStatus(): Promise<RecoveryCodesStatusResult> {
    this.guardDestroyed();
    try {
      const res = await this.http.get<ServerRecoveryCodesStatusResponse>(
        "/v1/client/auth/2fa/recovery-codes/status",
      );
      return {
        ok: true,
        status: {
          remainingCount: res.data.remaining_count,
          totalCount: res.data.total_count,
          hasRecoveryCodes: res.data.has_recovery_codes,
        },
      };
    } catch (err) {
      return this.handleError(err, "getRecoveryCodesStatus");
    }
  }

  /**
   * Get which second factors the account has enrolled.
   * Target Route: GET /v1/client/auth/2fa/methods
   *
   * `methods` is the list a sign-in challenge would offer, so a settings screen can state what the
   * next sign-in will ask for rather than deducing it. Passkeys and recovery codes appear there but
   * carry no detail object — {@link listWebAuthnCredentials} and {@link getRecoveryCodesStatus}
   * hold that.
   */
  async getTwoFactorMethods(): Promise<TwoFactorMethodsResult> {
    this.guardDestroyed();
    try {
      const res = await this.http.get<ServerTwoFactorMethodsResponse>("/v1/client/auth/2fa/methods");
      return {
        ok: true,
        methods: {
          methods: res.data.methods ?? [],
          totp: AuthnClient.mapTwoFactorMethodState(res.data.totp),
          sms: {
            ...AuthnClient.mapTwoFactorMethodState(res.data.sms),
            ...(res.data.sms?.phone_number ? { phoneNumber: res.data.sms.phone_number } : {}),
          },
        },
      };
    } catch (err) {
      return this.handleError(err, "getTwoFactorMethods");
    }
  }

  /**
   * Turns one factor's row into the documented shape.
   *
   * A missing object is read as not enrolled rather than thrown on: the caller's next move is to
   * offer enrollment either way, and a settings page that fails wholesale because one factor was
   * omitted tells the reader nothing about the factors that were present.
   */
  private static mapTwoFactorMethodState(
    data: ServerTwoFactorMethodState | undefined,
  ): TwoFactorMethodState {
    const state: TwoFactorMethodState = { enabled: data?.enabled === true };
    if (data?.created_at) state.createdAt = data.created_at;
    if (data?.last_used_at) state.lastUsedAt = data.last_used_at;
    return state;
  }

  /**
   * Begin WebAuthn passkey registration ceremony.
   * Target Route: POST /v1/client/auth/2fa/webauthn/register/begin
   */
  async beginPasskeyRegistration(): Promise<BeginPasskeyRegistrationResult> {
    this.guardDestroyed();
    try {
      const res = await this.http.post<ServerBeginPasskeyRegistrationResponse>(
        "/v1/client/auth/2fa/webauthn/register/begin",
      );
      return {
        ok: true,
        options: res.data.options,
        sessionId: res.data.session_id,
      };
    } catch (err) {
      return this.handleError(err, "beginPasskeyRegistration");
    }
  }

  /**
   * Complete WebAuthn passkey registration ceremony.
   * Target Route: POST /v1/client/auth/2fa/webauthn/register/finish
   */
  async finishPasskeyRegistration(
    params: FinishPasskeyRegistrationParams,
  ): Promise<Confirm2FAResult> {
    this.guardDestroyed();
    try {
      assertValid(validateWebAuthnCredential(params?.credential));
      const queryParams: Record<string, string> = {
        session_id: params.sessionId,
      };
      if (params.name) {
        queryParams["name"] = params.name;
      }
      const res = await this.http.postRaw<ServerConfirmTOTPResponse>(
        "/v1/client/auth/2fa/webauthn/register/finish",
        params.credential,
        queryParams,
      );
      return {
        ok: true,
        message: res.data.message,
        recoveryCodes: res.data.recovery_codes,
        recoveryCodesCreated: res.data.recovery_codes_created,
      };
    } catch (err) {
      return this.handleError(err, "finishPasskeyRegistration");
    }
  }

  /**
   * Begin WebAuthn passkey login challenge ceremony.
   * Target Route: POST /v1/client/auth/2fa/webauthn/login/begin
   */
  async beginPasskeyLogin(
    params: BeginPasskeyLoginParams,
  ): Promise<BeginPasskeyLoginResult> {
    this.guardDestroyed();
    try {
      const res = await this.http.post<ServerBeginPasskeyLoginResponse>(
        "/v1/client/auth/2fa/webauthn/login/begin",
        { mfa_token: params.mfaToken },
      );
      return {
        ok: true,
        options: res.data.options,
        sessionId: res.data.session_id,
        userId: res.data.user_id,
      };
    } catch (err) {
      return this.handleError(err, "beginPasskeyLogin");
    }
  }

  /**
   * Complete WebAuthn passkey login challenge ceremony.
   * Target Route: POST /v1/client/auth/2fa/webauthn/login/finish
   */
  async finishPasskeyLogin(
    params: FinishPasskeyLoginParams,
  ): Promise<FinishPasskeyLoginResult> {
    this.guardDestroyed();
    try {
      assertValid(validateWebAuthnCredential(params?.credential));
      const res = await this.http.postRaw<ServerAuthResponse>(
        "/v1/client/auth/2fa/webauthn/login/finish",
        params.credential,
        {
          mfa_token: params.mfaToken ?? "",
          session_id: params.sessionId,
        },
      );
      const session = this.mapSession(res.data);
      this.setSession(session);
      return { ok: true, session };
    } catch (err) {
      return this.handleError(err, "finishPasskeyLogin");
    }
  }

  /**
   * List all registered WebAuthn passkeys for the current user.
   * Target Route: GET /v1/client/auth/2fa/webauthn/credentials
   */
  async listWebAuthnCredentials(): Promise<ListWebAuthnCredentialsResult> {
    this.guardDestroyed();
    try {
      const res = await this.http.get<ServerListPasskeysResponse>(
        "/v1/client/auth/2fa/webauthn/credentials",
      );
      return {
        ok: true,
        credentials: (res.data.credentials ?? []).map((c) => this.mapPasskey(c)),
      };
    } catch (err) {
      return this.handleError(err, "listWebAuthnCredentials");
    }
  }

  /**
   * Revoke (delete) a WebAuthn passkey.
   * Target Route: DELETE /v1/client/auth/2fa/webauthn/credentials/:id
   */
  async revokeWebAuthnCredential(
    params: RevokeWebAuthnCredentialParams,
  ): Promise<VoidResult> {
    this.guardDestroyed();
    try {
      const path = `/v1/client/auth/2fa/webauthn/credentials/${encodeURIComponent(params.id)}`;
      const body = params.password ? { password: params.password } : undefined;
      const res = await this.http.del<ServerMessageResponse>(path, body);
      return {
        ok: true,
        message: res.data.message,
      };
    } catch (err) {
      return this.handleError(err, "revokeWebAuthnCredential");
    }
  }

  /**
   * Browser convenience helper to register a passkey in a single call.
   * Executes beginPasskeyRegistration -> navigator.credentials.create() -> finishPasskeyRegistration.
   */
  async registerPasskey(name?: string): Promise<Confirm2FAResult> {
    const beginRes = await this.beginPasskeyRegistration();
    if (!beginRes.ok) return beginRes;

    try {
      const preparedOptions = prepareCreationOptions(beginRes.options);
      const credential = (await navigator.credentials.create({
        publicKey: preparedOptions,
      })) as PublicKeyCredential;
      if (!credential) {
        throw new AuthnError({
          message: "Passkey creation returned empty credential",
          code: AuthnErrorCode.UNKNOWN,
        });
      }
      const formattedCredential = formatCreationCredential(credential);
      return await this.finishPasskeyRegistration({
        sessionId: beginRes.sessionId,
        name,
        credential: formattedCredential,
      });
    } catch (err) {
      return this.handleError(this.asCeremonyError(err), "registerPasskey");
    }
  }

  /**
   * Browser convenience helper to complete passkey login in a single call.
   * Executes beginPasskeyLogin -> navigator.credentials.get() -> finishPasskeyLogin.
   */
  async loginWithPasskey(mfaToken: string): Promise<FinishPasskeyLoginResult> {
    const beginRes = await this.beginPasskeyLogin({ mfaToken });
    if (!beginRes.ok) return beginRes;

    try {
      const preparedOptions = prepareRequestOptions(beginRes.options);
      const credential = (await navigator.credentials.get({
        publicKey: preparedOptions,
      })) as PublicKeyCredential;
      if (!credential) {
        throw new AuthnError({
          message: "Passkey assertion returned empty credential",
          code: AuthnErrorCode.UNKNOWN,
        });
      }
      const formattedCredential = formatRequestCredential(credential);
      return await this.finishPasskeyLogin({
        mfaToken,
        sessionId: beginRes.sessionId,
        credential: formattedCredential,
      });
    } catch (err) {
      return this.handleError(this.asCeremonyError(err), "loginWithPasskey");
    }
  }

  /**
   * Names the ceremony outcomes the browser reports as generic DOMExceptions.
   *
   * Passed through unchanged, a dismissed system prompt reaches the caller as
   * `UNKNOWN` — indistinguishable from a real fault, so a UI cannot tell "you
   * changed your mind" from "something broke". Anything unrecognised is returned
   * as it came, so this narrows the vocabulary without swallowing detail.
   */
  private asCeremonyError(err: unknown): unknown {
    if (err instanceof AuthnError) return err;
    const mapped = mapCeremonyError(err);
    if (!mapped) return err;
    return new AuthnError({
      message: mapped.message,
      code:
        mapped.outcome === "cancelled"
          ? AuthnErrorCode.CANCELLED
          : AuthnErrorCode.INVALID_PARAMS,
      details: { passkey_outcome: mapped.outcome },
      cause: err,
    });
  }

  private notifyListeners(): void {
    const user = this.currentSession?.user ?? null;
    const session = this.currentSession;
    for (const cb of this.stateListeners) {
      try {
        cb(user, session);
      } catch (listenerErr) {
        this.logger.error("Auth state listener threw an error", {
          error:
            listenerErr instanceof Error
              ? listenerErr.message
              : String(listenerErr),
        });
      }
    }
  }

  // -------------------------------------------------------------------------
  // B2B Organizations
  // -------------------------------------------------------------------------

  /**
   * Creates a new organization. The calling user becomes its first org_admin.
   * POST /v1/client/organizations
   */
  async createOrganization(params: CreateOrgParams): Promise<CreateOrgResult> {
    try {
      assertValid(validateToken(params.name?.trim(), "name"));
      const body: Record<string, unknown> = { name: params.name };
      if (params.slug !== undefined) body["slug"] = params.slug;
      if (params.logoUrl !== undefined) body["logo_url"] = params.logoUrl;
      if (params.metadata !== undefined) body["metadata"] = params.metadata;
      const res = await this.http.post<ServerOrgResponse>(
        "/v1/client/organizations",
        body,
      );
      return { ok: true, org: mapOrg(res.data) };
    } catch (err) {
      return this.handleError(err, "createOrganization");
    }
  }

  /**
   * Returns the organizations the calling user belongs to.
   * GET /v1/client/organizations
   */
  async listOrganizations(): Promise<ListOrgsResult> {
    try {
      const res = await this.http.get<{
        organizations: ServerOrgResponse[];
        total: number;
      }>("/v1/client/organizations");
      return {
        ok: true,
        organizations: res.data.organizations.map(mapOrg),
        total: res.data.total,
      };
    } catch (err) {
      return this.handleError(err, "listOrganizations");
    }
  }

  /**
   * Returns a single organization by ID. The caller must be a member.
   * GET /v1/client/organizations/:orgId
   */
  async getOrganization(orgId: string): Promise<GetOrgResult> {
    try {
      assertValid(validateToken(orgId, "orgId"));
      const res = await this.http.get<ServerOrgResponse>(
        `/v1/client/organizations/${orgId}`,
      );
      return { ok: true, org: mapOrg(res.data) };
    } catch (err) {
      return this.handleError(err, "getOrganization");
    }
  }

  /**
   * Applies a partial update to an organization. Requires org_admin role.
   * PATCH /v1/client/organizations/:orgId
   */
  async updateOrganization(
    orgId: string,
    params: UpdateOrgParams,
  ): Promise<UpdateOrgResult> {
    try {
      assertValid(validateToken(orgId, "orgId"));
      const body: Record<string, unknown> = {};
      if (params.name !== undefined) body["name"] = params.name;
      if (params.slug !== undefined) body["slug"] = params.slug;
      if (params.logoUrl !== undefined) body["logo_url"] = params.logoUrl;
      if (params.metadata !== undefined) body["metadata"] = params.metadata;
      const res = await this.http.patch<ServerOrgResponse>(
        `/v1/client/organizations/${orgId}`,
        body,
      );
      return { ok: true, org: mapOrg(res.data) };
    } catch (err) {
      return this.handleError(err, "updateOrganization");
    }
  }

  /**
   * Deletes an organization and all dependents. Requires org_admin role.
   * DELETE /v1/client/organizations/:orgId
   */
  async deleteOrganization(orgId: string): Promise<DeleteOrgResult> {
    try {
      assertValid(validateToken(orgId, "orgId"));
      const res = await this.http.del<{ message: string; org_id: string }>(
        `/v1/client/organizations/${orgId}`,
      );
      return { ok: true, orgId: res.data.org_id, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "deleteOrganization");
    }
  }

  /**
   * Sends an invitation email to join an organization. Requires org_admin role.
   * POST /v1/client/organizations/:orgId/invitations
   */
  async inviteOrgMember(
    orgId: string,
    params: InviteOrgMemberParams,
  ): Promise<InviteOrgMemberResult> {
    try {
      assertValid(validateToken(orgId, "orgId"));
      assertValid(validateEmail(params.email));
      assertValid(validateToken(params.roleId, "roleId"));
      const body: Record<string, unknown> = {
        email: params.email,
        role_id: params.roleId,
      };
      if (params.expiresHrs !== undefined) body["expires_hrs"] = params.expiresHrs;
      const res = await this.http.post<ServerOrgInvitationResponse>(
        `/v1/client/organizations/${orgId}/invitations`,
        body,
      );
      return { ok: true, invitation: mapInvitation(res.data) };
    } catch (err) {
      return this.handleError(err, "inviteOrgMember");
    }
  }

  /**
   * Redeems an invitation token, adding the calling user to the organization.
   * POST /v1/client/invitations/accept
   */
  async acceptOrgInvitation(
    params: AcceptOrgInvitationParams,
  ): Promise<AcceptOrgInvitationResult> {
    try {
      assertValid(validateToken(params.invitationToken, "invitationToken"));
      const res = await this.http.post<{
        message: string;
        member: ServerOrgMemberResponse;
      }>("/v1/client/invitations/accept", {
        invitation_token: params.invitationToken,
      });
      return { ok: true, member: mapMember(res.data.member), message: res.data.message };
    } catch (err) {
      return this.handleError(err, "acceptOrgInvitation");
    }
  }

  /**
   * Lists members of an organization. The caller must be a member.
   * GET /v1/client/organizations/:orgId/members
   */
  async listOrgMembers(orgId: string): Promise<ListOrgMembersResult> {
    try {
      assertValid(validateToken(orgId, "orgId"));
      const res = await this.http.get<{
        members: ServerOrgMemberResponse[];
        total: number;
      }>(`/v1/client/organizations/${orgId}/members`);
      return {
        ok: true,
        members: res.data.members.map(mapMember),
        total: res.data.total,
      };
    } catch (err) {
      return this.handleError(err, "listOrgMembers");
    }
  }

  /**
   * Updates a member's role within an organization. Requires org_admin role.
   * PATCH /v1/client/organizations/:orgId/members/:userId
   *
   * Answers `409` when the change would remove the organization's last
   * administrator — demoting yourself while alone in that role leaves a workspace
   * nobody can administer, so promote someone else first.
   */
  async updateOrgMemberRole(
    orgId: string,
    userId: string,
    params: UpdateOrgMemberRoleParams,
  ): Promise<UpdateOrgMemberRoleResult> {
    try {
      assertValid(validateToken(orgId, "orgId"));
      assertValid(validateToken(userId, "userId"));
      assertValid(validateToken(params.roleId, "roleId"));
      const res = await this.http.patch<ServerOrgMemberResponse>(
        `/v1/client/organizations/${orgId}/members/${userId}`,
        { role_id: params.roleId },
      );
      return { ok: true, member: mapMember(res.data) };
    } catch (err) {
      return this.handleError(err, "updateOrgMemberRole");
    }
  }

  /**
   * Removes a member from an organization, or leaves it.
   *
   * The two are the same call. Passing the caller's own user ID is how a plain
   * member leaves: no administrative rights are needed to remove yourself, and the
   * reply sets `left` so a UI knows the workspace it was showing is gone.
   *
   * Answers `409` when the removal would leave the organization without an
   * administrator, and `403` when removing someone else without org_admin rights.
   *
   * DELETE /v1/client/organizations/:orgId/members/:userId
   */
  async removeOrgMember(
    orgId: string,
    userId: string,
  ): Promise<RemoveOrgMemberResult> {
    try {
      assertValid(validateToken(orgId, "orgId"));
      assertValid(validateToken(userId, "userId"));
      const res = await this.http.del<{ message: string; left?: boolean }>(
        `/v1/client/organizations/${orgId}/members/${userId}`,
      );
      return {
        ok: true,
        message: res.data.message,
        left: res.data.left ?? false,
      };
    } catch (err) {
      return this.handleError(err, "removeOrgMember");
    }
  }

  /**
   * Lists the organization invitations addressed to the signed-in account.
   *
   * Matched on the account's *verified* primary address, so an unverified account
   * reads an empty list even when invitations exist for the address it claims.
   *
   * GET /v1/client/invitations
   */
  async listInvitations(): Promise<ListInvitationsResult> {
    try {
      const res = await this.http.get<{
        invitations: ServerOrgInvitationResponse[];
        total: number;
      }>("/v1/client/invitations");
      return {
        ok: true,
        invitations: (res.data.invitations ?? []).map(mapInvitation),
        total: res.data.total ?? 0,
      };
    } catch (err) {
      return this.handleError(err, "listInvitations");
    }
  }

  // -------------------------------------------------------------------------
  // Guardian Roster Management
  // -------------------------------------------------------------------------

  /**
   * Invites 1 to 5 trusted social recovery guardians for the calling user.
   * POST /v1/client/account/guardians/invite
   */
  async inviteGuardians(
    params: InviteGuardiansParams,
  ): Promise<InviteGuardiansResult> {
    try {
      if (!Array.isArray(params.guardians) || params.guardians.length === 0) {
        assertValid(
          validateToken("", "guardians"),
        );
      }
      for (const g of params.guardians) {
        assertValid(validateEmail(g.email));
        assertValid(validateToken(g.name, "name"));
      }
      const res = await this.http.post<{
        enrolled_count: number;
        threshold_k: number;
        guardians: ServerGuardianResponse[];
        invite_urls?: string[];
      }>("/v1/client/account/guardians/invite", {
        guardians: params.guardians,
      });
      return {
        ok: true,
        enrolledCount: res.data.enrolled_count,
        thresholdK: res.data.threshold_k,
        guardians: res.data.guardians.map(mapGuardian),
        inviteUrls: res.data.invite_urls,
      };
    } catch (err) {
      return this.handleError(err, "inviteGuardians");
    }
  }

  /**
   * Redeems a guardian invitation token.
   * POST /v1/client/account/guardians/accept
   */
  async acceptGuardianInvite(
    params: AcceptGuardianInviteParams,
  ): Promise<AcceptGuardianInviteResult> {
    try {
      assertValid(validateToken(params.contactId, "contactId"));
      assertValid(validateToken(params.token, "token"));
      const res = await this.http.post<{ message: string }>(
        "/v1/client/account/guardians/accept",
        {
          contact_id: params.contactId,
          token: params.token,
        },
      );
      return { ok: true, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "acceptGuardianInvite");
    }
  }

  /**
   * Returns the guardian roster for the calling user.
   * GET /v1/client/account/guardians
   */
  async listGuardians(): Promise<ListGuardiansResult> {
    try {
      const res = await this.http.get<{ guardians: ServerGuardianResponse[] }>(
        "/v1/client/account/guardians",
      );
      return { ok: true, guardians: res.data.guardians.map(mapGuardian) };
    } catch (err) {
      return this.handleError(err, "listGuardians");
    }
  }

  /**
   * Revokes/removes a guardian by contact ID and re-keys Shamir shares.
   * DELETE /v1/client/account/guardians/:id
   */
  async revokeGuardian(contactId: string): Promise<RevokeGuardianResult> {
    try {
      assertValid(validateToken(contactId, "contactId"));
      const res = await this.http.del<{ message: string }>(
        `/v1/client/account/guardians/${contactId}`,
      );
      return { ok: true, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "revokeGuardian");
    }
  }

  // -------------------------------------------------------------------------
  // Account Recovery
  // -------------------------------------------------------------------------

  /**
   * Initiates account recovery for a locked-out user address.
   * POST /v1/client/auth/recovery/initiate
   */
  async initiateRecovery(
    params: InitiateRecoveryParams,
  ): Promise<InitiateRecoveryResult> {
    try {
      assertValid(validateEmail(params.email));
      const body: Record<string, unknown> = {
        email: params.email,
        tenant_id: this.resolveTenantId(params.tenantId),
        environment: this.resolveEnvironment(
          params.environment as "test" | "live" | undefined,
        ),
      };
      const res = await this.http.post<{
        recovery_request_id: string;
        status: string;
        is_trusted_device_origin: boolean;
        available_methods: string[];
        security_questions?: SecurityQuestion[];
      }>("/v1/client/auth/recovery/initiate", body);
      return {
        ok: true,
        recoveryRequestId: res.data.recovery_request_id,
        status: res.data.status,
        isTrustedDeviceOrigin: res.data.is_trusted_device_origin,
        availableMethods: res.data.available_methods,
        securityQuestions: res.data.security_questions,
      };
    } catch (err) {
      return this.handleError(err, "initiateRecovery");
    }
  }

  /**
   * Submits a guardian Shamir share proof for a recovery request.
   * POST /v1/client/auth/recovery/proof/guardian
   */
  async submitGuardianProof(
    params: SubmitGuardianProofParams,
  ): Promise<SubmitGuardianProofResult> {
    try {
      assertValid(
        validateToken(params.recoveryRequestId, "recoveryRequestId"),
      );
      assertValid(validateToken(params.sharePayload, "sharePayload"));
      const res = await this.http.post<{
        threshold_reached: boolean;
        status: string;
      }>("/v1/client/auth/recovery/proof/guardian", {
        recovery_request_id: params.recoveryRequestId,
        share_payload: params.sharePayload,
      });
      return {
        ok: true,
        thresholdReached: res.data.threshold_reached,
        status: res.data.status,
      };
    } catch (err) {
      return this.handleError(err, "submitGuardianProof");
    }
  }

  /**
   * Submits an old password proof for a recovery request.
   * POST /v1/client/auth/recovery/proof/old-password
   */
  async submitOldPasswordProof(
    params: SubmitOldPasswordProofParams,
  ): Promise<SubmitOldPasswordProofResult> {
    try {
      assertValid(
        validateToken(params.recoveryRequestId, "recoveryRequestId"),
      );
      assertValid(validateToken(params.password, "password"));
      const res = await this.http.post<{ status: string; message: string }>(
        "/v1/client/auth/recovery/proof/old-password",
        {
          recovery_request_id: params.recoveryRequestId,
          password: params.password,
        },
      );
      return { ok: true, status: res.data.status, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "submitOldPasswordProof");
    }
  }

  /**
   * Submits security questions answers for a recovery request.
   * POST /v1/client/auth/recovery/proof/security-questions
   */
  async submitSecurityQuestionsProof(
    params: SubmitSecurityQuestionsProofParams,
  ): Promise<SubmitSecurityQuestionsProofResult> {
    try {
      assertValid(
        validateToken(params.recoveryRequestId, "recoveryRequestId"),
      );
      const res = await this.http.post<{ status: string; message: string }>(
        "/v1/client/auth/recovery/proof/security-questions",
        {
          recovery_request_id: params.recoveryRequestId,
          answers: params.answers,
        },
      );
      return { ok: true, status: res.data.status, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "submitSecurityQuestionsProof");
    }
  }

  /**
   * Redeems a claim token, resets account password, and returns new recovery codes.
   * POST /v1/client/auth/recovery/claim
   */
  async claimAccount(params: ClaimAccountParams): Promise<ClaimAccountResult> {
    try {
      assertValid(validateToken(params.requestId, "requestId"));
      assertValid(validateToken(params.claimToken, "claimToken"));
      assertValid(validatePassword(params.newPassword));
      const res = await this.http.post<{
        status: string;
        message: string;
        recovery_codes: string[];
        device_cookie?: string;
      }>("/v1/client/auth/recovery/claim", {
        request_id: params.requestId,
        claim_token: params.claimToken,
        new_password: params.newPassword,
      });
      return {
        ok: true,
        status: res.data.status,
        message: res.data.message,
        recoveryCodes: res.data.recovery_codes,
        deviceCookie: res.data.device_cookie,
      };
    } catch (err) {
      return this.handleError(err, "claimAccount");
    }
  }

  /**
   * Cancels a recovery request via authenticated session.
   * POST /v1/client/auth/recovery/cancel
   */
  async cancelRecovery(
    params: CancelRecoveryParams,
  ): Promise<CancelRecoveryResult> {
    try {
      assertValid(
        validateToken(params.recoveryRequestId, "recoveryRequestId"),
      );
      const res = await this.http.post<{ status: string; message: string }>(
        "/v1/client/auth/recovery/cancel",
        { recovery_request_id: params.recoveryRequestId },
      );
      return { ok: true, status: res.data.status, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "cancelRecovery");
    }
  }

  /**
   * Cancels a recovery request via signed link token.
   * POST /v1/client/auth/recovery/cancel/token
   */
  async cancelRecoveryToken(
    params: CancelRecoveryTokenParams,
  ): Promise<CancelRecoveryTokenResult> {
    try {
      assertValid(
        validateToken(params.cancellationToken, "cancellationToken"),
      );
      const res = await this.http.post<{ status: string; message: string }>(
        "/v1/client/auth/recovery/cancel/token",
        { cancellation_token: params.cancellationToken },
      );
      return { ok: true, status: res.data.status, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "cancelRecoveryToken");
    }
  }

  private handleError(err: unknown, method: string): { ok: false; error: AuthnError } {
    const error =
      err instanceof AuthnError
        ? err
        : new AuthnError({
            message:
              err instanceof Error ? err.message : "An unexpected error occurred.",
            code: AuthnErrorCode.UNKNOWN,
            cause: err,
          });

    this.logger.error(`${method} failed: ${error.message}`, {
      code: error.code,
      statusCode: error.statusCode,
    });
    this.config.onError?.(error);
    return { ok: false, error };
  }
}

const TWO_FACTOR_METHODS: readonly TwoFactorMethod[] = [
  "totp",
  "passkey",
  "sms",
  "backup_code",
];

/**
 * normaliseTwoFactorMethods keeps the engine's ordering while dropping any name
 * this version of the SDK has no screen for.
 *
 * Order is meaningful — the engine sorts by last use so a challenge opens on the
 * factor its owner reached for last time — which rules out normalising through a
 * set. An unrecognised name is dropped rather than passed through, because a UI
 * that renders the list verbatim would otherwise offer a factor it cannot
 * collect. The list falls back to TOTP rather than to empty: the engine only
 * challenges an account that has a factor, so an empty result here means the
 * names drifted, and offering the one factor every tenant has is recoverable
 * where offering nothing is a dead end.
 */
function normaliseTwoFactorMethods(methods?: string[]): TwoFactorMethod[] {
  const known = (methods ?? []).filter((m): m is TwoFactorMethod =>
    TWO_FACTOR_METHODS.includes(m as TwoFactorMethod),
  );

  return known.length > 0 ? known : ["totp"];
}

function mapAppConfig(data: ServerAppConfigResponse): AppConfig {
  return {
    application: {
      id: data.application.id,
      name: data.application.name,
      environment: data.application.environment === "live" ? "live" : "test",
    },
    tenant: { name: data.tenant.name, slug: data.tenant.slug },
    branding: {
      appName: data.branding.app_name,
      logoUrl: data.branding.logo_url,
      logoDarkUrl: data.branding.logo_dark_url,
      faviconUrl: data.branding.favicon_url,
      primaryColor: data.branding.primary_color,
      backgroundColor: data.branding.background_color,
      textColor: data.branding.text_color,
      buttonTextColor: data.branding.button_text_color,
      fontFamily: data.branding.font_family,
      supportUrl: data.branding.support_url,
      termsUrl: data.branding.terms_url,
      privacyUrl: data.branding.privacy_url,
      customCss: data.branding.custom_css,
    },
    signInMethods: {
      password: data.sign_in_methods.password,
      magicLink: data.sign_in_methods.magic_link,
      passkey: data.sign_in_methods.passkey,
      enterpriseSso: data.sign_in_methods.enterprise_sso,
      socialProviders: data.sign_in_methods.social_providers ?? [],
    },
    secondFactors: {
      totp: data.second_factors.totp,
      sms: data.second_factors.sms,
      passkey: data.second_factors.passkey,
      recoveryCodes: data.second_factors.recovery_codes,
      push: data.second_factors.push,
    },
    passwordRules: {
      minLength: data.password_rules.min_length,
      maxLength: data.password_rules.max_length,
      requireUppercase: data.password_rules.require_uppercase,
      requireLowercase: data.password_rules.require_lowercase,
      requireNumeric: data.password_rules.require_numeric,
      requireSpecial: data.password_rules.require_special,
      enforced: data.password_rules.enforced,
    },
    emailVerification: {
      required: data.email_verification.required,
      // Anything other than the two documented values is read as the stricter
      // one: treating an unknown mode as "soft" would admit an unverified user
      // the tenant may have meant to block.
      mode: data.email_verification.mode === "soft" ? "soft" : "hard",
    },
    accountRecovery: {
      guardians: data.account_recovery.guardians,
      phoneOtp: data.account_recovery.phone_otp,
      emailOtp: data.account_recovery.email_otp,
      oldPassword: data.account_recovery.old_password,
      securityQuestions: data.account_recovery.security_questions,
      minGuardians: data.account_recovery.min_guardians,
      maxGuardians: data.account_recovery.max_guardians,
    },
  };
}
