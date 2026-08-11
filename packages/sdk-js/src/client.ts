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
  AuthnClientConfig,
  AuthnDeviceSession,
  AuthnLogger,
  AuthnProfile,
  AuthnSession,
  AuthnUser,
  AuthResult,
  AuthStateCallback,
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
  PolicyWarning,
  ProfileResult,
  RecoveryCodesStatusResult,
  RecoveryEmailResult,
  RegenerateRecoveryCodesParams,
  RegenerateRecoveryCodesResult,
  ResendVerificationParams,
  RevokeSessionsResult,
  RevokeWebAuthnCredentialParams,
  SessionListResult,
  SessionResult,
  SignUpParams,
  SocialAccountsResult,
  UpdateProfileParams,
  VerifyEmailParams,
  VerifyMagicLinkParams,
  VerifyTOTPParams,
  VerifyTOTPResult,
  VoidResult,
  WebAuthnPasskey,
} from "./types";
import { AuthnError, AuthnErrorCode } from "./types";
import {
  assertValid,
  validateEmail,
  validateEnvironment,
  validatePassword,
  validatePhoneNumber,
  validatePublishableKey,
  validateTenantId,
  validateToken,
  validateTOTPCode,
  validateWebAuthnCredential,
} from "./core/validation";
import {
  formatCreationCredential,
  formatRequestCredential,
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

interface ServerRegenerateRecoveryCodesResponse {
  message: string;
  recovery_codes: string[];
}

interface ServerRecoveryCodesStatusResponse {
  remaining_count: number;
  total_count: number;
  has_recovery_codes: boolean;
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

interface ServerListPasskeysResponse {
  credentials: WebAuthnPasskey[];
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
      publishableKey: publishableKey!,
      timeout,
      logger,
      customFetch: config.fetch,
      getAccessToken: () => this.getToken(),
      onRefreshToken: () => this.refreshSession(),
    });

    this.logger.info("AuthnClient initialized", {
      endpoint,
      environment: this.config.environment,
      autoRefresh,
    });
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
   * });
   * ```
   */
  async signUp(params: SignUpParams): Promise<AuthResult> {
    this.guardDestroyed();

    // Validate inputs before network call
    assertValid(validateEmail(params.email));
    assertValid(validatePassword(params.password));
    assertValid(validateTenantId(params.tenantId));
    assertValid(validateEnvironment(params.environment));

    try {
      const res = await this.http.post<ServerAuthResponse>(
        "/v1/client/signup",
        {
          email: params.email,
          password: params.password,
          name: params.name,
          tenant_id: this.resolveTenantId(params.tenantId),
          environment: this.resolveEnvironment(params.environment),
        },
      );

      const session = this.mapSession(res.data);
      const policyWarning = this.mapPolicyWarning(res.data.policy_warning);

      this.setSession(session);
      this.logger.info("Sign-up successful", { userId: session.user.id });

      return { ok: true, session, policyWarning };
    } catch (err) {
      return this.handleError(err, "signUp");
    }
  }

  // -----------------------------------------------------------------------
  // Login
  // -----------------------------------------------------------------------

  /**
   * Authenticate an existing user with email and password.
   *
   * @param params - Login parameters.
   * @returns `{ ok: true, session }` on success, `{ ok: false, error }` on failure.
   *
   * @example
   * ```ts
   * const result = await authn.login({
   *   email: "user@example.com",
   *   password: "SuperSecret123!",
   * });
   * if (!result.ok && result.error.code === AuthnErrorCode.INVALID_CREDENTIALS) {
   *   showError("Wrong email or password");
   * }
   * ```
   */
  async login(params: LoginParams): Promise<AuthResult> {
    this.guardDestroyed();

    assertValid(validateEmail(params.email));
    assertValid(validatePassword(params.password));
    assertValid(validateTenantId(params.tenantId));
    assertValid(validateEnvironment(params.environment));

    try {
      const res = await this.http.post<ServerAuthResponse>(
        "/v1/client/login",
        {
          email: params.email,
          password: params.password,
          tenant_id: this.resolveTenantId(params.tenantId),
          environment: this.resolveEnvironment(params.environment),
        },
      );

      const session = this.mapSession(res.data);
      const policyWarning = this.mapPolicyWarning(res.data.policy_warning);

      this.setSession(session);
      this.logger.info("Login successful", { userId: session.user.id });

      return { ok: true, session, policyWarning };
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

      const session = this.mapSession(res.data);
      this.setSession(session);
      this.logger.info("Magic link verified", { userId: session.user.id });

      return { ok: true, session };
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
        "/v1/client/verify-email",
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
        "/v1/client/resend-verification",
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
   * Requires an authenticated session and the account password for
   * confirmation; the server returns `401` if it is wrong.
   */
  async deleteAccount(password: string): Promise<VoidResult> {
    this.guardDestroyed();

    try {
      assertValid(validateToken(password, "password"));

      const res = await this.http.del<ServerMessageResponse>(
        "/v1/client/user/account",
        { password },
      );

      // The account no longer exists — any retained session is meaningless.
      this.setSession(null);

      return { ok: true, message: res.data.message };
    } catch (err) {
      return this.handleError(err, "deleteAccount");
    }
  }

  // -----------------------------------------------------------------------
  // Destroy
  // -----------------------------------------------------------------------

  /**
   * Permanently tear down the client instance.
   *
   * Cancels the refresh timer, clears all listeners, and prevents further
   * API calls. Use this in SPA cleanup (e.g. React `useEffect` cleanup).
   */
  destroy(): void {
    this.destroyed = true;
    this.clearRefreshTimer();
    this.stateListeners.clear();
    this.currentSession = null;
    this.logger.debug("AuthnClient destroyed");
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

  private mapSession(data: ServerAuthResponse): AuthnSession {
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt:
        data.expires_at ?? Math.floor(Date.now() / 1000) + 15 * 60,
      user: {
        id: data.user.id,
        email: data.user.email,
        emailVerified: data.user.email_verified,
        name: data.user.name,
        status: (data.user.status as AuthnUser["status"]) ?? "active",
        createdAt: data.user.created_at,
      },
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
   * Target Route: POST /v1/client/2fa/totp/enroll
   */
  async enrollTOTP(): Promise<EnrollTOTPResult> {
    this.guardDestroyed();
    try {
      const res = await this.http.post<ServerEnrollTOTPResponse>("/v1/client/2fa/totp/enroll");
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
   * Target Route: POST /v1/client/2fa/totp/confirm
   */
  async confirmTOTP(params: ConfirmTOTPParams): Promise<Confirm2FAResult> {
    this.guardDestroyed();
    try {
      assertValid(validateTOTPCode(params?.code));
      const res = await this.http.post<ServerConfirmTOTPResponse>("/v1/client/2fa/totp/confirm", {
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
   * Target Route: POST /v1/client/2fa/totp/disable
   */
  async disableTOTP(params: DisableTOTPParams): Promise<VoidResult> {
    this.guardDestroyed();
    try {
      assertValid(validatePassword(params?.password));
      const res = await this.http.post<ServerMessageResponse>("/v1/client/2fa/totp/disable", {
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
   * Target Route: POST /v1/client/2fa/totp/verify
   */
  async verifyTOTP(params: VerifyTOTPParams): Promise<VerifyTOTPResult> {
    this.guardDestroyed();
    try {
      assertValid(validateTOTPCode(params?.code));
      if (params.mfaToken) {
        const res = await this.http.post<ServerAuthResponse>("/v1/client/2fa/totp/verify", {
          code: params.code,
          mfa_token: params.mfaToken,
          method: params.method,
        });
        const session = this.mapSession(res.data);
        this.setSession(session);
        return { ok: true, session };
      } else {
        const res = await this.http.post<{ valid: boolean }>("/v1/client/2fa/totp/verify", {
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
   * Target Route: POST /v1/client/2fa/sms/enroll
   */
  async enrollSMS(params: EnrollSMSParams): Promise<EnrollSMSResult> {
    this.guardDestroyed();
    try {
      assertValid(validatePhoneNumber(params?.phoneNumber));
      const res = await this.http.post<ServerEnrollSMSResponse>("/v1/client/2fa/sms/enroll", {
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
   * Confirm SMS 2FA enrollment with the received OTP code.
   * Target Route: POST /v1/client/2fa/sms/confirm
   */
  async confirmSMS(params: ConfirmSMSParams): Promise<Confirm2FAResult> {
    this.guardDestroyed();
    try {
      assertValid(validateTOTPCode(params?.code));
      const res = await this.http.post<ServerConfirmTOTPResponse>("/v1/client/2fa/sms/confirm", {
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
   * Target Route: DELETE /v1/client/2fa/sms/disable
   */
  async disableSMS(params: DisableSMSParams): Promise<VoidResult> {
    this.guardDestroyed();
    try {
      assertValid(validatePassword(params?.password));
      const res = await this.http.del<ServerMessageResponse>("/v1/client/2fa/sms/disable", {
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
   * Target Route: POST /v1/client/2fa/recovery-codes/regenerate
   */
  async regenerateRecoveryCodes(
    params: RegenerateRecoveryCodesParams,
  ): Promise<RegenerateRecoveryCodesResult> {
    this.guardDestroyed();
    try {
      assertValid(validatePassword(params?.password));
      const res = await this.http.post<ServerRegenerateRecoveryCodesResponse>(
        "/v1/client/2fa/recovery-codes/regenerate",
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
   * Target Route: GET /v1/client/2fa/recovery-codes/status
   */
  async getRecoveryCodesStatus(): Promise<RecoveryCodesStatusResult> {
    this.guardDestroyed();
    try {
      const res = await this.http.get<ServerRecoveryCodesStatusResponse>(
        "/v1/client/2fa/recovery-codes/status",
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
   * Begin WebAuthn passkey registration ceremony.
   * Target Route: POST /v1/client/2fa/webauthn/register/begin
   */
  async beginPasskeyRegistration(): Promise<BeginPasskeyRegistrationResult> {
    this.guardDestroyed();
    try {
      const res = await this.http.post<ServerBeginPasskeyRegistrationResponse>(
        "/v1/client/2fa/webauthn/register/begin",
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
   * Target Route: POST /v1/client/2fa/webauthn/register/finish
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
        "/v1/client/2fa/webauthn/register/finish",
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
   * Target Route: POST /v1/client/2fa/webauthn/login/begin
   */
  async beginPasskeyLogin(
    params: BeginPasskeyLoginParams,
  ): Promise<BeginPasskeyLoginResult> {
    this.guardDestroyed();
    try {
      const res = await this.http.post<ServerBeginPasskeyLoginResponse>(
        "/v1/client/2fa/webauthn/login/begin",
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
   * Target Route: POST /v1/client/2fa/webauthn/login/finish
   */
  async finishPasskeyLogin(
    params: FinishPasskeyLoginParams,
  ): Promise<FinishPasskeyLoginResult> {
    this.guardDestroyed();
    try {
      assertValid(validateWebAuthnCredential(params?.credential));
      const res = await this.http.postRaw<ServerAuthResponse>(
        "/v1/client/2fa/webauthn/login/finish",
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
   * Target Route: GET /v1/client/2fa/webauthn/credentials
   */
  async listWebAuthnCredentials(): Promise<ListWebAuthnCredentialsResult> {
    this.guardDestroyed();
    try {
      const res = await this.http.get<ServerListPasskeysResponse>(
        "/v1/client/2fa/webauthn/credentials",
      );
      return {
        ok: true,
        credentials: res.data.credentials,
      };
    } catch (err) {
      return this.handleError(err, "listWebAuthnCredentials");
    }
  }

  /**
   * Revoke (delete) a WebAuthn passkey.
   * Target Route: DELETE /v1/client/2fa/webauthn/credentials/:id
   */
  async revokeWebAuthnCredential(
    params: RevokeWebAuthnCredentialParams,
  ): Promise<VoidResult> {
    this.guardDestroyed();
    try {
      const path = `/v1/client/2fa/webauthn/credentials/${encodeURIComponent(params.id)}`;
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
      return this.handleError(err, "registerPasskey");
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
      return this.handleError(err, "loginWithPasskey");
    }
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
