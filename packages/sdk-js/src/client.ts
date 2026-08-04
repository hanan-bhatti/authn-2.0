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

import { HttpClient } from "./http";
import { createDefaultLogger } from "./logger";
import type {
  AuthnClientConfig,
  AuthnLogger,
  AuthnSession,
  AuthnUser,
  AuthResult,
  AuthStateCallback,
  LoginParams,
  MagicLinkParams,
  PolicyWarning,
  ResendVerificationParams,
  SessionResult,
  SignUpParams,
  VerifyEmailParams,
  VerifyMagicLinkParams,
  VoidResult,
} from "./types";
import { AuthnError, AuthnErrorCode } from "./types";
import {
  assertValid,
  validateEmail,
  validateEnvironment,
  validatePassword,
  validatePublishableKey,
  validateTenantId,
  validateToken,
} from "./validation";

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
    // Validate configuration upfront
    assertValid(validatePublishableKey(config.publishableKey));

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
    const logger = config.logger ?? createDefaultLogger();

    // Infer environment from key prefix
    const inferredEnv = config.publishableKey.startsWith("pk_live_")
      ? "live"
      : "test";
    const environment = config.environment ?? inferredEnv;

    this.config = { ...config, endpoint, timeout, autoRefresh, environment };
    this.logger = logger;

    this.http = new HttpClient({
      baseUrl: endpoint,
      publishableKey: config.publishableKey,
      timeout,
      logger,
      customFetch: config.fetch,
    });

    this.logger.info("AuthnClient initialized", {
      endpoint,
      environment,
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

  private resolveTenantId(override?: string): string {
    return override ?? this.config.tenantId ?? "tnt_default";
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
