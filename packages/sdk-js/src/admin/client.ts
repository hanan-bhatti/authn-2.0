/**
 * @authn/js — AuthnAdminClient
 * 
 * High-privilege Admin API client for server-side / Node.js usage.
 * NEVER expose or instantiate this client in browser bundles.
 */

import type {
  AuthnAdminConfig,
  CreateRoleParams,
  CreateRoleResult,
  ListRolesResult,
  UpdateRolePermissionsParams,
  UpdateRolePermissionsResult,
  AssignUserRoleParams,
  AssignUserRoleResult,
  RevokeUserRoleParams,
  RevokeUserRoleResult,
  GetUserPermissionsResult,
  InitiateImpersonationParams,
  InitiateImpersonationResult,
  ExitImpersonationResult,
  GetImpersonationPolicyResult,
  UpdateImpersonationPolicyParams,
  UpdateImpersonationPolicyResult,
  CreateWebhookEndpointParams,
  CreateWebhookEndpointResult,
  ListWebhookEndpointsResult,
  GetWebhookEndpointResult,
  UpdateWebhookEndpointParams,
  UpdateWebhookEndpointResult,
  DeleteWebhookEndpointResult,
  RotateWebhookSecretResult,
  ListWebhookDeliveriesResult,
  RedeliverWebhookResult,
  CreateSAMLConnectionParams,
  CreateSAMLConnectionResult,
  GetSAMLConnectionResult,
  UpdateSAMLConnectionParams,
  UpdateSAMLConnectionResult,
  DeleteSAMLConnectionResult,
  CreateAPIKeyParams,
  CreateAPIKeyResult,
  ListAPIKeysResult,
  RevokeAPIKeyResult,
  ListAuditLogsParams,
  ListAuditLogsResult,
  PasswordPolicyDTO,
  GetPasswordPolicyResult,
  UpdatePasswordPolicyParams,
  UpdatePasswordPolicyResult,
  SecurityPolicyDTO,
  GetSecurityPolicyResult,
  UpdateSecurityPolicyParams,
  UpdateSecurityPolicyResult,
  RecoveryPolicyDTO,
  GetRecoveryPolicyResult,
  UpdateRecoveryPolicyParams,
  UpdateRecoveryPolicyResult,
  RotateJWKSResult,
  RoleDTO,
  ImpersonationPolicyDTO,
  WebhookEndpointDTO,
  WebhookDeliveryDTO,
  SAMLConnectionDTO,
  APIKeyDTO,
  AuditLogDTO,
} from "../types/admin";
import { AuthnError, AuthnLogger } from "../types";
import { HttpClient } from "../core/http";
import { assertValid, validateToken } from "../core/validation";

const noopLogger: AuthnLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

export class AuthnAdminClient {
  private http: HttpClient;
  private secretKey: string;
  private publishableKey: string;

  constructor(config: AuthnAdminConfig) {
    const rawSecretKey =
      config?.secretKey ||
      (typeof process !== "undefined" ? process.env?.AUTHN_SECRET_KEY : undefined);

    const isBrowser = typeof window !== "undefined";

    // In browser environments, throw if a raw secret key (sk_...) is provided to prevent key leakage
    if (isBrowser && rawSecretKey && rawSecretKey.startsWith("sk_")) {
      throw new Error(
        "AuthnAdminClient Error: Secret keys (sk_...) must NOT be exposed or used in browser environments. Use session JWT token authentication for client-side admin operations."
      );
    }

    const secretKey = isBrowser ? undefined : rawSecretKey;

    const publishableKey =
      config?.publishableKey ||
      (typeof process !== "undefined" ? process.env?.NEXT_PUBLIC_AUTHN_PUBLISHABLE_KEY : undefined) ||
      "";

    const endpoint =
      config?.endpoint ||
      (typeof process !== "undefined"
        ? process.env?.NEXT_PUBLIC_AUTHN_API_URL || process.env?.APP_BASE_URL
        : undefined) ||
      "http://127.0.0.1:8080";

    this.secretKey = secretKey || publishableKey;
    this.publishableKey = publishableKey;


    this.http = new HttpClient({
      baseUrl: endpoint,
      apiKey: this.secretKey,
      timeout: config.timeout || 10000,
      customHeaders: config.headers,
      logger: noopLogger,
    });
  }

  private async safeCall<T>(fn: () => Promise<T>): Promise<T | { ok: false; error: AuthnError }> {
    try {
      return await fn();
    } catch (err: unknown) {
      if (err instanceof AuthnError) {
        return { ok: false, error: err };
      }
      return {
        ok: false,
        error: AuthnError.networkError(err),
      };
    }
  }

  // --- RBAC Sub-module ---
  public async createRole(
    params: CreateRoleParams
  ): Promise<CreateRoleResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(params?.name, "name"));
      if (!Array.isArray(params?.permissions)) {
        throw AuthnError.validation("permissions", "permissions array is required");
      }

      const res = await this.http.post<RoleDTO>("/v1/tenant/roles", {
        name: params.name,
        slug: params.slug || params.name.toLowerCase().replace(/\s+/g, "_"),
        description: params.description,
        permissions: params.permissions,
      });
      return { ok: true, role: res.data };
    });
  }

  public async listRoles(): Promise<
    ListRolesResult | { ok: false; error: AuthnError }
  > {
    return this.safeCall(async () => {
      const res = await this.http.get<RoleDTO[]>("/v1/tenant/roles");
      return { ok: true, roles: Array.isArray(res.data) ? res.data : [] };
    });
  }

  public async updateRolePermissions(
    params: UpdateRolePermissionsParams
  ): Promise<UpdateRolePermissionsResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(params?.roleId, "roleId"));
      if (!Array.isArray(params?.permissions)) {
        throw AuthnError.validation("permissions", "permissions array is required");
      }

      const res = await this.http.put<RoleDTO>(
        `/v1/tenant/roles/${encodeURIComponent(params.roleId)}/permissions`,
        { permissions: params.permissions }
      );
      return { ok: true, role: res.data };
    });
  }

  public async assignUserRole(
    params: AssignUserRoleParams
  ): Promise<AssignUserRoleResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(params?.userId, "userId"));
      assertValid(validateToken(params?.roleSlug, "roleSlug"));

      await this.http.post(
        `/v1/admin/users/${encodeURIComponent(params.userId)}/roles`,
        { role_slug: params.roleSlug }
      );
      return { ok: true, message: "Role assigned successfully" };
    });
  }

  public async revokeUserRole(
    params: RevokeUserRoleParams
  ): Promise<RevokeUserRoleResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(params?.userId, "userId"));
      assertValid(validateToken(params?.roleSlug, "roleSlug"));

      await this.http.del(
        `/v1/admin/users/${encodeURIComponent(
          params.userId
        )}/roles/${encodeURIComponent(params.roleSlug)}`
      );
      return { ok: true, message: "Role revoked successfully" };
    });
  }

  public async getUserPermissions(): Promise<
    GetUserPermissionsResult | { ok: false; error: AuthnError }
  > {
    return this.safeCall(async () => {
      const res = await this.http.get<{ permissions: string[] }>(
        "/v1/client/user/permissions"
      );
      return { ok: true, permissions: res.data.permissions || [] };
    });
  }

  // --- Impersonation Sub-module ---
  public async impersonateUser(
    params: InitiateImpersonationParams
  ): Promise<InitiateImpersonationResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(params?.userId, "userId"));

      const res = await this.http.post<{
        access_token?: string;
        accessToken?: string;
        impersonation_token?: string;
        impersonationToken?: string;
        token?: string;
        expires_at?: string;
        expiresAt?: string;
        expires_in?: number;
      }>(`/v1/admin/users/${encodeURIComponent(params.userId)}/impersonate`, {
        reason: params.reason || "Admin support impersonation",
        verification_method: params.verificationMethod,
        admin_password: params.adminPassword,
        verification_payload: params.verificationPayload,
      });

      const token =
        res.data.access_token ||
        res.data.accessToken ||
        res.data.impersonation_token ||
        res.data.impersonationToken ||
        res.data.token ||
        "";
      const expiresAt =
        res.data.expires_at ||
        res.data.expiresAt ||
        (res.data.expires_in
          ? new Date(Date.now() + res.data.expires_in * 1000).toISOString()
          : new Date().toISOString());

      return { ok: true, impersonationToken: token, expiresAt };
    });
  }

  public async exitImpersonation(
    impersonationToken: string
  ): Promise<ExitImpersonationResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(impersonationToken, "impersonationToken"));

      await this.http.post("/v1/client/auth/impersonate/exit", undefined, {
        Authorization: `Bearer ${impersonationToken}`,
        "X-Authn-Publishable-Key": this.publishableKey,
      });
      return { ok: true, message: "Exited impersonation successfully" };
    });
  }

  public async getImpersonationPolicy(): Promise<
    GetImpersonationPolicyResult | { ok: false; error: AuthnError }
  > {
    return this.safeCall(async () => {
      const res = await this.http.get<ImpersonationPolicyDTO>(
        "/v1/tenant/impersonation-policy"
      );
      return { ok: true, policy: res.data };
    });
  }

  public async updateImpersonationPolicy(
    params: UpdateImpersonationPolicyParams
  ): Promise<
    UpdateImpersonationPolicyResult | { ok: false; error: AuthnError }
  > {
    return this.safeCall(async () => {
      const body: Record<string, unknown> = {};
      if (params.enabled !== undefined) body.enabled = params.enabled;
      if (params.requireStepUpAuth !== undefined || params.requireStepUp !== undefined) {
        body.require_step_up_auth = params.requireStepUpAuth ?? params.requireStepUp;
      }
      if (params.maxDurationMinutes !== undefined) {
        body.max_duration_minutes = params.maxDurationMinutes;
      } else if (params.maxDurationSeconds !== undefined) {
        body.max_duration_minutes = Math.max(1, Math.floor(params.maxDurationSeconds / 60));
      } else {
        body.max_duration_minutes = 30;
      }
      if (params.allowImpersonateAdmins !== undefined) {
        body.allow_impersonate_admins = params.allowImpersonateAdmins;
      }
      if (params.requireTicketId !== undefined) {
        body.require_ticket_id = params.requireTicketId;
      }
      if (params.emailNotificationPolicy !== undefined) {
        body.email_notification_policy = params.emailNotificationPolicy;
      } else {
        body.email_notification_policy = "DISABLED";
      }

      const res = await this.http.put<ImpersonationPolicyDTO>(
        "/v1/tenant/impersonation-policy",
        body
      );
      return { ok: true, policy: res.data };
    });
  }

  // --- Webhooks Sub-module ---
  public async createWebhookEndpoint(
    params: CreateWebhookEndpointParams
  ): Promise<CreateWebhookEndpointResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(params?.url, "url"));
      if (!Array.isArray(params?.events)) {
        throw AuthnError.validation("events", "events array is required");
      }

      const res = await this.http.post<WebhookEndpointDTO>(
        "/v1/admin/webhooks/endpoints",
        {
          url: params.url,
          events: params.events,
          description: params.description,
        }
      );
      return { ok: true, endpoint: res.data };
    });
  }

  public async listWebhookEndpoints(): Promise<
    ListWebhookEndpointsResult | { ok: false; error: AuthnError }
  > {
    return this.safeCall(async () => {
      const res = await this.http.get<WebhookEndpointDTO[]>(
        "/v1/admin/webhooks/endpoints"
      );
      return { ok: true, endpoints: Array.isArray(res.data) ? res.data : [] };
    });
  }

  public async getWebhookEndpoint(
    endpointId: string
  ): Promise<GetWebhookEndpointResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(endpointId, "endpointId"));

      const res = await this.http.get<WebhookEndpointDTO>(
        `/v1/admin/webhooks/endpoints/${encodeURIComponent(endpointId)}`
      );
      return { ok: true, endpoint: res.data };
    });
  }

  public async updateWebhookEndpoint(
    params: UpdateWebhookEndpointParams
  ): Promise<UpdateWebhookEndpointResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(params?.endpointId, "endpointId"));

      const res = await this.http.put<WebhookEndpointDTO>(
        `/v1/admin/webhooks/endpoints/${encodeURIComponent(params.endpointId)}`,
        {
          url: params.url,
          events: params.events,
          description: params.description,
          status: params.status,
        }
      );
      return { ok: true, endpoint: res.data };
    });
  }

  public async deleteWebhookEndpoint(
    endpointId: string
  ): Promise<DeleteWebhookEndpointResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(endpointId, "endpointId"));

      await this.http.del(
        `/v1/admin/webhooks/endpoints/${encodeURIComponent(endpointId)}`
      );
      return {
        ok: true,
        endpointId,
        message: "Webhook endpoint deleted successfully",
      };
    });
  }

  public async pingWebhookEndpoint(
    endpointId: string
  ): Promise<{ ok: true; message: string } | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(endpointId, "endpointId"));

      await this.http.post(
        `/v1/admin/webhooks/endpoints/${encodeURIComponent(endpointId)}/ping`
      );
      return { ok: true, message: "Ping sent successfully" };
    });
  }

  public async rotateWebhookSecret(
    endpointId: string
  ): Promise<RotateWebhookSecretResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(endpointId, "endpointId"));

      const res = await this.http.post<{ secret: string }>(
        `/v1/admin/webhooks/endpoints/${encodeURIComponent(
          endpointId
        )}/rotate-secret`
      );
      return { ok: true, endpointId, secret: res.data.secret || "" };
    });
  }

  public async listWebhookDeliveries(params?: { endpointId?: string; limit?: number }): Promise<
    ListWebhookDeliveriesResult | { ok: false; error: AuthnError }
  > {
    return this.safeCall(async () => {
      const queryParams = new URLSearchParams();
      if (params?.endpointId) queryParams.set("endpoint_id", params.endpointId);
      if (params?.limit) queryParams.set("limit", String(params.limit));
      const qs = queryParams.toString();
      const path = `/v1/admin/webhooks/deliveries${qs ? `?${qs}` : ""}`;
      const res = await this.http.get<WebhookDeliveryDTO[]>(path);
      return { ok: true, deliveries: Array.isArray(res.data) ? res.data : [] };
    });
  }

  public async redeliverWebhook(
    deliveryId: string
  ): Promise<RedeliverWebhookResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(deliveryId, "deliveryId"));

      await this.http.post(
        `/v1/admin/webhooks/deliveries/${encodeURIComponent(
          deliveryId
        )}/redeliver`
      );
      return { ok: true, deliveryId, message: "Redelivery scheduled successfully" };
    });
  }

  // --- SAML SSO Sub-module ---
  public async createSAMLConnection(
    params: CreateSAMLConnectionParams
  ): Promise<CreateSAMLConnectionResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(params?.orgId, "orgId"));

      const res = await this.http.post<SAMLConnectionDTO>(
        `/v1/tenant/organizations/${encodeURIComponent(params.orgId)}/saml`,
        {
          idp_metadata_url: params.idpMetadataUrl,
          idp_entity_id: params.idpEntityId,
          idp_sso_url: params.idpSsoUrl || params.ssoUrl,
          idp_certificate: params.idpCertificate || params.certificate,
          allowed_domains: params.allowedDomains || ["verifier-test.com"],
        }
      );
      return { ok: true, connection: res.data };
    });
  }

  public async getSAMLConnection(
    orgId: string
  ): Promise<GetSAMLConnectionResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(orgId, "orgId"));

      const res = await this.http.get<SAMLConnectionDTO>(
        `/v1/tenant/organizations/${encodeURIComponent(orgId)}/saml`
      );
      return { ok: true, connection: res.data };
    });
  }

  public async updateSAMLConnection(
    params: UpdateSAMLConnectionParams
  ): Promise<UpdateSAMLConnectionResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(params?.orgId, "orgId"));

      const res = await this.http.patch<SAMLConnectionDTO>(
        `/v1/tenant/organizations/${encodeURIComponent(params.orgId)}/saml`,
        {
          idp_metadata_url: params.idpMetadataUrl,
          idp_entity_id: params.idpEntityId,
          idp_sso_url: params.idpSsoUrl || params.ssoUrl,
          idp_certificate: params.idpCertificate || params.certificate,
          allowed_domains: params.allowedDomains,
          enforce_sso: params.enabled,
        }
      );
      return { ok: true, connection: res.data };
    });
  }

  public async deleteSAMLConnection(
    orgId: string
  ): Promise<DeleteSAMLConnectionResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(orgId, "orgId"));

      await this.http.del(
        `/v1/tenant/organizations/${encodeURIComponent(orgId)}/saml`
      );
      return { ok: true, orgId, message: "SAML connection deleted successfully" };
    });
  }

  // --- API Keys Sub-module ---
  public async createAPIKey(
    params: CreateAPIKeyParams
  ): Promise<CreateAPIKeyResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(params?.name, "name"));
      assertValid(validateToken(params?.type, "type"));

      const res = await this.http.post<APIKeyDTO>("/v1/admin/keys", {
        name: params.name,
        type: params.type,
        environment: params.environment || "test",
      });
      return { ok: true, key: res.data };
    });
  }

  public async listAPIKeys(): Promise<
    ListAPIKeysResult | { ok: false; error: AuthnError }
  > {
    return this.safeCall(async () => {
      const res = await this.http.get<APIKeyDTO[]>("/v1/admin/keys");
      return { ok: true, keys: Array.isArray(res.data) ? res.data : [] };
    });
  }

  public async revokeAPIKey(
    keyId: string
  ): Promise<RevokeAPIKeyResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      assertValid(validateToken(keyId, "keyId"));

      await this.http.post(
        `/v1/admin/keys/${encodeURIComponent(keyId)}/revoke`
      );
      return { ok: true, keyId, message: "API key revoked successfully" };
    });
  }

  // --- Audit Logs Sub-module ---
  public async listAuditLogs(
    params?: ListAuditLogsParams
  ): Promise<ListAuditLogsResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      const queryParams: Record<string, string> = {};
      if (params?.limit) queryParams.limit = params.limit.toString();
      if (params?.offset) queryParams.offset = params.offset.toString();
      if (params?.actorId) queryParams.actor_id = params.actorId;
      if (params?.eventType) queryParams.event_type = params.eventType;

      const res = await this.http.get<{ logs: AuditLogDTO[]; total: number }>(
        "/v1/admin/audit-logs",
        queryParams
      );
      return {
        ok: true,
        logs: Array.isArray(res.data.logs) ? res.data.logs : [],
        total: res.data.total || 0,
      };
    });
  }

  // --- Password Policy ---
  public async getPasswordPolicy(): Promise<
    GetPasswordPolicyResult | { ok: false; error: AuthnError }
  > {
    return this.safeCall(async () => {
      const res = await this.http.get<PasswordPolicyDTO>("/v1/tenant/password-policy");
      return { ok: true, policy: res.data };
    });
  }

  public async updatePasswordPolicy(
    params: UpdatePasswordPolicyParams
  ): Promise<UpdatePasswordPolicyResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      const res = await this.http.put<PasswordPolicyDTO>("/v1/tenant/password-policy", {
        min_length: params.minLength,
        require_uppercase: params.requireUppercase,
        require_lowercase: params.requireLowercase,
        require_numbers: params.requireNumbers,
        require_symbols: params.requireSymbols,
        max_age_days: params.maxAgeDays,
        prevent_reuse_count: params.preventReuseCount,
      });
      return { ok: true, policy: res.data };
    });
  }

  // --- Security Policy ---
  public async getSecurityPolicy(): Promise<
    GetSecurityPolicyResult | { ok: false; error: AuthnError }
  > {
    return this.safeCall(async () => {
      const res = await this.http.get<SecurityPolicyDTO>("/v1/tenant/security-policy");
      return { ok: true, policy: res.data };
    });
  }

  public async updateSecurityPolicy(
    params: UpdateSecurityPolicyParams
  ): Promise<UpdateSecurityPolicyResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      const res = await this.http.put<SecurityPolicyDTO>("/v1/tenant/security-policy", {
        require_mfa_admins: params.requireMfaAdmins,
        require_mfa_all: params.requireMfaAll,
        session_timeout_minutes: params.sessionTimeoutMinutes,
        max_failed_attempts: params.maxFailedAttempts,
        lockout_duration_minutes: params.lockoutDurationMinutes,
        allowed_ip_ranges: params.allowedIpRanges,
      });
      return { ok: true, policy: res.data };
    });
  }

  // --- Recovery Policy ---
  public async getRecoveryPolicy(): Promise<
    GetRecoveryPolicyResult | { ok: false; error: AuthnError }
  > {
    return this.safeCall(async () => {
      const res = await this.http.get<RecoveryPolicyDTO>("/v1/tenant/recovery-policy");
      return { ok: true, policy: res.data };
    });
  }

  public async updateRecoveryPolicy(
    params: UpdateRecoveryPolicyParams
  ): Promise<UpdateRecoveryPolicyResult | { ok: false; error: AuthnError }> {
    return this.safeCall(async () => {
      const res = await this.http.put<RecoveryPolicyDTO>("/v1/tenant/recovery-policy", {
        allow_guardian_recovery: params.allowGuardianRecovery,
        min_guardians: params.minGuardians,
        allow_security_questions: params.allowSecurityQuestions,
        allow_old_password: params.allowOldPassword,
        recovery_delay_hours: params.recoveryDelayHours,
      });
      return { ok: true, policy: res.data };
    });
  }

  // --- JWKS Key Rotation ---
  public async rotateJWKS(): Promise<
    RotateJWKSResult | { ok: false; error: AuthnError }
  > {
    return this.safeCall(async () => {
      const res = await this.http.post<{ message?: string; active_kid?: string }>(
        "/v1/admin/jwks/rotate"
      );
      return {
        ok: true,
        message: res.data?.message || "JWKS signing key rotated successfully",
        activeKid: res.data?.active_kid,
      };
    });
  }
}
