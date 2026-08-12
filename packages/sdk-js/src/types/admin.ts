/**
 * @authn/js — Admin SDK Types
 */


export interface AuthnAdminConfig {
  secretKey: string;
  publishableKey?: string;
  endpoint?: string;
  tenantId?: string;
  environment?: "test" | "live";
  timeout?: number;
}

// RBAC
export interface RoleDTO {
  id: string;
  tenantId: string;
  name: string;
  slug: string;
  description?: string;
  permissions: string[];
  createdAt: string;
}

export interface CreateRoleParams {
  name: string;
  slug?: string;
  description?: string;
  permissions: string[];
}

export interface CreateRoleResult {
  ok: true;
  role: RoleDTO;
}

export interface ListRolesResult {
  ok: true;
  roles: RoleDTO[];
}

export interface UpdateRolePermissionsParams {
  roleId: string;
  permissions: string[];
}

export interface UpdateRolePermissionsResult {
  ok: true;
  role: RoleDTO;
}

export interface AssignUserRoleParams {
  userId: string;
  roleSlug: string;
}

export interface AssignUserRoleResult {
  ok: true;
  message: string;
}

export interface RevokeUserRoleParams {
  userId: string;
  roleSlug: string;
}

export interface RevokeUserRoleResult {
  ok: true;
  message: string;
}

export interface GetUserPermissionsResult {
  ok: true;
  permissions: string[];
}

// Impersonation
export interface InitiateImpersonationParams {
  userId: string;
  reason?: string;
  verificationMethod?: "password" | "totp" | "passkey";
  adminPassword?: string;
  verificationPayload?: string;
}

export interface InitiateImpersonationResult {
  ok: true;
  impersonationToken: string;
  expiresAt: string;
}

export interface ExitImpersonationResult {
  ok: true;
  message: string;
}

export interface ImpersonationPolicyDTO {
  enabled: boolean;
  requireStepUpAuth?: boolean;
  requireStepUp?: boolean;
  maxDurationMinutes?: number;
  maxDurationSeconds?: number;
  allowImpersonateAdmins?: boolean;
  requireTicketId?: boolean;
  emailNotificationPolicy?: string;
}

export interface GetImpersonationPolicyResult {
  ok: true;
  policy: ImpersonationPolicyDTO;
}

export interface UpdateImpersonationPolicyParams {
  enabled?: boolean;
  requireStepUp?: boolean;
  requireStepUpAuth?: boolean;
  maxDurationMinutes?: number;
  maxDurationSeconds?: number;
  allowImpersonateAdmins?: boolean;
  requireTicketId?: boolean;
  emailNotificationPolicy?: string;
}

export interface UpdateImpersonationPolicyResult {
  ok: true;
  policy: ImpersonationPolicyDTO;
}

// Webhooks
export interface WebhookEndpointDTO {
  id: string;
  tenantId: string;
  url: string;
  description?: string;
  events: string[];
  secret?: string;
  status: "active" | "disabled";
  createdAt: string;
}

export interface CreateWebhookEndpointParams {
  url: string;
  events: string[];
  description?: string;
}

export interface CreateWebhookEndpointResult {
  ok: true;
  endpoint: WebhookEndpointDTO;
}

export interface ListWebhookEndpointsResult {
  ok: true;
  endpoints: WebhookEndpointDTO[];
}

export interface GetWebhookEndpointResult {
  ok: true;
  endpoint: WebhookEndpointDTO;
}

export interface UpdateWebhookEndpointParams {
  endpointId: string;
  url?: string;
  events?: string[];
  description?: string;
  status?: "active" | "disabled";
}

export interface UpdateWebhookEndpointResult {
  ok: true;
  endpoint: WebhookEndpointDTO;
}

export interface DeleteWebhookEndpointResult {
  ok: true;
  endpointId: string;
  message: string;
}

export interface RotateWebhookSecretResult {
  ok: true;
  endpointId: string;
  secret: string;
}

export interface WebhookDeliveryDTO {
  id: string;
  endpointId: string;
  eventType: string;
  responseStatusCode: number;
  success: boolean;
  deliveredAt: string;
}

export interface ListWebhookDeliveriesResult {
  ok: true;
  deliveries: WebhookDeliveryDTO[];
}

export interface RedeliverWebhookResult {
  ok: true;
  deliveryId: string;
  message: string;
}

// SAML SSO
export interface SAMLConnectionDTO {
  id: string;
  orgId: string;
  idpMetadataUrl?: string;
  idpEntityId?: string;
  ssoUrl?: string;
  certificate?: string;
  enabled: boolean;
  createdAt: string;
}

export interface CreateSAMLConnectionParams {
  orgId: string;
  idpMetadataUrl?: string;
  idpEntityId?: string;
  ssoUrl?: string;
  idpSsoUrl?: string;
  certificate?: string;
  idpCertificate?: string;
  allowedDomains?: string[];
}

export interface CreateSAMLConnectionResult {
  ok: true;
  connection: SAMLConnectionDTO;
}

export interface GetSAMLConnectionResult {
  ok: true;
  connection: SAMLConnectionDTO;
}

export interface UpdateSAMLConnectionParams {
  orgId: string;
  idpMetadataUrl?: string;
  idpEntityId?: string;
  ssoUrl?: string;
  idpSsoUrl?: string;
  certificate?: string;
  idpCertificate?: string;
  allowedDomains?: string[];
  enabled?: boolean;
}

export interface UpdateSAMLConnectionResult {
  ok: true;
  connection: SAMLConnectionDTO;
}

export interface DeleteSAMLConnectionResult {
  ok: true;
  orgId: string;
  message: string;
}

// API Keys
export interface APIKeyDTO {
  id: string;
  tenantId: string;
  name: string;
  type: "publishable" | "secret";
  keyPrefix: string;
  environment: "test" | "live";
  key?: string; // Only returned on creation
  createdAt: string;
  revokedAt?: string;
}

export interface CreateAPIKeyParams {
  name: string;
  type: "publishable" | "secret";
  environment?: "test" | "live";
}

export interface CreateAPIKeyResult {
  ok: true;
  key: APIKeyDTO;
}

export interface ListAPIKeysResult {
  ok: true;
  keys: APIKeyDTO[];
}

export interface RevokeAPIKeyResult {
  ok: true;
  keyId: string;
  message: string;
}

// Audit Logs
export interface AuditLogDTO {
  id: string;
  tenantId: string;
  actorType: "admin" | "user" | "system";
  actorId?: string;
  eventType: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
  createdAt: string;
}

export interface ListAuditLogsParams {
  limit?: number;
  offset?: number;
  actorId?: string;
  eventType?: string;
}

export interface ListAuditLogsResult {
  ok: true;
  logs: AuditLogDTO[];
  total: number;
}
