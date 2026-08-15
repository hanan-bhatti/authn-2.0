# Authn Engine — Complete Route Inventory (OpenAPI 3.0 Baseline)

This document contains the single authoritative list of all registered HTTP routes in `apps/auth-engine`. Every subagent in Phase 1 extracts OpenAPI 3.0 YAML fragments according to these inventoried endpoints.

---

## Complete Route Checklist

| # | HTTP Method | Path | Internal Package | Handler Function | Code Location | Auth Requirements |
|---|-------------|------|------------------|------------------|---------------|-------------------|
| 1 | `GET` | `/v1/health` | `cmd/server` | `HealthCheckHandler` | `cmd/server/routes.go:30` | None (Public) |
| 2 | `GET` | `/v1/ready` | `cmd/server` | `ReadinessCheckHandler` | `cmd/server/routes.go:31` | None (Public) |
| 3 | `GET` | `/healthz` | `cmd/server` | `HealthCheckHandler` | `cmd/server/routes.go:32` | None (Public) |
| 4 | `GET` | `/readyz` | `cmd/server` | `ReadinessCheckHandler` | `cmd/server/routes.go:33` | None (Public) |
| 5 | `POST` | `/v1/client/auth/signup` | `auth` | `SignUp` | `internal/auth/handler.go:142` | `PublishableKey` (pk_) |
| 6 | `POST` | `/v1/client/auth/login` | `auth` | `Login` | `internal/auth/handler.go:143` | `PublishableKey` (pk_) |
| 7 | `GET` | `/v1/client/auth/verify-email` | `auth` | `VerifyEmail` | `internal/auth/handler.go:144` | `PublishableKey` (pk_) |
| 8 | `POST` | `/v1/client/auth/resend-verification` | `auth` | `ResendVerification` | `internal/auth/handler.go:145` | `PublishableKey` (pk_) |
| 9 | `POST` | `/v1/client/auth/magic-link` | `auth` | `SendMagicLink` | `internal/auth/handler.go:148` | `PublishableKey` (pk_) |
| 10 | `GET` | `/v1/client/auth/magic-link/verify` | `auth` | `VerifyMagicLink` | `internal/auth/handler.go:149` | `PublishableKey` (pk_) |
| 11 | `POST` | `/v1/client/auth/magic-link/verify` | `auth` | `VerifyMagicLink` | `internal/auth/handler.go:150` | `PublishableKey` (pk_) |
| 12 | `POST` | `/v1/client/auth/2fa/totp/enroll` | `auth` | `EnrollTOTP` | `internal/auth/handler.go:154` | `PublishableKey` + `BearerAuth` (Session) |
| 13 | `POST` | `/v1/client/auth/2fa/totp/confirm` | `auth` | `ConfirmTOTP` | `internal/auth/handler.go:155` | `PublishableKey` + `BearerAuth` (Session) |
| 14 | `POST` | `/v1/client/auth/2fa/totp/disable` | `auth` | `DisableTOTP` | `internal/auth/handler.go:156` | `PublishableKey` + `BearerAuth` (Session) |
| 15 | `POST` | `/v1/client/auth/2fa/totp/verify` | `auth` | `VerifyTOTP` | `internal/auth/handler.go:157` | `PublishableKey` (pk_) |
| 16 | `POST` | `/v1/client/auth/2fa/verify` | `auth` | `VerifyTOTP` | `internal/auth/handler.go:158` | `PublishableKey` (pk_) |
| 17 | `POST` | `/v1/client/auth/2fa/sms/enroll` | `auth` | `EnrollSMS` | `internal/auth/handler.go:161` | `PublishableKey` + `BearerAuth` (Session) |
| 18 | `POST` | `/v1/client/auth/2fa/sms/confirm` | `auth` | `ConfirmSMS` | `internal/auth/handler.go:162` | `PublishableKey` + `BearerAuth` (Session) |
| 19 | `DELETE` | `/v1/client/auth/2fa/sms/disable` | `auth` | `DisableSMS` | `internal/auth/handler.go:163` | `PublishableKey` + `BearerAuth` (Session) |
| 20 | `POST` | `/v1/client/auth/2fa/recovery-codes/regenerate` | `auth` | `RegenerateRecoveryCodes` | `internal/auth/handler.go:166` | `PublishableKey` + `BearerAuth` (Session) |
| 21 | `GET` | `/v1/client/auth/2fa/recovery-codes/status` | `auth` | `GetRecoveryCodesStatus` | `internal/auth/handler.go:167` | `PublishableKey` + `BearerAuth` (Session) |
| 22 | `POST` | `/v1/client/auth/2fa/webauthn/register/begin` | `auth` | `BeginWebAuthnRegistration` | `internal/auth/handler.go:170` | `PublishableKey` + `BearerAuth` (Session) |
| 23 | `POST` | `/v1/client/auth/2fa/webauthn/register/finish` | `auth` | `FinishWebAuthnRegistration` | `internal/auth/handler.go:171` | `PublishableKey` + `BearerAuth` (Session) |
| 24 | `POST` | `/v1/client/auth/2fa/webauthn/login/begin` | `auth` | `BeginWebAuthnLogin` | `internal/auth/handler.go:172` | `PublishableKey` (pk_) |
| 25 | `POST` | `/v1/client/auth/2fa/webauthn/login/finish` | `auth` | `FinishWebAuthnLogin` | `internal/auth/handler.go:173` | `PublishableKey` (pk_) |
| 26 | `GET` | `/v1/client/auth/2fa/webauthn/credentials` | `auth` | `ListWebAuthnPasskeys` | `internal/auth/handler.go:174` | `PublishableKey` + `BearerAuth` (Session) |
| 27 | `DELETE` | `/v1/client/auth/2fa/webauthn/credentials/:id` | `auth` | `DeleteWebAuthnPasskey` | `internal/auth/handler.go:175` | `PublishableKey` + `BearerAuth` (Session) |
| 28 | `POST` | `/v1/client/account/guardians/invite` | `auth` | `InviteGuardians` | `internal/auth/handler.go:179` | `PublishableKey` + `BearerAuth` (Session) |
| 29 | `POST` | `/v1/client/account/guardians/accept` | `auth` | `AcceptGuardianInvite` | `internal/auth/handler.go:180` | `PublishableKey` (pk_) |
| 30 | `GET` | `/v1/client/account/guardians` | `auth` | `ListGuardians` | `internal/auth/handler.go:181` | `PublishableKey` + `BearerAuth` (Session) |
| 31 | `DELETE` | `/v1/client/account/guardians/:id` | `auth` | `RevokeGuardian` | `internal/auth/handler.go:182` | `PublishableKey` + `BearerAuth` (Session) |
| 32 | `POST` | `/v1/client/auth/recovery/initiate` | `auth` | `InitiateRecovery` | `internal/auth/handler.go:186` | `PublishableKey` (pk_) |
| 33 | `POST` | `/v1/client/auth/recovery/proof/guardian` | `auth` | `SubmitGuardianProof` | `internal/auth/handler.go:187` | `PublishableKey` (pk_) |
| 34 | `POST` | `/v1/client/auth/recovery/proof/old-password` | `auth` | `SubmitOldPasswordProof` | `internal/auth/handler.go:188` | `PublishableKey` (pk_) |
| 35 | `POST` | `/v1/client/auth/recovery/proof/security-questions` | `auth` | `SubmitSecurityQuestionsProof` | `internal/auth/handler.go:189` | `PublishableKey` (pk_) |
| 36 | `POST` | `/v1/client/auth/recovery/claim` | `auth` | `ClaimAccount` | `internal/auth/handler.go:190` | `PublishableKey` (pk_) |
| 37 | `POST` | `/v1/client/auth/recovery/cancel` | `auth` | `CancelRecoveryAuth` | `internal/auth/handler.go:191` | `PublishableKey` (pk_) |
| 38 | `POST` | `/v1/client/auth/recovery/cancel/token` | `auth` | `CancelRecoveryToken` | `internal/auth/handler.go:192` | `PublishableKey` (pk_) |
| 39 | `POST` | `/v1/admin/keys` | `apikey` | `CreateKey` | `internal/apikey/handler.go:113` | `SecretKey` (sk_) or Admin JWT |
| 40 | `GET` | `/v1/admin/keys` | `apikey` | `ListKeys` | `internal/apikey/handler.go:114` | `SecretKey` (sk_) or Admin JWT |
| 41 | `POST` | `/v1/admin/keys/:id/revoke` | `apikey` | `RevokeKey` | `internal/apikey/handler.go:115` | `SecretKey` (sk_) or Admin JWT |
| 42 | `POST` | `/v1/admin/users/:user_id/impersonate` | `impersonation` | `InitiateImpersonation` | `internal/impersonation/handler.go:127` | `SecretKey` (sk_) or Admin JWT |
| 43 | `GET` | `/v1/tenant/impersonation-policy` | `impersonation` | `GetImpersonationPolicy` | `internal/impersonation/handler.go:133` | `SecretKey` (sk_) or Admin JWT |
| 44 | `PUT` | `/v1/tenant/impersonation-policy` | `impersonation` | `UpdateImpersonationPolicy` | `internal/impersonation/handler.go:134` | `SecretKey` (sk_) or Admin JWT |
| 45 | `POST` | `/v1/client/auth/impersonate/exit` | `impersonation` | `ExitImpersonation` | `internal/impersonation/handler.go:143` | `PublishableKey` + `BearerAuth` |
| 46 | `GET` | `/.well-known/openid-configuration` | `oauth` | `GetOIDCDiscovery` | `internal/oauth/handler.go:52` | None (Public) |
| 47 | `GET` | `/v1/oauth/jwks` | `oauth` | `GetJWKS` | `internal/oauth/handler.go:55` | None (Public) |
| 48 | `GET` | `/v1/oauth/userinfo` | `oauth` | `GetUserInfo` | `internal/oauth/handler.go:56` | `BearerAuth` |
| 49 | `GET` | `/v1/oauth/authorize` | `oauth` | `Authorize` | `internal/oauth/handler.go:58` | `PublishableKey` (pk_) |
| 50 | `POST` | `/v1/oauth/token` | `oauth` | `TokenExchange` | `internal/oauth/handler.go:59` | `PublishableKey` (pk_) |
| 51 | `POST` | `/v1/admin/jwks/rotate` | `oauth` | `RotateJWKS` | `internal/oauth/handler.go:67` | `SecretKey` (sk_) or Admin JWT |
| 52 | `POST` | `/v1/tenant/applications` | `oauth` | `CreateApplication` | `internal/oauth/handler.go:70` | `SecretKey` (sk_) or Admin JWT |
| 53 | `POST` | `/v1/client/organizations` | `org` | `CreateOrganization` | `internal/org/handler.go:51` | `PublishableKey` + `BearerAuth` |
| 54 | `GET` | `/v1/client/organizations` | `org` | `ListUserOrganizations` | `internal/org/handler.go:52` | `PublishableKey` + `BearerAuth` |
| 55 | `GET` | `/v1/client/organizations/:orgId` | `org` | `GetOrganization` | `internal/org/handler.go:53` | `PublishableKey` + `BearerAuth` |
| 56 | `PATCH` | `/v1/client/organizations/:orgId` | `org` | `UpdateOrganization` | `internal/org/handler.go:54` | `PublishableKey` + `BearerAuth` |
| 57 | `DELETE` | `/v1/client/organizations/:orgId` | `org` | `DeleteOrganization` | `internal/org/handler.go:55` | `PublishableKey` + `BearerAuth` |
| 58 | `GET` | `/v1/client/organizations/:orgId/members` | `org` | `ListMembers` | `internal/org/handler.go:57` | `PublishableKey` + `BearerAuth` |
| 59 | `POST` | `/v1/client/organizations/:orgId/members` | `org` | `AddMember` | `internal/org/handler.go:58` | `PublishableKey` + `BearerAuth` |
| 60 | `PATCH` | `/v1/client/organizations/:orgId/members/:userId` | `org` | `UpdateMemberRole` | `internal/org/handler.go:59` | `PublishableKey` + `BearerAuth` |
| 61 | `DELETE` | `/v1/client/organizations/:orgId/members/:userId` | `org` | `RemoveMember` | `internal/org/handler.go:60` | `PublishableKey` + `BearerAuth` |
| 62 | `POST` | `/v1/client/organizations/:orgId/invitations` | `org` | `CreateInvitation` | `internal/org/handler.go:62` | `PublishableKey` + `BearerAuth` |
| 63 | `GET` | `/v1/client/organizations/:orgId/invitations` | `org` | `ListPendingInvitations` | `internal/org/handler.go:63` | `PublishableKey` + `BearerAuth` |
| 64 | `DELETE` | `/v1/client/organizations/:orgId/invitations/:invitationId` | `org` | `RevokeInvitation` | `internal/org/handler.go:64` | `PublishableKey` + `BearerAuth` |
| 65 | `POST` | `/v1/client/invitations/accept` | `org` | `AcceptInvitation` | `internal/org/handler.go:65` | `PublishableKey` + `BearerAuth` |
| 66 | `GET` | `/v1/tenant/organizations` | `org` | `TenantListOrganizations` | `internal/org/handler.go:68` | `SecretKey` (sk_) or Admin JWT |
| 67 | `GET` | `/v1/tenant/organizations/:orgId` | `org` | `TenantGetOrganization` | `internal/org/handler.go:69` | `SecretKey` (sk_) or Admin JWT |
| 68 | `POST` | `/v1/tenant/organizations` | `org` | `TenantCreateOrganization` | `internal/org/handler.go:70` | `SecretKey` (sk_) or Admin JWT |
| 69 | `DELETE` | `/v1/tenant/organizations/:orgId` | `org` | `TenantDeleteOrganization` | `internal/org/handler.go:71` | `SecretKey` (sk_) or Admin JWT |
| 70 | `GET` | `/v1/tenant/password-policy` | `policy` | `GetPolicy` | `internal/policy/handler.go:140` | `SecretKey` (sk_) or Admin JWT |
| 71 | `PUT` | `/v1/tenant/password-policy` | `policy` | `UpdatePolicy` | `internal/policy/handler.go:141` | `SecretKey` (sk_) or Admin JWT |
| 72 | `GET` | `/v1/tenant/security-policy` | `policy` | `GetSecurityPolicy` | `internal/policy/handler.go:144` | `SecretKey` (sk_) or Admin JWT |
| 73 | `PUT` | `/v1/tenant/security-policy` | `policy` | `UpdateSecurityPolicy` | `internal/policy/handler.go:145` | `SecretKey` (sk_) or Admin JWT |
| 74 | `GET` | `/v1/tenant/recovery-policy` | `policy` | `GetRecoveryPolicy` | `internal/policy/handler.go:148` | `SecretKey` (sk_) or Admin JWT |
| 75 | `PUT` | `/v1/tenant/recovery-policy` | `policy` | `UpdateRecoveryPolicy` | `internal/policy/handler.go:149` | `SecretKey` (sk_) or Admin JWT |
| 76 | `POST` | `/v1/tenant/roles` | `rbac` | `CreateRole` | `internal/rbac/handler.go:53` | `SecretKey` (sk_) or Admin JWT |
| 77 | `GET` | `/v1/tenant/roles` | `rbac` | `ListRoles` | `internal/rbac/handler.go:54` | `SecretKey` (sk_) or Admin JWT |
| 78 | `PUT` | `/v1/tenant/roles/:role_id/permissions` | `rbac` | `UpdateRolePermissions` | `internal/rbac/handler.go:55` | `SecretKey` (sk_) or Admin JWT |
| 79 | `POST` | `/v1/admin/users/:user_id/roles` | `rbac` | `AssignUserRole` | `internal/rbac/handler.go:61` | `SecretKey` (sk_) or Admin JWT |
| 80 | `DELETE` | `/v1/admin/users/:user_id/roles/:role_slug` | `rbac` | `RevokeUserRole` | `internal/rbac/handler.go:62` | `SecretKey` (sk_) or Admin JWT |
| 81 | `GET` | `/v1/client/user/permissions` | `rbac` | `GetUserPermissions` | `internal/rbac/handler.go:71` | `PublishableKey` + `BearerAuth` |
| 82 | `POST` | `/v1/saml/acs` | `saml` | `ProcessACS` | `internal/saml/handler.go:55` | None (Protocol Assertion) |
| 83 | `GET` | `/v1/saml/metadata/:orgId` | `saml` | `GetSPMetadata` | `internal/saml/handler.go:56` | None (Public XML) |
| 84 | `POST` | `/v1/client/auth/domain-lookup` | `saml` | `LookupDomainSSO` | `internal/saml/handler.go:59` | `PublishableKey` (pk_) |
| 85 | `POST` | `/v1/client/organizations/:orgId/saml` | `saml` | `CreateSAMLConnection` | `internal/saml/handler.go:61` | `PublishableKey` + `BearerAuth` |
| 86 | `GET` | `/v1/client/organizations/:orgId/saml` | `saml` | `GetSAMLConnection` | `internal/saml/handler.go:62` | `PublishableKey` + `BearerAuth` |
| 87 | `PATCH` | `/v1/client/organizations/:orgId/saml` | `saml` | `UpdateSAMLConnection` | `internal/saml/handler.go:63` | `PublishableKey` + `BearerAuth` |
| 88 | `DELETE` | `/v1/client/organizations/:orgId/saml` | `saml` | `DeleteSAMLConnection` | `internal/saml/handler.go:64` | `PublishableKey` + `BearerAuth` |
| 89 | `POST` | `/v1/tenant/organizations/:orgId/saml` | `saml` | `CreateSAMLConnection` | `internal/saml/handler.go:68` | `SecretKey` (sk_) or Admin JWT |
| 90 | `GET` | `/v1/tenant/organizations/:orgId/saml` | `saml` | `GetSAMLConnection` | `internal/saml/handler.go:69` | `SecretKey` (sk_) or Admin JWT |
| 91 | `PATCH` | `/v1/tenant/organizations/:orgId/saml` | `saml` | `UpdateSAMLConnection` | `internal/saml/handler.go:70` | `SecretKey` (sk_) or Admin JWT |
| 92 | `DELETE` | `/v1/tenant/organizations/:orgId/saml` | `saml` | `DeleteSAMLConnection` | `internal/saml/handler.go:71` | `SecretKey` (sk_) or Admin JWT |
| 93 | `GET` | `/v1/client/sessions` | `session` | `ListSessions` | `internal/session/handler.go:57` | `PublishableKey` (pk_) |
| 94 | `POST` | `/v1/client/sessions/revoke` | `session` | `RevokeSession` | `internal/session/handler.go:58` | `PublishableKey` (pk_) |
| 95 | `POST` | `/v1/client/sessions/revoke-others` | `session` | `RevokeOtherSessions` | `internal/session/handler.go:59` | `PublishableKey` (pk_) |
| 96 | `POST` | `/v1/client/sessions/revoke-all` | `session` | `RevokeAllSessions` | `internal/session/handler.go:60` | `PublishableKey` (pk_) |
| 97 | `POST` | `/v1/client/auth/refresh` | `session` | `RefreshTokens` | `internal/session/handler.go:62` | `PublishableKey` (pk_) |
| 98 | `GET` | `/v1/admin/users/:user_id/sessions` | `session` | `AdminListUserSessions` | `internal/session/handler.go:65` | `SecretKey` (sk_) or Admin JWT |
| 99 | `POST` | `/v1/admin/users/:user_id/sessions/revoke-all` | `session` | `AdminRevokeAllUserSessions` | `internal/session/handler.go:66` | `SecretKey` (sk_) or Admin JWT |
| 100 | `GET` | `/v1/client/auth/social/:provider/authorize` | `social` | `Authorize` | `internal/social/handler.go:49` | `PublishableKey` (pk_) |
| 101 | `GET` | `/v1/client/auth/social/:provider/callback` | `social` | `Callback` | `internal/social/handler.go:50` | `PublishableKey` (pk_) |
| 102 | `GET` | `/v1/tenant/social-providers` | `social` | `ListProviders` | `internal/social/handler.go:56` | `SecretKey` (sk_) or Admin JWT |
| 103 | `GET` | `/v1/tenant/social-providers/:provider` | `social` | `GetProvider` | `internal/social/handler.go:57` | `SecretKey` (sk_) or Admin JWT |
| 104 | `PUT` | `/v1/tenant/social-providers/:provider` | `social` | `ConfigureProvider` | `internal/social/handler.go:58` | `SecretKey` (sk_) or Admin JWT |
| 105 | `DELETE` | `/v1/tenant/social-providers/:provider` | `social` | `DeleteProvider` | `internal/social/handler.go:59` | `SecretKey` (sk_) or Admin JWT |
| 106 | `GET` | `/v1/client/user/email/verify` | `user` | `VerifyEmailChange` | `internal/user/handler.go:110` | `PublishableKey` (pk_) |
| 107 | `GET` | `/v1/client/user/recovery-email/verify` | `user` | `VerifyRecoveryEmail` | `internal/user/handler.go:111` | `PublishableKey` (pk_) |
| 108 | `GET` | `/v1/client/user/profile` | `user` | `GetProfile` | `internal/user/handler.go:122` | `PublishableKey` + `BearerAuth` |
| 109 | `PATCH` | `/v1/client/user/profile` | `user` | `UpdateProfile` | `internal/user/handler.go:123` | `PublishableKey` + `BearerAuth` |
| 110 | `POST` | `/v1/client/user/password` | `user` | `ChangePassword` | `internal/user/handler.go:124` | `PublishableKey` + `BearerAuth` |
| 111 | `POST` | `/v1/client/user/email` | `user` | `RequestEmailChange` | `internal/user/handler.go:125` | `PublishableKey` + `BearerAuth` |
| 112 | `GET` | `/v1/client/user/recovery-email` | `user` | `GetRecoveryEmail` | `internal/user/handler.go:126` | `PublishableKey` + `BearerAuth` |
| 113 | `POST` | `/v1/client/user/recovery-email` | `user` | `SetRecoveryEmail` | `internal/user/handler.go:127` | `PublishableKey` + `BearerAuth` |
| 114 | `DELETE` | `/v1/client/user/recovery-email` | `user` | `DeleteRecoveryEmail` | `internal/user/handler.go:128` | `PublishableKey` + `BearerAuth` |
| 115 | `GET` | `/v1/client/user/social-accounts` | `user` | `ListSocialAccounts` | `internal/user/handler.go:129` | `PublishableKey` + `BearerAuth` |
| 116 | `DELETE` | `/v1/client/user/social-accounts/:provider` | `user` | `UnlinkSocialAccount` | `internal/user/handler.go:130` | `PublishableKey` + `BearerAuth` |
| 117 | `DELETE` | `/v1/client/user/account` | `user` | `DeleteAccount` | `internal/user/handler.go:131` | `PublishableKey` + `BearerAuth` |
| 118 | `POST` | `/v1/admin/webhooks/endpoints` | `webhook` | `CreateEndpoint` | `internal/webhook/handler.go:35` | `SecretKey` (sk_) or Admin JWT |
| 119 | `GET` | `/v1/admin/webhooks/endpoints` | `webhook` | `ListEndpoints` | `internal/webhook/handler.go:36` | `SecretKey` (sk_) or Admin JWT |
| 120 | `GET` | `/v1/admin/webhooks/endpoints/:id` | `webhook` | `GetEndpoint` | `internal/webhook/handler.go:37` | `SecretKey` (sk_) or Admin JWT |
| 121 | `PUT` | `/v1/admin/webhooks/endpoints/:id` | `webhook` | `UpdateEndpoint` | `internal/webhook/handler.go:38` | `SecretKey` (sk_) or Admin JWT |
| 122 | `DELETE` | `/v1/admin/webhooks/endpoints/:id` | `webhook` | `DeleteEndpoint` | `internal/webhook/handler.go:39` | `SecretKey` (sk_) or Admin JWT |
| 123 | `POST` | `/v1/admin/webhooks/endpoints/:id/ping` | `webhook` | `SendTestPing` | `internal/webhook/handler.go:40` | `SecretKey` (sk_) or Admin JWT |
| 124 | `POST` | `/v1/admin/webhooks/endpoints/:id/rotate-secret` | `webhook` | `RotateSecret` | `internal/webhook/handler.go:41` | `SecretKey` (sk_) or Admin JWT |
| 125 | `GET` | `/v1/admin/webhooks/deliveries` | `webhook` | `ListDeliveries` | `internal/webhook/handler.go:44` | `SecretKey` (sk_) or Admin JWT |
| 126 | `POST` | `/v1/admin/webhooks/deliveries/:id/redeliver` | `webhook` | `Redeliver` | `internal/webhook/handler.go:45` | `SecretKey` (sk_) or Admin JWT |

---

## Markdown Documentation Cross-Check & Mismatches

| Markdown Doc | Route in Code? | Notes / Status |
|--------------|----------------|----------------|
| `docs/endpoints/cross-domain-resume.md` | ❌ No | **FLAGGED FOR HUMAN REVIEW**: Document exists for `/v1/client/auth/cross-domain/resume`, but no corresponding route is registered in `apps/auth-engine`. |
| `docs/endpoints/lockout-engine.md` | ℹ️ Pentest Doc | Describes security lockout logic evaluated inside `POST /v1/client/auth/login`. |
| `docs/endpoints/system-health.md` | ✅ Yes | Maps to `/v1/health`, `/v1/ready`, `/healthz`, `/readyz`. |

---

## Subagent Assignment Chunks (Phase 1 Target)

Each subagent will extract its assigned routes into `docs/openapi-fragments/<chunk-name>.yaml`:

- **`chunk-auth`**: Routes 1-11 (`/v1/health`, `/v1/ready`, `/healthz`, `/readyz`, signup, login, verify-email, resend-verification, magic-link).
- **`chunk-mfa-webauthn`**: Routes 12-27 (TOTP, SMS, Recovery Codes, WebAuthn passkeys).
- **`chunk-guardian-recovery`**: Routes 28-38 (Guardian invitation roster, Account recovery flow).
- **`chunk-org`**: Routes 53-69 (Client and Tenant Organization CRUD, member management, invitation flows).
- **`chunk-oauth-social`**: Routes 46-52, 100-105 (OIDC Discovery, JWKS, UserInfo, Authorize, Token, JWKS Rotation, Apps, Social Providers).
- **`chunk-saml`**: Routes 82-92 (SAML ACS, metadata, domain lookup, client & tenant SAML connection management).
- **`chunk-user-session`**: Routes 93-99, 106-117 (User profile, email changes, password updates, social account unlinking, session management & revocation).
- **`chunk-admin-system`**: Routes 39-45, 70-81, 118-126 (API keys, Impersonation & policy, Password/Security/Recovery Policies, RBAC roles & permissions, Webhook endpoints & delivery logs).

Total inventoried endpoints in Go code: **126 route registrations across 13 handler modules**.
