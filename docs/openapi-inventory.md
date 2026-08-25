# Authn Engine — Complete Route Inventory (OpenAPI 3.0 Baseline)

This document contains the single authoritative list of all registered HTTP routes in `apps/auth-engine`. Every subagent in Phase 1 extracts OpenAPI 3.0 YAML fragments according to these inventoried endpoints.

---

## Complete Route Checklist

| # | HTTP Method | Path | Internal Package | Handler Function | Code Location | Auth Requirements |
|---|-------------|------|------------------|------------------|---------------|-------------------|
| 1 | `GET` | `/v1/health` | `cmd/server` | `HealthCheckHandler` | `cmd/server/routes.go:32` | None (Public) |
| 2 | `GET` | `/v1/ready` | `cmd/server` | `ReadinessCheckHandler` | `cmd/server/routes.go:33` | None (Public) |
| 3 | `GET` | `/healthz` | `cmd/server` | `HealthCheckHandler` | `cmd/server/routes.go:34` | None (Public) |
| 4 | `GET` | `/readyz` | `cmd/server` | `ReadinessCheckHandler` | `cmd/server/routes.go:35` | None (Public) |
| 5 | `POST` | `/v1/client/auth/signup` | `auth` | `SignUp` | `internal/auth/handler.go:180` | `PublishableKey` (pk_) |
| 6 | `POST` | `/v1/client/auth/login` | `auth` | `Login` | `internal/auth/handler.go:181` | `PublishableKey` (pk_) |
| 7 | `GET` | `/v1/client/auth/verify-email` | `auth` | `VerifyEmail` | `internal/auth/handler.go:182` | `PublishableKey` (pk_) |
| 8 | `POST` | `/v1/client/auth/resend-verification` | `auth` | `ResendVerification` | `internal/auth/handler.go:183` | `PublishableKey` (pk_) |
| 9 | `POST` | `/v1/client/auth/magic-link` | `auth` | `SendMagicLink` | `internal/auth/handler.go:191` | `PublishableKey` (pk_) |
| 10 | `POST` | `/v1/client/auth/magic-link/verify` | `auth` | `VerifyMagicLink` | `internal/auth/handler.go:192` | `PublishableKey` (pk_) |
| 11 | `POST` | `/v1/client/auth/2fa/totp/enroll` | `auth` | `EnrollTOTP` | `internal/auth/handler.go:196` | `PublishableKey` + `BearerAuth` (Session) |
| 12 | `POST` | `/v1/client/auth/2fa/totp/confirm` | `auth` | `ConfirmTOTP` | `internal/auth/handler.go:197` | `PublishableKey` + `BearerAuth` (Session) |
| 13 | `POST` | `/v1/client/auth/2fa/totp/disable` | `auth` | `DisableTOTP` | `internal/auth/handler.go:198` | `PublishableKey` + `BearerAuth` (Session) |
| 14 | `POST` | `/v1/client/auth/2fa/totp/verify` | `auth` | `VerifyTOTP` | `internal/auth/handler.go:199` | `PublishableKey` (pk_) |
| 15 | `POST` | `/v1/client/auth/2fa/verify` | `auth` | `VerifyTOTP` | `internal/auth/handler.go:202` | `PublishableKey` (pk_) |
| 16 | `POST` | `/v1/client/auth/2fa/sms/enroll` | `auth` | `EnrollSMS` | `internal/auth/handler.go:205` | `PublishableKey` + `BearerAuth` (Session) |
| 17 | `POST` | `/v1/client/auth/2fa/sms/challenge` | `auth` | `SendSMSChallenge` | `internal/auth/handler.go:325` | `PublishableKey` (pk_) |
| 18 | `POST` | `/v1/client/auth/2fa/sms/confirm` | `auth` | `ConfirmSMS` | `internal/auth/handler.go:206` | `PublishableKey` + `BearerAuth` (Session) |
| 19 | `DELETE` | `/v1/client/auth/2fa/sms/disable` | `auth` | `DisableSMS` | `internal/auth/handler.go:207` | `PublishableKey` + `BearerAuth` (Session) |
| 20 | `POST` | `/v1/client/auth/2fa/recovery-codes/regenerate` | `auth` | `RegenerateRecoveryCodes` | `internal/auth/handler.go:210` | `PublishableKey` + `BearerAuth` (Session) |
| 21 | `GET` | `/v1/client/auth/2fa/recovery-codes/status` | `auth` | `GetRecoveryCodesStatus` | `internal/auth/handler.go:211` | `PublishableKey` + `BearerAuth` (Session) |
| 22 | `GET` | `/v1/client/auth/2fa/methods` | `auth` | `GetTwoFactorMethods` | `internal/auth/handler.go:314` | `PublishableKey` + `BearerAuth` (Session) |
| 23 | `POST` | `/v1/client/auth/2fa/webauthn/register/begin` | `auth` | `BeginWebAuthnRegistration` | `internal/auth/handler.go:214` | `PublishableKey` + `BearerAuth` (Session) |
| 24 | `POST` | `/v1/client/auth/2fa/webauthn/register/finish` | `auth` | `FinishWebAuthnRegistration` | `internal/auth/handler.go:215` | `PublishableKey` + `BearerAuth` (Session) |
| 25 | `POST` | `/v1/client/auth/2fa/webauthn/login/begin` | `auth` | `BeginWebAuthnLogin` | `internal/auth/handler.go:216` | `PublishableKey` (pk_) |
| 26 | `POST` | `/v1/client/auth/2fa/webauthn/login/finish` | `auth` | `FinishWebAuthnLogin` | `internal/auth/handler.go:217` | `PublishableKey` (pk_) |
| 27 | `GET` | `/v1/client/auth/2fa/webauthn/credentials` | `auth` | `ListWebAuthnPasskeys` | `internal/auth/handler.go:218` | `PublishableKey` + `BearerAuth` (Session) |
| 28 | `DELETE` | `/v1/client/auth/2fa/webauthn/credentials/:id` | `auth` | `DeleteWebAuthnPasskey` | `internal/auth/handler.go:219` | `PublishableKey` + `BearerAuth` (Session) |
| 29 | `POST` | `/v1/client/account/guardians/invite` | `auth` | `InviteGuardians` | `internal/auth/handler.go:223` | `PublishableKey` + `BearerAuth` (Session) |
| 30 | `POST` | `/v1/client/account/guardians/accept` | `auth` | `AcceptGuardianInvite` | `internal/auth/handler.go:224` | `PublishableKey` (pk_) |
| 31 | `GET` | `/v1/client/account/guardians` | `auth` | `ListGuardians` | `internal/auth/handler.go:225` | `PublishableKey` + `BearerAuth` (Session) |
| 32 | `DELETE` | `/v1/client/account/guardians/:id` | `auth` | `RevokeGuardian` | `internal/auth/handler.go:226` | `PublishableKey` + `BearerAuth` (Session) |
| 33 | `POST` | `/v1/client/auth/recovery/initiate` | `auth` | `InitiateRecovery` | `internal/auth/handler.go:230` | `PublishableKey` (pk_) |
| 34 | `POST` | `/v1/client/auth/recovery/proof/guardian` | `auth` | `SubmitGuardianProof` | `internal/auth/handler.go:231` | `PublishableKey` (pk_) |
| 35 | `POST` | `/v1/client/auth/recovery/proof/old-password` | `auth` | `SubmitOldPasswordProof` | `internal/auth/handler.go:232` | `PublishableKey` (pk_) |
| 36 | `POST` | `/v1/client/auth/recovery/proof/security-questions` | `auth` | `SubmitSecurityQuestionsProof` | `internal/auth/handler.go:233` | `PublishableKey` (pk_) |
| 37 | `POST` | `/v1/client/auth/recovery/claim` | `auth` | `ClaimAccount` | `internal/auth/handler.go:234` | `PublishableKey` (pk_) |
| 38 | `POST` | `/v1/client/auth/recovery/cancel` | `auth` | `CancelRecoveryAuth` | `internal/auth/handler.go:235` | `PublishableKey` (pk_) |
| 39 | `POST` | `/v1/client/auth/recovery/cancel/token` | `auth` | `CancelRecoveryToken` | `internal/auth/handler.go:236` | `PublishableKey` (pk_) |
| 40 | `POST` | `/v1/admin/keys` | `apikey` | `CreateKey` | `internal/apikey/handler.go:113` | `SecretKey` (sk_) or Admin JWT |
| 41 | `GET` | `/v1/admin/keys` | `apikey` | `ListKeys` | `internal/apikey/handler.go:114` | `SecretKey` (sk_) or Admin JWT |
| 42 | `POST` | `/v1/admin/keys/:id/revoke` | `apikey` | `RevokeKey` | `internal/apikey/handler.go:115` | `SecretKey` (sk_) or Admin JWT |
| 43 | `POST` | `/v1/admin/users/:user_id/impersonate` | `impersonation` | `InitiateImpersonation` | `internal/impersonation/handler.go:135` | `SecretKey` (sk_) or Admin JWT |
| 44 | `GET` | `/v1/tenant/impersonation-policy` | `impersonation` | `GetImpersonationPolicy` | `internal/impersonation/handler.go:141` | `SecretKey` (sk_) or Admin JWT |
| 45 | `PUT` | `/v1/tenant/impersonation-policy` | `impersonation` | `UpdateImpersonationPolicy` | `internal/impersonation/handler.go:142` | `SecretKey` (sk_) or Admin JWT |
| 46 | `POST` | `/v1/client/auth/impersonate/exit` | `impersonation` | `ExitImpersonation` | `internal/impersonation/handler.go:151` | `PublishableKey` + `BearerAuth` |
| 47 | `GET` | `/.well-known/openid-configuration` | `oauth` | `GetOIDCDiscovery` | `internal/oauth/handler.go:76` | None (Public) |
| 48 | `GET` | `/v1/oauth/jwks` | `oauth` | `GetJWKS` | `internal/oauth/handler.go:79` | None (Public) |
| 49 | `GET` | `/v1/oauth/userinfo` | `oauth` | `GetUserInfo` | `internal/oauth/handler.go:80` | `BearerAuth` |
| 50 | `GET` | `/v1/oauth/authorize` | `oauth` | `Authorize` | `internal/oauth/handler.go:82` | `PublishableKey` (pk_) |
| 51 | `POST` | `/v1/oauth/token` | `oauth` | `TokenExchange` | `internal/oauth/handler.go:83` | `PublishableKey` (pk_) |
| 52 | `POST` | `/v1/admin/jwks/rotate` | `oauth` | `RotateJWKS` | `internal/oauth/handler.go:99` | `SecretKey` (sk_) or Admin JWT |
| 53 | `POST` | `/v1/tenant/applications` | `oauth` | `CreateApplication` | `internal/oauth/handler.go:104` | `SecretKey` (sk_) or Admin JWT |
| 54 | `POST` | `/v1/client/organizations` | `org` | `CreateOrganization` | `internal/org/handler.go:51` | `PublishableKey` + `BearerAuth` |
| 55 | `GET` | `/v1/client/organizations` | `org` | `ListUserOrganizations` | `internal/org/handler.go:52` | `PublishableKey` + `BearerAuth` |
| 56 | `GET` | `/v1/client/organizations/:orgId` | `org` | `GetOrganization` | `internal/org/handler.go:53` | `PublishableKey` + `BearerAuth` |
| 57 | `PATCH` | `/v1/client/organizations/:orgId` | `org` | `UpdateOrganization` | `internal/org/handler.go:54` | `PublishableKey` + `BearerAuth` |
| 58 | `DELETE` | `/v1/client/organizations/:orgId` | `org` | `DeleteOrganization` | `internal/org/handler.go:55` | `PublishableKey` + `BearerAuth` |
| 59 | `GET` | `/v1/client/organizations/:orgId/members` | `org` | `ListMembers` | `internal/org/handler.go:57` | `PublishableKey` + `BearerAuth` |
| 60 | `POST` | `/v1/client/organizations/:orgId/members` | `org` | `AddMember` | `internal/org/handler.go:58` | `PublishableKey` + `BearerAuth` |
| 61 | `PATCH` | `/v1/client/organizations/:orgId/members/:userId` | `org` | `UpdateMemberRole` | `internal/org/handler.go:59` | `PublishableKey` + `BearerAuth` |
| 62 | `DELETE` | `/v1/client/organizations/:orgId/members/:userId` | `org` | `RemoveMember` | `internal/org/handler.go:60` | `PublishableKey` + `BearerAuth` |
| 63 | `POST` | `/v1/client/organizations/:orgId/invitations` | `org` | `CreateInvitation` | `internal/org/handler.go:62` | `PublishableKey` + `BearerAuth` |
| 64 | `GET` | `/v1/client/organizations/:orgId/invitations` | `org` | `ListPendingInvitations` | `internal/org/handler.go:63` | `PublishableKey` + `BearerAuth` |
| 65 | `DELETE` | `/v1/client/organizations/:orgId/invitations/:invitationId` | `org` | `RevokeInvitation` | `internal/org/handler.go:64` | `PublishableKey` + `BearerAuth` |
| 66 | `POST` | `/v1/client/invitations/accept` | `org` | `AcceptInvitation` | `internal/org/handler.go:65` | `PublishableKey` + `BearerAuth` |
| 67 | `GET` | `/v1/tenant/organizations` | `org` | `TenantListOrganizations` | `internal/org/handler.go:68` | `SecretKey` (sk_) or Admin JWT |
| 68 | `GET` | `/v1/tenant/organizations/:orgId` | `org` | `TenantGetOrganization` | `internal/org/handler.go:69` | `SecretKey` (sk_) or Admin JWT |
| 69 | `POST` | `/v1/tenant/organizations` | `org` | `TenantCreateOrganization` | `internal/org/handler.go:70` | `SecretKey` (sk_) or Admin JWT |
| 70 | `DELETE` | `/v1/tenant/organizations/:orgId` | `org` | `TenantDeleteOrganization` | `internal/org/handler.go:71` | `SecretKey` (sk_) or Admin JWT |
| 71 | `GET` | `/v1/tenant/password-policy` | `policy` | `GetPolicy` | `internal/policy/handler.go:444` | `SecretKey` (sk_) or Admin JWT |
| 72 | `PUT` | `/v1/tenant/password-policy` | `policy` | `UpdatePolicy` | `internal/policy/handler.go:445` | `SecretKey` (sk_) or Admin JWT |
| 73 | `GET` | `/v1/tenant/security-policy` | `policy` | `GetSecurityPolicy` | `internal/policy/handler.go:448` | `SecretKey` (sk_) or Admin JWT |
| 74 | `PUT` | `/v1/tenant/security-policy` | `policy` | `UpdateSecurityPolicy` | `internal/policy/handler.go:449` | `SecretKey` (sk_) or Admin JWT |
| 75 | `GET` | `/v1/tenant/recovery-policy` | `policy` | `GetRecoveryPolicy` | `internal/policy/handler.go:452` | `SecretKey` (sk_) or Admin JWT |
| 76 | `PUT` | `/v1/tenant/recovery-policy` | `policy` | `UpdateRecoveryPolicy` | `internal/policy/handler.go:453` | `SecretKey` (sk_) or Admin JWT |
| 77 | `POST` | `/v1/tenant/roles` | `rbac` | `CreateRole` | `internal/rbac/handler.go:54` | `SecretKey` (sk_) or Admin JWT |
| 78 | `GET` | `/v1/tenant/roles` | `rbac` | `ListRoles` | `internal/rbac/handler.go:55` | `SecretKey` (sk_) or Admin JWT |
| 79 | `PUT` | `/v1/tenant/roles/:role_id/permissions` | `rbac` | `UpdateRolePermissions` | `internal/rbac/handler.go:56` | `SecretKey` (sk_) or Admin JWT |
| 80 | `POST` | `/v1/admin/users/:user_id/roles` | `rbac` | `AssignUserRole` | `internal/rbac/handler.go:62` | `SecretKey` (sk_) or Admin JWT |
| 81 | `DELETE` | `/v1/admin/users/:user_id/roles/:role_slug` | `rbac` | `RevokeUserRole` | `internal/rbac/handler.go:63` | `SecretKey` (sk_) or Admin JWT |
| 82 | `GET` | `/v1/client/user/permissions` | `rbac` | `GetUserPermissions` | `internal/rbac/handler.go:72` | `PublishableKey` + `BearerAuth` |
| 83 | `POST` | `/v1/saml/acs` | `saml` | `ProcessACS` | `internal/saml/handler.go:76` | None (Protocol Assertion; 302 to a registered RelayState, else 200) |
| 84 | `GET` | `/v1/saml/metadata/:orgId` | `saml` | `GetSPMetadata` | `internal/saml/handler.go:77` | None (Public XML) |
| 85 | `POST` | `/v1/client/auth/domain-lookup` | `saml` | `LookupDomainSSO` | `internal/saml/handler.go:80` | `PublishableKey` (pk_) |
| 86 | `POST` | `/v1/client/organizations/:orgId/saml` | `saml` | `CreateSAMLConnection` | `internal/saml/handler.go:82` | `PublishableKey` + `BearerAuth` — **live key** when the connection is in `live` or the request moves it there |
| 87 | `GET` | `/v1/client/organizations/:orgId/saml` | `saml` | `GetSAMLConnection` | `internal/saml/handler.go:83` | `PublishableKey` + `BearerAuth` |
| 88 | `PATCH` | `/v1/client/organizations/:orgId/saml` | `saml` | `UpdateSAMLConnection` | `internal/saml/handler.go:84` | `PublishableKey` + `BearerAuth` — **live key** when the connection is in `live` or the request moves it there |
| 89 | `DELETE` | `/v1/client/organizations/:orgId/saml` | `saml` | `DeleteSAMLConnection` | `internal/saml/handler.go:85` | `PublishableKey` + `BearerAuth` — **live key** when the connection is in `live` or the request moves it there |
| 90 | `POST` | `/v1/tenant/organizations/:orgId/saml` | `saml` | `CreateSAMLConnection` | `internal/saml/handler.go:89` | `SecretKey` (sk_) or Admin JWT — **live key** when the connection is in `live` or the request moves it there |
| 91 | `GET` | `/v1/tenant/organizations/:orgId/saml` | `saml` | `GetSAMLConnection` | `internal/saml/handler.go:90` | `SecretKey` (sk_) or Admin JWT |
| 92 | `PATCH` | `/v1/tenant/organizations/:orgId/saml` | `saml` | `UpdateSAMLConnection` | `internal/saml/handler.go:91` | `SecretKey` (sk_) or Admin JWT — **live key** when the connection is in `live` or the request moves it there |
| 93 | `DELETE` | `/v1/tenant/organizations/:orgId/saml` | `saml` | `DeleteSAMLConnection` | `internal/saml/handler.go:92` | `SecretKey` (sk_) or Admin JWT — **live key** when the connection is in `live` or the request moves it there |
| 94 | `GET` | `/v1/client/sessions` | `session` | `ListSessions` | `internal/session/handler.go:76` | `PublishableKey` (pk_) |
| 95 | `POST` | `/v1/client/sessions/revoke` | `session` | `RevokeSession` | `internal/session/handler.go:77` | `PublishableKey` (pk_) |
| 96 | `POST` | `/v1/client/sessions/revoke-others` | `session` | `RevokeOtherSessions` | `internal/session/handler.go:78` | `PublishableKey` (pk_) |
| 97 | `POST` | `/v1/client/sessions/revoke-all` | `session` | `RevokeAllSessions` | `internal/session/handler.go:79` | `PublishableKey` (pk_) |
| 98 | `POST` | `/v1/client/auth/refresh` | `session` | `RefreshTokens` | `internal/session/handler.go:81` | `PublishableKey` (pk_) |
| 99 | `GET` | `/v1/admin/users/:user_id/sessions` | `session` | `AdminListUserSessions` | `internal/session/handler.go:93` | `SecretKey` (sk_) or Admin JWT |
| 100 | `POST` | `/v1/admin/users/:user_id/sessions/revoke-all` | `session` | `AdminRevokeAllUserSessions` | `internal/session/handler.go:94` | `SecretKey` (sk_) or Admin JWT |
| 101 | `GET` | `/v1/client/auth/social/:provider/authorize` | `social` | `Authorize` | `internal/social/handler.go:71` | `PublishableKey` (pk_) |
| 102 | `GET` | `/v1/client/auth/social/:provider/callback` | `social` | `Callback` | `internal/social/handler.go:72` | `PublishableKey` (pk_) |
| 103 | `GET` | `/v1/tenant/social-providers` | `social` | `ListProviders` | `internal/social/handler.go:78` | `SecretKey` (sk_) or Admin JWT |
| 104 | `GET` | `/v1/tenant/social-providers/:provider` | `social` | `GetProvider` | `internal/social/handler.go:79` | `SecretKey` (sk_) or Admin JWT |
| 105 | `PUT` | `/v1/tenant/social-providers/:provider` | `social` | `ConfigureProvider` | `internal/social/handler.go:80` | `SecretKey` (sk_) or Admin JWT |
| 106 | `DELETE` | `/v1/tenant/social-providers/:provider` | `social` | `DeleteProvider` | `internal/social/handler.go:81` | `SecretKey` (sk_) or Admin JWT |
| 107 | `GET` | `/v1/client/user/email/verify` | `user` | `VerifyEmailChange` | `internal/user/handler.go:110` | `PublishableKey` (pk_) |
| 108 | `GET` | `/v1/client/user/recovery-email/verify` | `user` | `VerifyRecoveryEmail` | `internal/user/handler.go:111` | `PublishableKey` (pk_) |
| 109 | `GET` | `/v1/client/user/profile` | `user` | `GetProfile` | `internal/user/handler.go:122` | `PublishableKey` + `BearerAuth` |
| 110 | `PATCH` | `/v1/client/user/profile` | `user` | `UpdateProfile` | `internal/user/handler.go:123` | `PublishableKey` + `BearerAuth` |
| 111 | `POST` | `/v1/client/user/password` | `user` | `ChangePassword` | `internal/user/handler.go:124` | `PublishableKey` + `BearerAuth` |
| 112 | `POST` | `/v1/client/user/email` | `user` | `RequestEmailChange` | `internal/user/handler.go:125` | `PublishableKey` + `BearerAuth` |
| 113 | `GET` | `/v1/client/user/recovery-email` | `user` | `GetRecoveryEmail` | `internal/user/handler.go:126` | `PublishableKey` + `BearerAuth` |
| 114 | `POST` | `/v1/client/user/recovery-email` | `user` | `SetRecoveryEmail` | `internal/user/handler.go:127` | `PublishableKey` + `BearerAuth` |
| 115 | `DELETE` | `/v1/client/user/recovery-email` | `user` | `DeleteRecoveryEmail` | `internal/user/handler.go:128` | `PublishableKey` + `BearerAuth` |
| 116 | `GET` | `/v1/client/user/social-accounts` | `user` | `ListSocialAccounts` | `internal/user/handler.go:129` | `PublishableKey` + `BearerAuth` |
| 117 | `DELETE` | `/v1/client/user/social-accounts/:provider` | `user` | `UnlinkSocialAccount` | `internal/user/handler.go:130` | `PublishableKey` + `BearerAuth` |
| 118 | `DELETE` | `/v1/client/user/account` | `user` | `DeleteAccount` | `internal/user/handler.go:131` | `PublishableKey` + `BearerAuth` |
| 119 | `POST` | `/v1/admin/webhooks/endpoints` | `webhook` | `CreateEndpoint` | `internal/webhook/handler.go:45` | `SecretKey` (sk_) or Admin JWT — **live key** (`sk_live_`) required |
| 120 | `GET` | `/v1/admin/webhooks/endpoints` | `webhook` | `ListEndpoints` | `internal/webhook/handler.go:46` | `SecretKey` (sk_) or Admin JWT |
| 121 | `GET` | `/v1/admin/webhooks/endpoints/:id` | `webhook` | `GetEndpoint` | `internal/webhook/handler.go:47` | `SecretKey` (sk_) or Admin JWT |
| 122 | `PUT` | `/v1/admin/webhooks/endpoints/:id` | `webhook` | `UpdateEndpoint` | `internal/webhook/handler.go:48` | `SecretKey` (sk_) or Admin JWT — **live key** (`sk_live_`) required |
| 123 | `DELETE` | `/v1/admin/webhooks/endpoints/:id` | `webhook` | `DeleteEndpoint` | `internal/webhook/handler.go:49` | `SecretKey` (sk_) or Admin JWT — **live key** (`sk_live_`) required |
| 124 | `POST` | `/v1/admin/webhooks/endpoints/:id/ping` | `webhook` | `SendTestPing` | `internal/webhook/handler.go:50` | `SecretKey` (sk_) or Admin JWT — **live key** (`sk_live_`) required |
| 125 | `POST` | `/v1/admin/webhooks/endpoints/:id/rotate-secret` | `webhook` | `RotateSecret` | `internal/webhook/handler.go:51` | `SecretKey` (sk_) or Admin JWT — **live key** (`sk_live_`) required |
| 126 | `GET` | `/v1/admin/webhooks/deliveries` | `webhook` | `ListDeliveries` | `internal/webhook/handler.go:54` | `SecretKey` (sk_) or Admin JWT |
| 127 | `POST` | `/v1/admin/webhooks/deliveries/:id/redeliver` | `webhook` | `Redeliver` | `internal/webhook/handler.go:55` | `SecretKey` (sk_) or Admin JWT — **live key** (`sk_live_`) required |
| 128 | `GET` | `/v1/client/app-config` | `appconfig` | `GetAppConfig` | `internal/appconfig/handler.go:148` | `PublishableKey` (pk_) |
| 129 | `GET` | `/v1/tenant/branding` | `appconfig` | `GetBranding` | `internal/appconfig/handler.go:150` | `SecretKey` (sk_) or Admin JWT |
| 130 | `PUT` | `/v1/tenant/branding` | `appconfig` | `UpdateBranding` | `internal/appconfig/handler.go:151` | `SecretKey` (sk_) or Admin JWT |
| 131 | `GET` | `/v1/tenant/session-policy` | `policy` | `GetSessionPolicy` | `internal/policy/handler.go:456` | `SecretKey` (sk_) or Admin JWT |
| 132 | `PUT` | `/v1/tenant/session-policy` | `policy` | `UpdateSessionPolicy` | `internal/policy/handler.go:457` | `SecretKey` (sk_) or Admin JWT |
| 133 | `GET` | `/v1/tenant/settings` | `policy` | `GetSettings` | `internal/policy/handler.go:460` | `SecretKey` (sk_) or Admin JWT |
| 134 | `GET` | `/v1/tenant/settings/diff` | `policy` | `GetSettingsDiff` | `internal/policy/handler.go:461` | `SecretKey` (sk_) or Admin JWT |
| 135 | `POST` | `/v1/tenant/settings/publish` | `policy` | `PublishSettings` | `internal/policy/handler.go:462` | `SecretKey` (sk_) or Admin JWT (destination environment must match the key) |
| 136 | `GET` | `/v1/tenant/sandbox/messages` | `sandbox` | `ListMessages` | `internal/sandbox/handler.go:102` | `SecretKey` (sk_test_) or Admin JWT (a live credential is `403`) |
| 137 | `DELETE` | `/v1/tenant/sandbox/messages` | `sandbox` | `PurgeMessages` | `internal/sandbox/handler.go:103` | `SecretKey` (sk_test_) or Admin JWT (a live credential is `403`) |
| 138 | `GET` | `/v1/tenant/sandbox/messages/:id` | `sandbox` | `GetMessage` | `internal/sandbox/handler.go:104` | `SecretKey` (sk_test_) or Admin JWT (a live credential is `403`) |
| 139 | `POST` | `/v1/tenant/delivery/verify` | `sandbox` | `VerifyDelivery` | `internal/sandbox/handler.go:107` | Admin JWT only (a secret key is `403`; sends to the signed-in operator's own address) |
| 140 | `GET` | `/v1/admin/audit-logs` | `audit` | `ListAuditLogs` | `internal/audit/handler.go:50` | `SecretKey` (sk_) or Admin JWT |
| 141 | `GET` | `/v1/admin/audit-logs/` | `audit` | `ListAuditLogs` | `internal/audit/handler.go:51` | `SecretKey` (sk_) or Admin JWT |
| 142 | `GET` | `/v1/admin/users` | `useradmin` | `ListUsers` | `internal/useradmin/handler.go:67` | `SecretKey` (sk_) or Admin JWT |
| 143 | `GET` | `/v1/admin/users/` | `useradmin` | `ListUsers` | `internal/useradmin/handler.go:68` | `SecretKey` (sk_) or Admin JWT |
| 144 | `GET` | `/v1/admin/users/:user_id` | `useradmin` | `GetUser` | `internal/useradmin/handler.go:69` | `SecretKey` (sk_) or Admin JWT |
| 145 | `PATCH` | `/v1/admin/users/:user_id` | `useradmin` | `UpdateUser` | `internal/useradmin/handler.go:70` | `SecretKey` (sk_) or Admin JWT |
| 146 | `DELETE` | `/v1/admin/users/:user_id` | `useradmin` | `DeleteUser` | `internal/useradmin/handler.go:71` | `SecretKey` (sk_) or Admin JWT |
| 147 | `POST` | `/v1/admin/users/:user_id/ban` | `useradmin` | `BanUser` | `internal/useradmin/handler.go:73` | `SecretKey` (sk_) or Admin JWT |
| 148 | `POST` | `/v1/admin/users/:user_id/unban` | `useradmin` | `UnbanUser` | `internal/useradmin/handler.go:74` | `SecretKey` (sk_) or Admin JWT |
| 149 | `POST` | `/v1/admin/users/:user_id/suspend` | `useradmin` | `SuspendUser` | `internal/useradmin/handler.go:75` | `SecretKey` (sk_) or Admin JWT |
| 150 | `POST` | `/v1/admin/users/:user_id/unsuspend` | `useradmin` | `UnsuspendUser` | `internal/useradmin/handler.go:76` | `SecretKey` (sk_) or Admin JWT |
| 151 | `POST` | `/v1/admin/users/:user_id/restore` | `useradmin` | `RestoreUser` | `internal/useradmin/handler.go:77` | `SecretKey` (sk_) or Admin JWT |
| 152 | `POST` | `/v1/admin/users/:user_id/logout` | `useradmin` | `ForceLogout` | `internal/useradmin/handler.go:78` | `SecretKey` (sk_) or Admin JWT |
| 153 | `POST` | `/v1/admin/users/:user_id/verify-email` | `useradmin` | `VerifyEmail` | `internal/useradmin/handler.go:79` | `SecretKey` (sk_) or Admin JWT |
| 154 | `POST` | `/v1/platform/tenants` | `platform` | `CreateTenant` | `internal/platform/handler.go:105` | Platform session `BearerAuth` (API keys refused; mounted only when a platform tenant is configured) |
| 155 | `GET` | `/v1/platform/tenants` | `platform` | `ListTenants` | `internal/platform/handler.go:106` | Platform session `BearerAuth` (API keys refused; mounted only when a platform tenant is configured) |

---

## Markdown Documentation Cross-Check & Mismatches

| Markdown Doc | Route in Code? | Notes / Status |
|--------------|----------------|----------------|
| `docs/endpoints/cross-domain-resume.md` | ❌ No | **FLAGGED FOR HUMAN REVIEW**: Document exists for `/v1/client/auth/cross-domain/resume`, but no corresponding route is registered in `apps/auth-engine`. |
| `docs/endpoints/lockout-engine.md` | ℹ️ Pentest Doc | Describes security lockout logic evaluated inside `POST /v1/client/auth/login`. |
| `docs/endpoints/system-health.md` | ✅ Yes | Maps to `/v1/health`, `/v1/ready`, `/healthz`, `/readyz`. |
| `docs/endpoints/client-app-config.md` | ✅ Yes | Maps to routes 127-129. |
| `docs/endpoints/tenant-settings.md` | ✅ Yes | Maps to routes 70-75, 128-134 plus the social provider routes 102-105 — the per-environment settings surface and the publish path. |
| `docs/endpoints/tenant-sandbox-inbox.md` | ✅ Yes | Maps to routes 135-138 — the test-environment message inbox and provider delivery verification. |
| `docs/endpoints/platform-tenants.md` | ✅ Yes | Maps to routes 153-154. Mounted only when a platform tenant is configured; otherwise `/v1/platform` is a plain `404`. |

---

## Subagent Assignment Chunks (Phase 1 Target)

Each subagent will extract its assigned routes into `docs/openapi-fragments/<chunk-name>.yaml`:

- **`chunk-auth`**: Routes 1-10 (`/v1/health`, `/v1/ready`, `/healthz`, `/readyz`, signup, login, verify-email, resend-verification, magic-link).
- **`chunk-mfa-webauthn`**: Routes 11-27 (TOTP, SMS, Recovery Codes, WebAuthn passkeys).
- **`chunk-guardian-recovery`**: Routes 28-38 (Guardian invitation roster, Account recovery flow).
- **`chunk-org`**: Routes 53-69 (Client and Tenant Organization CRUD, member management, invitation flows).
- **`chunk-oauth-social`**: Routes 46-52, 100-105 (OIDC Discovery, JWKS, UserInfo, Authorize, Token, JWKS Rotation, Apps, Social Providers).
- **`chunk-saml`**: Routes 82-92 (SAML ACS, metadata, domain lookup, client & tenant SAML connection management).
- **`chunk-user-session`**: Routes 93-99, 106-117 (User profile, email changes, password updates, social account unlinking, session management & revocation).
- **`chunk-admin-system`**: Routes 39-45, 70-81, 118-126, 130-138 (API keys, Impersonation & policy, Password/Security/Recovery/Session Policies, per-environment settings read/diff/publish, RBAC roles & permissions, Webhook endpoints & delivery logs, sandbox message inbox & delivery verification).

Total inventoried endpoints in this table: **155 route registrations across 18 handler modules**.

> **Known gap**: routes 139-154 — `internal/audit`, `internal/useradmin` and `internal/platform` — are inventoried above but have no OpenAPI fragment and no entry in `openapi.yaml`. They are registered in `cmd/server/routes.go` and served, so the gap is in the specification rather than in the engine. `docs/endpoints/platform-tenants.md` documents 153-154 in prose.
