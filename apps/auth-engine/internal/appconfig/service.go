/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/appconfig/service.go
 * Tier: Business Logic Layer
 *
 * Assembles the public bootstrap document from the tenant's settings, its
 * policies, and the deployment's own capabilities.
 *
 * This is the file that decides what a publishable key can read. The projections
 * below are deliberately narrower than the structs they are built from, and each
 * omission is recorded next to the code that makes it, because the omissions are
 * the security property: a publishable key ships in a browser bundle, so
 * everything reaching this response is effectively published.
 *
 * Nothing here fails. A policy read already degrades to its documented default,
 * a tenant-row read degrades to empty branding, and the SSO probe degrades to
 * false. A sign-in page that cannot bootstrap cannot sign anyone in, so the worst
 * outcome available is an unstyled page offering the engine's base credentials.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package appconfig

import (
	"context"
	"log"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/settings"
)

// noopSMSDriver is the SMS driver that logs a message instead of sending it.
//
// A deployment left on it has no way to deliver a text, so reporting SMS as an
// available factor would have a sign-in page offer a code that never arrives.
// Email has no equivalent check: address verification is on every sign-up path
// whether or not a provider is configured, so gating it would remove a step the
// engine performs regardless.
const noopSMSDriver = "noop"

// ApplicationResolver reads an application's runtime settings.
//
// It is an interface so the service can be exercised without a database and a
// cache. settings.Resolver satisfies it, and brings a short-TTL Redis cache with
// it — which matters here, because this is the one request every sign-in page
// makes before it renders.
type ApplicationResolver interface {
	// Application returns the application, or (nil, nil) when no such row exists.
	Application(ctx context.Context, applicationID string) (*settings.Application, error)
}

// Service builds the bootstrap document and applies branding writes.
type Service struct {
	// repo reads the tenant row's settings columns.
	repo *Repository
	// policies reads the tenant's password, security and recovery policies.
	policies *policy.Repository
	// apps resolves the application the presented key belongs to.
	apps ApplicationResolver
	// cfg supplies the deployment capabilities a tenant cannot change.
	cfg *config.Config
}

// NewService returns a service wired to its dependencies.
func NewService(repo *Repository, policies *policy.Repository, apps ApplicationResolver, cfg *config.Config) *Service {
	return &Service{repo: repo, policies: policies, apps: apps, cfg: cfg}
}

// AppConfig assembles the bootstrap document for one application.
//
// tenantID, applicationID and environment come from the publishable key the
// middleware verified, never from the request, so a caller cannot bootstrap a
// tenant their key does not belong to. The environment decides every configured
// value below: a test key describes the test configuration, and rehearsing a
// branding or provider change in test is the point of that.
//
// It returns no error. Every underlying read degrades to a documented default, so
// the caller always has something to render.
func (s *Service) AppConfig(ctx context.Context, tenantID, applicationID, environment string) AppConfig {
	identity := s.repo.TenantIdentity(ctx, tenantID)

	// One read covers everything the customer configures. The policies, branding and
	// provider list all live in the same row, and this is the request every sign-in
	// page makes before it renders — so they are fetched together rather than a row
	// read apiece. An unreadable row yields a zero value whose every accessor returns
	// the documented default.
	stored, err := s.policies.Snapshot(ctx, tenantID, environment)
	if err != nil {
		log.Printf("[error] appconfig.settings tenant=%s environment=%s: %v", tenantID, environment, err)
	}

	smsDeliverable := s.smsDeliverable()

	return AppConfig{
		Application:       s.applicationInfo(ctx, applicationID, environment),
		Tenant:            TenantInfo{Name: identity.Name, Slug: identity.Slug},
		Branding:          decodeBranding(stored.BrandingConfig),
		SignInMethods:     s.signInMethods(ctx, tenantID, environment, enabledProviders(stored.SocialProviders)),
		SecondFactors:     s.secondFactors(smsDeliverable),
		PasswordRules:     passwordRules(stored.Password()),
		EmailVerification: emailVerification(stored.Security()),
		AccountRecovery:   accountRecovery(stored.Recovery(), smsDeliverable),
	}
}

// applicationInfo projects the application's public identity.
//
// The environment is taken from the key rather than from the resolved row so that
// the answer describes the credential that was presented. The two agree in
// practice, and preferring the key means a client is told which environment its
// own key addresses.
//
// The resolved row also carries the application's allowed CORS origins and exact
// redirect URIs. Neither is projected: they are the allowlists an open-redirect
// or cross-origin attempt is measured against, and a public endpoint that
// enumerated them would turn guessing a valid redirect target into reading one.
func (s *Service) applicationInfo(ctx context.Context, applicationID, environment string) ApplicationInfo {
	info := ApplicationInfo{ID: applicationID, Environment: environment}

	app, err := s.apps.Application(ctx, applicationID)
	if err != nil || app == nil {
		return info
	}
	info.Name = app.Name
	return info
}

// signInMethods reports the first factors a page should offer.
func (s *Service) signInMethods(ctx context.Context, tenantID, environment string, socialProviders []string) SignInMethods {
	if socialProviders == nil {
		socialProviders = []string{}
	}
	return SignInMethods{
		Password:        true,
		MagicLink:       s.cfg.FeatureMagicLinkEnabled,
		Passkey:         true,
		EnterpriseSSO:   s.repo.HasEnterpriseSSO(ctx, tenantID, environment),
		SocialProviders: socialProviders,
	}
}

// smsDeliverable reports whether this deployment can actually send a text
// message.
//
// An unnamed driver counts as undeliverable rather than deliverable. config.Load
// always resolves SMS_DRIVER to one of the supported values, but a Config
// assembled in code leaves the field empty, and reading that as "SMS works"
// would have a sign-in page offer a code that nothing is configured to send.
func (s *Service) smsDeliverable() bool {
	return s.cfg.SMSDriver != "" && s.cfg.SMSDriver != noopSMSDriver
}

// secondFactors reports the second factors a page should be prepared to challenge
// with.
func (s *Service) secondFactors(smsDeliverable bool) SecondFactors {
	return SecondFactors{
		TOTP:          true,
		SMS:           smsDeliverable,
		Passkey:       true,
		RecoveryCodes: true,
		Push:          s.cfg.FeaturePush2FAEnabled,
	}
}

// passwordRules projects the password policy into the rules a client should apply.
//
// The lengths are the effective bounds rather than the stored ones, so the rule a
// page enforces is the rule the engine enforces. "require" and "notify" collapse
// to a single Enforced flag: a client only needs to know whether to block or to
// warn, and an enum invites a third state to be mishandled.
//
// ForceUpgradeOnSignin is not projected. It governs what happens to an existing
// user with a non-compliant password at their next sign-in, which the sign-in
// response tells the client at the moment it applies; publishing it up front
// would have a page act on a condition it cannot evaluate.
func passwordRules(p policy.PasswordPolicy) PasswordRules {
	minLen, maxLen := policy.EffectivePasswordBounds(p)
	return PasswordRules{
		MinLength:        minLen,
		MaxLength:        maxLen,
		RequireUppercase: p.RequireUppercase,
		RequireLowercase: p.RequireLowercase,
		RequireNumeric:   p.RequireNumeric,
		RequireSpecial:   p.RequireSpecial,
		Enforced:         p.EnforcementMode != "notify",
	}
}

// emailVerification projects the verification half of the security policy.
//
// TokenReusePolicy, the policy's third field, is not projected. It says whether a
// replayed refresh token ends every session the user has or only the affected
// family, which tells an attacker holding a stolen token whether using it is
// noisy or quiet. A sign-in page has no use for the answer.
func emailVerification(sp policy.SecurityPolicy) EmailVerification {
	mode := sp.EmailVerificationMode
	if mode == "" {
		mode = "soft"
	}
	return EmailVerification{
		Required: sp.RequireEmailVerification,
		Mode:     mode,
	}
}

// accountRecovery projects the recovery methods a locked-out user may offer.
//
// Only the method toggles and the guardian counts cross the boundary. The freeze
// window, claim-token lifetime, lockout schedule, lockout reset window, trusted
// device window, per-window attempt cap and the subnet widths attempts are
// grouped by are all withheld: they are the thresholds an attack is measured
// against, and an attacker who can read them can pace an attempt to stay under
// every one. A recovery screen needs to know which buttons to draw, not how
// patient to be.
func accountRecovery(rp policy.RecoveryPolicy, smsDeliverable bool) AccountRecovery {
	return AccountRecovery{
		Guardians:         rp.GuardiansEnabled,
		PhoneOTP:          rp.PhoneOTPEnabled && smsDeliverable,
		EmailOTP:          rp.EmailOTPEnabled,
		OldPassword:       rp.OldPasswordEnabled,
		SecurityQuestions: rp.SecurityQuestionsEnabled,
		MinGuardians:      rp.MinGuardians,
		MaxGuardians:      rp.MaxGuardians,
	}
}

// Branding returns the environment's stored branding for the administrative read,
// or the default branding when nothing is stored.
func (s *Service) Branding(ctx context.Context, tenantID, environment string) (Branding, error) {
	stored, err := s.policies.GetBrandingConfig(ctx, tenantID, environment)
	if err != nil {
		return DefaultBranding(), err
	}
	return decodeBranding(stored), nil
}

// UpdateBranding validates and stores the environment's branding, returning what was
// stored.
//
// The stored column is replaced rather than merged. Branding is edited as a whole
// form, so a merge would make clearing a logo impossible: an empty string and an
// absent key are indistinguishable after JSON round-tripping.
func (s *Service) UpdateBranding(ctx context.Context, tenantID, environment string, b Branding) (Branding, error) {
	validated, err := ValidateBranding(b)
	if err != nil {
		return b, err
	}

	if err := s.policies.UpdateBrandingConfig(ctx, tenantID, environment, encodeBranding(validated)); err != nil {
		return validated, err
	}
	return validated, nil
}
