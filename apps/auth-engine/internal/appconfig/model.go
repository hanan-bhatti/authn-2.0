/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/appconfig/model.go
 * Tier: Domain Model Layer
 *
 * The bootstrap document a sign-in page fetches before it renders, and the
 * tenant branding an administrator configures to shape it.
 *
 * Everything here is served behind a publishable key, which ships in browser
 * bundles and is therefore public. The question asked of every field is not
 * "is the caller authenticated" but "would this be safe printed on the sign-in
 * page", because in practice that is where it ends up. The fields deliberately
 * left out are enumerated in service.go, next to the code that omits them.
 *
 * The response is a set of explicit projections rather than the stored policy
 * structs. A policy gains fields over time, and embedding one would publish each
 * new field the moment it was added; a projection means a field reaches this API
 * only when someone puts it here on purpose.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package appconfig

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/validator"
)

// Bounds on the free-text branding fields. Each value is stored in a JSON column
// read on every sign-in page load, so it is bounded at the point of writing
// rather than left to whatever an administrator pastes in.
const (
	maxAppNameLength    = 100
	maxFontFamilyLength = 200
	maxCustomCSSLength  = 16 * 1024
)

// hexColor matches a CSS hex colour in its three accepted lengths: #rgb, #rrggbb
// and #rrggbbaa.
//
// Colours are constrained to this form rather than accepting any CSS colour
// value because they are interpolated into a stylesheet or an inline style. A
// free-form value there can carry a whole declaration — "red; behavior: url(…)"
// — so the safest colour is one whose grammar cannot express anything else.
var hexColor = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$`)

// Branding is the presentational configuration a tenant applies to its hosted
// sign-in experience.
//
// Every field is public: it is served to any holder of a publishable key, which
// is to say to anyone who views the source of the sign-in page. The type exists
// to keep it that way. The stored column is a free-form JSON object shared with
// settings that are not public — email templates among them — and unmarshalling
// into a fixed struct discards every key that is not named here, so a key added
// to the column for another purpose cannot reach this response.
type Branding struct {
	// AppName is the product name shown on the sign-in card. Empty means the
	// client should fall back to the application or tenant name.
	AppName string `json:"app_name"`
	// LogoURL is the primary logo, and LogoDarkURL its dark-scheme counterpart.
	// Both are absolute http(s) URLs.
	LogoURL     string `json:"logo_url"`
	LogoDarkURL string `json:"logo_dark_url"`
	// FaviconURL is the icon for the hosted pages.
	FaviconURL string `json:"favicon_url"`

	// PrimaryColor is the accent applied to buttons and links, BackgroundColor
	// the page background, TextColor the body text, and ButtonTextColor the label
	// on a primary button. All are hex, and all may be empty to inherit the
	// client's own default.
	PrimaryColor    string `json:"primary_color"`
	BackgroundColor string `json:"background_color"`
	TextColor       string `json:"text_color"`
	ButtonTextColor string `json:"button_text_color"`

	// FontFamily is a CSS font-family list, without the property name or the
	// terminating semicolon.
	FontFamily string `json:"font_family"`

	// SupportURL, TermsURL and PrivacyURL are the footer links. A tenant that
	// leaves one empty has no such link rather than a broken one.
	SupportURL string `json:"support_url"`
	TermsURL   string `json:"terms_url"`
	PrivacyURL string `json:"privacy_url"`
	// CustomCSS is appended to the hosted stylesheet.
	CustomCSS string `json:"custom_css"`
}

// DefaultBranding returns the branding of a tenant that has configured none:
// every field empty, which leaves the client on its own defaults.
//
// It returns zero values rather than a house style because this is the fallback
// used when the tenant row cannot be read. Substituting a colour scheme there
// would render a sign-in page that looks configured and is not.
func DefaultBranding() Branding {
	return Branding{}
}

// ValidateBranding checks and normalizes caller-supplied branding, returning what
// should be stored.
//
// It returns an error naming the first offending field. Unlike the tenant
// policies, nothing here is clamped into range: a colour or URL cannot be
// corrected into a valid one, and silently dropping a logo an administrator
// believes they set is worse than refusing the write.
//
// URLs are checked with validator.ValidateImageURL, which enforces http(s),
// rejects javascript: and data: payloads, and constrains the host. Its name
// refers to its first use rather than a limit on what it accepts; the rules are
// exactly the ones a value written into an href or src needs.
func ValidateBranding(b Branding) (Branding, error) {
	name, err := validator.SanitizeString(b.AppName, 0, maxAppNameLength)
	if err != nil {
		return b, fmt.Errorf("app_name: %w", err)
	}
	b.AppName = name

	urls := []struct {
		field string
		value *string
	}{
		{"logo_url", &b.LogoURL},
		{"logo_dark_url", &b.LogoDarkURL},
		{"favicon_url", &b.FaviconURL},
		{"support_url", &b.SupportURL},
		{"terms_url", &b.TermsURL},
		{"privacy_url", &b.PrivacyURL},
	}
	for _, u := range urls {
		normalized, err := validator.ValidateImageURL(*u.value)
		if err != nil {
			return b, fmt.Errorf("%s: %w", u.field, err)
		}
		*u.value = normalized
	}

	colors := []struct {
		field string
		value *string
	}{
		{"primary_color", &b.PrimaryColor},
		{"background_color", &b.BackgroundColor},
		{"text_color", &b.TextColor},
		{"button_text_color", &b.ButtonTextColor},
	}
	for _, c := range colors {
		trimmed := strings.TrimSpace(*c.value)
		if trimmed != "" && !hexColor.MatchString(trimmed) {
			return b, fmt.Errorf("%s must be a hex colour such as #1a73e8 (got %q)", c.field, trimmed)
		}
		*c.value = trimmed
	}

	font := strings.TrimSpace(b.FontFamily)
	if len(font) > maxFontFamilyLength {
		return b, fmt.Errorf("font_family must not exceed %d characters", maxFontFamilyLength)
	}
	// A font family is interpolated into a single CSS declaration. Semicolons and
	// braces are what let a value end that declaration and start another, so they
	// are refused rather than escaped: no legitimate font list contains one.
	if strings.ContainsAny(font, ";{}<>") || validator.ContainsControlChars(font) {
		return b, fmt.Errorf("font_family must not contain ; { } < > or control characters")
	}
	b.FontFamily = font

	css := strings.TrimSpace(b.CustomCSS)
	if len(css) > maxCustomCSSLength {
		return b, fmt.Errorf("custom_css must not exceed %d bytes", maxCustomCSSLength)
	}
	// "<" is refused outright because the stylesheet is delivered inside a <style>
	// element: a payload containing "</style><script>" would close the element and
	// execute. CSS has no other use for the character, so refusing it costs a
	// tenant nothing and removes the breakout entirely. The cost is that a "width
	// < 400px" container query has to be written with the max-width form.
	if strings.ContainsAny(css, "<>") {
		return b, fmt.Errorf("custom_css must not contain < or >, which would let a payload escape the <style> element")
	}
	if validator.ContainsControlChars(css) {
		return b, fmt.Errorf("custom_css must not contain control characters")
	}
	b.CustomCSS = css

	return b, nil
}

// AppConfig is the document a sign-in page fetches once, before it renders, to
// learn how it should look, which sign-in options to offer, and what it may
// accept as a password.
//
// It answers those three questions in one round trip because a page that made
// three calls would render three times, and because two of the three are
// policies the page must agree with the server about — publishing a weaker
// password rule than the server enforces produces a form that accepts input the
// API then refuses.
type AppConfig struct {
	// Application identifies the application the presented key belongs to, so a
	// client can confirm it is talking to the environment it expected.
	Application ApplicationInfo `json:"application"`
	// Tenant is the owning workspace's public identity.
	Tenant TenantInfo `json:"tenant"`
	// Branding is the tenant's presentational configuration.
	Branding Branding `json:"branding"`
	// SignInMethods is what the page should offer as a way in.
	SignInMethods SignInMethods `json:"sign_in_methods"`
	// SecondFactors is what it should offer once a first factor succeeds.
	SecondFactors SecondFactors `json:"second_factors"`
	// PasswordRules is the effective password policy, expressed as the values the
	// engine will actually enforce.
	PasswordRules PasswordRules `json:"password_rules"`
	// EmailVerification is how the tenant treats an unverified address.
	EmailVerification EmailVerification `json:"email_verification"`
	// AccountRecovery is which recovery proofs a locked-out user may offer.
	AccountRecovery AccountRecovery `json:"account_recovery"`
}

// ApplicationInfo is the calling application's public identity.
//
// The allowed origins and redirect URIs stored alongside these fields are
// deliberately absent: they are the allowlists an open-redirect attempt is
// measured against, and publishing them turns a guess into a lookup.
type ApplicationInfo struct {
	// ID is the application identifier the publishable key resolved to.
	ID string `json:"id"`
	// Name is the human-readable application name.
	Name string `json:"name"`
	// Environment is "test" or "live", taken from the key rather than the request.
	// A client renders a test-mode banner from this.
	Environment string `json:"environment"`
}

// TenantInfo is the owning workspace's public identity: what a sign-in page may
// display and nothing more.
type TenantInfo struct {
	// Name is the workspace's display name.
	Name string `json:"name"`
	// Slug is its URL-safe handle.
	Slug string `json:"slug"`
}

// SignInMethods is the set of first factors a sign-in page should offer.
//
// Several fields are unconditionally true. They describe the surface the engine
// compiles in, and they are reported rather than assumed so that a client reads
// every capability from one place instead of splitting the question between what
// it asks the server and what it hardcodes.
type SignInMethods struct {
	// Password reports whether email-and-password sign-in is available. Always
	// true: it is the engine's base credential and has no switch.
	Password bool `json:"password"`
	// MagicLink reports whether a one-time emailed sign-in link is available,
	// following the deployment's FEATURE_MAGIC_LINK_ENABLED flag.
	MagicLink bool `json:"magic_link"`
	// Passkey reports whether WebAuthn sign-in is available. Always true: the
	// relying party is always configured, defaulting to the deployment host.
	Passkey bool `json:"passkey"`
	// EnterpriseSSO reports whether this tenant has at least one SAML connection,
	// which is what makes a "Sign in with SSO" option worth showing. Which
	// connection serves a given user is resolved per email domain, by
	// POST /v1/client/auth/domain-lookup — that is not answered here, because it
	// depends on the address the user has not typed yet.
	EnterpriseSSO bool `json:"enterprise_sso"`
	// SocialProviders names the providers the tenant has enabled, sorted, so the
	// page renders its buttons in a stable order.
	//
	// Names only. The client ID of an enabled provider is not included: the
	// engine performs the authorization redirect itself, so a browser never needs
	// one, and a credential nobody needs is a credential not worth publishing.
	SocialProviders []string `json:"social_providers"`
}

// SecondFactors is the set of second factors a tenant's users may hold, so a
// sign-in page can label an MFA challenge before it knows which factor the user
// enrolled.
type SecondFactors struct {
	// TOTP reports authenticator-app codes. Always true.
	TOTP bool `json:"totp"`
	// SMS reports whether one-time codes can be delivered by text message, which
	// requires the deployment to have a real SMS driver configured.
	SMS bool `json:"sms"`
	// Passkey reports WebAuthn as a second factor. Always true.
	Passkey bool `json:"passkey"`
	// RecoveryCodes reports single-use backup codes. Always true.
	RecoveryCodes bool `json:"recovery_codes"`
	// Push reports whether push approval is available, following the deployment's
	// FEATURE_PUSH_2FA_ENABLED flag.
	Push bool `json:"push"`
}

// PasswordRules is the password policy as a sign-in page should apply it.
//
// The lengths are the effective bounds, not the stored ones. A tenant may store
// a minimum below the engine's own floor, and the engine still enforces the
// floor; publishing the stored value would produce a form that accepts a
// password the API then rejects, which reads to the user as a bug in the site.
type PasswordRules struct {
	// MinLength and MaxLength are the character bounds the engine will enforce.
	MinLength int `json:"min_length"`
	MaxLength int `json:"max_length"`
	// RequireUppercase, RequireLowercase, RequireNumeric and RequireSpecial are
	// the character-class requirements.
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumeric   bool `json:"require_numeric"`
	RequireSpecial   bool `json:"require_special"`
	// Enforced reports whether a non-compliant password is refused. When false
	// the tenant is in "notify" mode: the password is accepted and the unmet
	// criteria are reported, so a page should warn rather than block.
	Enforced bool `json:"enforced"`
}

// EmailVerification is how the tenant treats a user whose address is unverified,
// which decides what a page does after a successful sign-up.
type EmailVerification struct {
	// Required reports whether a verified address is demanded at all.
	Required bool `json:"required"`
	// Mode is "hard" when an unverified user is refused access, or "soft" when
	// they are admitted with the unverified state flagged on the token. A page
	// shows a blocking screen for the first and a dismissible banner for the
	// second.
	Mode string `json:"mode"`
}

// AccountRecovery is which proofs a locked-out user may offer, so the "can't sign
// in?" flow can render its options.
//
// The recovery policy's remaining fields — the lockout schedule, the reset
// window, the per-window attempt cap, and the subnet widths attempts are grouped
// by — are absent by design. They are the thresholds an attack is measured
// against, and an attacker who can read them can pace an attempt to stay under
// every one of them.
type AccountRecovery struct {
	// Guardians, PhoneOTP, EmailOTP, OldPassword and SecurityQuestions each
	// report whether that proof is accepted. PhoneOTP additionally requires the
	// deployment to have a real SMS driver, since a tenant can enable the method
	// on a deployment that cannot deliver a text.
	Guardians         bool `json:"guardians"`
	PhoneOTP          bool `json:"phone_otp"`
	EmailOTP          bool `json:"email_otp"`
	OldPassword       bool `json:"old_password"`
	SecurityQuestions bool `json:"security_questions"`
	// MinGuardians and MaxGuardians bound how many guardians a user enrols, which
	// the enrolment screen needs in order to validate before submitting.
	MinGuardians int `json:"min_guardians"`
	MaxGuardians int `json:"max_guardians"`
}
