/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/environment.go
 * Tier: Internal Feature Package / Environment Naming & Settings Comparison
 *
 * The two environment names, and the operations that treat a whole environment's
 * settings as one value: redacting it for a response and comparing it against the
 * other environment.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package policy

import "encoding/json"

const (
	// EnvironmentTest is the sandbox environment. Its users, applications and keys
	// are invisible to a live credential, and its settings govern only its own
	// sign-ins.
	EnvironmentTest = "test"
	// EnvironmentLive is the production environment.
	EnvironmentLive = "live"
)

// settingsColumns names every policy column, in the order a diff reports them.
//
// Publishing copies all of these, so a column absent from this list would be
// copied without ever appearing in the diff an administrator approved.
var settingsColumns = []string{
	"branding_config",
	"password_policy",
	"security_policy",
	"recovery_policy",
	"social_providers",
	"role_policy",
	"session_policy",
}

// column returns one policy column by its stored name.
func (s Settings) column(name string) map[string]interface{} {
	switch name {
	case "branding_config":
		return s.BrandingConfig
	case "password_policy":
		return s.PasswordPolicy
	case "security_policy":
		return s.SecurityPolicy
	case "recovery_policy":
		return s.RecoveryPolicy
	case "social_providers":
		return s.SocialProviders
	case "role_policy":
		return s.RolePolicy
	case "session_policy":
		return s.SessionPolicy
	}
	return nil
}

// Password returns the enforceable password policy these settings hold, or the
// default when the column is absent or no longer parses.
//
// The four accessors below exist so a caller that already holds a whole Settings
// does not have to read the row again per policy. The bootstrap document behind
// every sign-in page needs three of them at once, and it decodes them here exactly
// as a direct repository read would.
func (s Settings) Password() PasswordPolicy {
	return decodePasswordPolicy(s.PasswordPolicy)
}

// Security returns the enforceable security policy these settings hold, or the
// default when the column is absent or no longer parses.
func (s Settings) Security() SecurityPolicy {
	return decodeSecurityPolicy(s.SecurityPolicy)
}

// Recovery returns the recovery policy these settings hold, or the default when the
// column is absent or no longer parses.
func (s Settings) Recovery() RecoveryPolicy {
	return decodeRecoveryPolicy(s.RecoveryPolicy)
}

// Session returns the enforceable session policy these settings hold, or the default
// when the column is absent or no longer parses.
func (s Settings) Session() SessionPolicy {
	return decodeSessionPolicy(s.SessionPolicy)
}

// Redacted returns a copy safe to put in an API response.
//
// Only social_providers carries a secret. Each provider's encrypted client secret
// is replaced by a client_secret_set boolean, which is the part a console actually
// needs: whether the provider is configured. Returning the ciphertext would put a
// credential in a response for no gain, and an administrator comparing two
// environments does not need to see either secret to know they differ.
func (s Settings) Redacted() Settings {
	s.SocialProviders = redactSocialProviders(s.SocialProviders)
	return s
}

// redactSocialProviders replaces every provider's client secret with a boolean.
//
// The provider entries are copied rather than edited, because the map handed in
// belongs to an Ent row that other code may still read.
func redactSocialProviders(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return nil
	}

	out := make(map[string]interface{}, len(in))
	for provider, raw := range in {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			// Not the documented shape. Passed through rather than dropped, since a
			// value this layer does not recognise is not one it can confirm is a
			// secret, and silently discarding configuration is worse than showing it.
			out[provider] = raw
			continue
		}

		copied := make(map[string]interface{}, len(entry))
		for key, value := range entry {
			switch key {
			case "client_secret_encrypted", "client_secret":
				secret, _ := value.(string)
				copied["client_secret_set"] = secret != ""
			default:
				copied[key] = value
			}
		}
		out[provider] = copied
	}
	return out
}

// DifferingFields returns the names of the policy columns that differ between two
// environments' settings, in a stable order.
//
// Comparison is on the encoded JSON rather than the maps, which makes it exact and
// order-independent: encoding/json sorts map keys, so two maps holding the same
// configuration always encode identically. An unencodable column is reported as
// differing, because a column this layer cannot compare is one it cannot promise is
// unchanged.
//
// Two matching environments give an empty slice rather than a nil one, so the
// endpoints that hand this straight to a response encode "nothing differs" as [].
// It is the most common answer they give, and a caller reading its length should
// not have to treat it as the one shape that has no length.
func DifferingFields(a, b Settings) []string {
	differing := make([]string, 0, len(settingsColumns))
	for _, name := range settingsColumns {
		if !sameColumn(a.column(name), b.column(name)) {
			differing = append(differing, name)
		}
	}
	return differing
}

// sameColumn reports whether two policy columns hold the same configuration.
//
// An absent column and an empty one are the same thing to every reader in this
// package — both mean "nothing stored, run the defaults" — so they compare equal
// rather than showing up as a difference that publishing would not change.
func sameColumn(a, b map[string]interface{}) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}

	encodedA, errA := json.Marshal(a)
	encodedB, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(encodedA) == string(encodedB)
}
