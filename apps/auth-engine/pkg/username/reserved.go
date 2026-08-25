/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/username/reserved.go
 * Tier: Shared Package / Identifier Normalization
 *
 * The set of handles no user may hold.
 *
 * Three distinct hazards are covered, and the list is grouped by which one each
 * entry addresses rather than alphabetically, because the grouping is what tells
 * a later contributor whether their addition belongs.
 *
 * A handle appears in a URL path, so one that collides with an application route
 * makes that route unreachable — a user holding "settings" shadows the settings
 * page for the whole deployment. A handle also appears wherever the product
 * names itself, so one that reads as staff lets its holder ask other users for
 * their password with the platform's own authority behind the request. The
 * remainder are values that software treats as absent: a handle of "null" or
 * "undefined" is indistinguishable from a bug in every log line it appears in.
 *
 * The list is compiled in rather than stored, because it is a constant of the
 * product and not tenant data. A database lookup to answer a question whose
 * answer never changes would put a round trip on the availability path, which is
 * the one path where latency is visible as the user types.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package username

// reserved is the lookup set built from reservedHandles at init.
var reserved = func() map[string]struct{} {
	set := make(map[string]struct{}, len(reservedHandles))
	for _, h := range reservedHandles {
		set[h] = struct{}{}
	}
	return set
}()

// Reserved reports whether canonical is withheld from user allocation.
//
// The argument is expected in canonical form. Canonical calls this as its last
// check, so a value that reached storage has already been tested.
func Reserved(canonical string) bool {
	_, taken := reserved[canonical]
	return taken
}

// reservedHandles lists every withheld handle in canonical form.
//
// Separator-free and underscore variants are listed alongside their hyphenated
// originals — "verify_email" and "verifyemail" as well as the "/verify-email"
// route they protect — because the canonical charset excludes the hyphen, so the
// route name itself can never be typed and only its typeable spellings need
// withholding.
var reservedHandles = []string{
	// Authority: a handle that reads as the platform or its operators.
	"admin", "admins", "administrator", "root", "superuser", "sudo",
	"sysadmin", "system", "staff", "official", "support", "helpdesk",
	"moderator", "moderators", "mod", "security", "abuse", "postmaster",
	"webmaster", "hostmaster", "authn", "noreply", "no_reply", "donotreply",

	// Routes: a handle that would shadow a page or an API prefix.
	"auth", "api", "oauth", "oauth2", "openid", "sso", "saml", "scim",
	"login", "signin", "sign_in", "logout", "signout", "sign_out",
	"signup", "sign_up", "register", "registration", "join",
	"verify", "verify_email", "verifyemail", "verification",
	"magic", "magiclink", "magic_link", "passwordless",
	"password", "reset", "forgot", "recover", "recovery",
	"mfa", "2fa", "twofactor", "two_factor", "totp", "otp", "passkey", "webauthn",
	"token", "tokens", "session", "sessions", "callback", "redirect",
	"account", "accounts", "user", "users", "profile", "profiles",
	"me", "my", "settings", "preferences", "dashboard", "console", "portal",
	"org", "orgs", "organization", "organizations", "team", "teams",
	"billing", "invoice", "invoices", "plans", "pricing", "upgrade",
	"docs", "documentation", "help", "about", "contact", "legal",
	"terms", "tos", "privacy", "status", "health", "blog", "news",
	"search", "explore", "discover", "feed", "notifications", "invite",
	"invitations", "webhook", "webhooks", "graphql", "rpc",

	// Hostnames: a handle that reads as infrastructure, which matters wherever a
	// handle is rendered as a subdomain or an address.
	"www", "www1", "www2", "web", "mail", "email", "smtp", "imap", "pop",
	"ftp", "sftp", "ssh", "ns", "ns1", "ns2", "dns", "mx", "cdn", "edge",
	"static", "assets", "img", "images", "media", "files", "download",
	"downloads", "upload", "uploads", "app", "apps", "dev", "developer",
	"developers", "staging", "sandbox", "internal", "localhost",

	// Absent values: a handle software cannot distinguish from missing data.
	"null", "nil", "none", "undefined", "empty", "void", "false", "true",
	"anonymous", "anon", "guest", "unknown", "deleted", "removed", "banned",
	"everyone", "all", "here", "channel", "bot", "bots", "robot",
	"test", "tests", "testing", "demo", "example", "sample", "placeholder",
}
