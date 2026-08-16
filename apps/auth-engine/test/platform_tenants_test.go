//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/platform_tenants_test.go
 * Tier: Integration Tests / Hosted Control Plane
 *
 * The self-serve provisioning path, driven over HTTP against a real database.
 *
 * These tests exist for the properties that only appear once the guard, the
 * handler, the provisioning service and the privacy interceptor are all in play:
 * that ownership is attributed to the signed-in caller and to nobody else, that a
 * slug someone already holds cannot be claimed by a second caller, and that the
 * keys handed back actually work against the tenant they were minted for.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	entmanagedtenant "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/managedtenant"
)

// provisionReply is the subset of the creation response these tests assert on.
type provisionReply struct {
	Tenant struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Slug        string `json:"slug"`
		Environment string `json:"environment"`
	} `json:"tenant"`
	Application struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"application"`
	RolesInstalled int    `json:"roles_installed"`
	PublishableKey string `json:"publishable_key"`
	SecretKey      string `json:"secret_key"`
}

// ownedTenantsReply is the listing response.
type ownedTenantsReply struct {
	Tenants []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Slug       string `json:"slug"`
		Role       string `json:"role"`
		AcquiredAt string `json:"acquired_at"`
	} `json:"tenants"`
	Count int `json:"count"`
}

// platformMember signs a user up on the platform tenant, verifies their address,
// and returns an access token for them.
//
// Verification is part of the setup rather than a step under test because it is
// the guard's entry condition: an unverified member is refused before any handler
// runs, which TestPlatformProvisioningRequiresVerifiedEmail covers on its own.
func (e *testEnv) platformMember(t *testing.T, address string) string {
	t.Helper()

	const password = "PlatformPass123!"
	if resp := e.signUp(t, address, password, "Platform Member"); resp.status != http.StatusCreated {
		t.Fatalf("platform signup for %s: status %d body %s", address, resp.status, resp.body)
	}

	token, ok := e.emails.tokenFor(address)
	if !ok {
		t.Fatalf("no verification email carrying a token was sent to %s", address)
	}
	if resp := e.do(t, http.MethodGet,
		"/v1/client/auth/verify-email?token="+url.QueryEscape(token), nil); resp.status != http.StatusOK {
		t.Fatalf("verify-email for %s: status %d body %s", address, resp.status, resp.body)
	}

	loginResp := e.login(t, address, password)
	if loginResp.status != http.StatusOK {
		t.Fatalf("login for %s: status %d body %s", address, loginResp.status, loginResp.body)
	}
	var tokens tokenResponse
	loginResp.json(t, &tokens)
	if tokens.AccessToken == "" {
		t.Fatalf("login for %s returned no access token: %s", address, loginResp.body)
	}
	return tokens.AccessToken
}

// provision posts a creation request as the holder of accessToken.
func (e *testEnv) provision(t *testing.T, accessToken string, payload map[string]any) response {
	t.Helper()
	return e.do(t, http.MethodPost, "/v1/platform/tenants", payload,
		withHeader("Authorization", "Bearer "+accessToken))
}

// listTenants reads the caller's owned tenants.
func (e *testEnv) listTenants(t *testing.T, accessToken string) ownedTenantsReply {
	t.Helper()

	resp := e.do(t, http.MethodGet, "/v1/platform/tenants", nil,
		withHeader("Authorization", "Bearer "+accessToken))
	if resp.status != http.StatusOK {
		t.Fatalf("list tenants: status %d body %s", resp.status, resp.body)
	}
	var out ownedTenantsReply
	resp.json(t, &out)
	return out
}

// ownershipRow is one ManagedTenant record, flattened for assertion.
type ownershipRow struct {
	// OwnerUserID is the platform user the row attributes the tenant to.
	OwnerUserID string
	// TenantID is the row's own tenant, which must be the platform tenant.
	TenantID string
	// Role is the relationship recorded: "owner" or "member".
	Role string
}

// ownershipRows returns the ownership records pointing at a customer tenant.
//
// It reads under a bypass because the question is about the whole table: a scoped
// read would answer only for the control plane, which is precisely the scope the
// assertion is trying to confirm rather than assume.
func (e *testEnv) ownershipRows(t *testing.T, managedTenantID string) []ownershipRow {
	t.Helper()

	ctx := e.bypassContext()
	rows, err := e.factory.GetClient(ctx, "", "").ManagedTenant.Query().
		Where(entmanagedtenant.ManagedTenantID(managedTenantID)).
		All(ctx)
	if err != nil {
		t.Fatalf("reading ownership rows for %s: %v", managedTenantID, err)
	}

	out := make([]ownershipRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, ownershipRow{
			OwnerUserID: row.OwnerUserID,
			TenantID:    row.TenantID,
			Role:        string(row.Role),
		})
	}
	return out
}

// ownershipRowCount counts every ownership record in the database.
//
// Used where the caller cannot be asked what they own — an unverified member is
// refused by the guard on the listing route too — so "nothing was created" has to
// be answered from the table itself.
func (e *testEnv) ownershipRowCount(t *testing.T) int {
	t.Helper()

	ctx := e.bypassContext()
	n, err := e.factory.GetClient(ctx, "", "").ManagedTenant.Query().Count(ctx)
	if err != nil {
		t.Fatalf("counting ownership rows: %v", err)
	}
	return n
}

// TestPlatformProvisioningCreatesUsableTenant walks the whole self-serve path.
//
// The last step is the point of the test: the publishable key from the response is
// used to register a user into the brand-new tenant. Anything short of that would
// leave the response's keys unproven, and a caller whose first real request fails
// has been handed a tenant they cannot use.
func TestPlatformProvisioningCreatesUsableTenant(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	token := env.platformMember(t, "founder@example.com")

	resp := env.provision(t, token, map[string]any{
		"name":                 "Acme Corporation",
		"slug":                 "acme-corp",
		"environment":          "test",
		"application_name":     "Acme Web",
		"redirect_uris":        []string{"https://acme.example.com/callback"},
		"allowed_cors_origins": []string{"https://acme.example.com"},
	})
	if resp.status != http.StatusCreated {
		t.Fatalf("provision: status %d body %s", resp.status, resp.body)
	}

	var created provisionReply
	resp.json(t, &created)

	if created.Tenant.ID == "" || created.Tenant.Slug != "acme-corp" {
		t.Fatalf("provision returned an unexpected tenant: %+v", created.Tenant)
	}
	if created.Tenant.ID == testTenant {
		t.Fatal("provisioning returned the platform tenant itself rather than a new one")
	}
	if created.Application.ID == "" || created.Application.Name != "Acme Web" {
		t.Errorf("expected the first application to be named as requested, got %+v", created.Application)
	}
	if created.RolesInstalled == 0 {
		t.Error("no system roles were installed, so the new tenant has no RBAC to administer with")
	}
	if !strings.HasPrefix(created.PublishableKey, "pk_") {
		t.Errorf("publishable key %q does not carry the pk_ prefix clients dispatch on", created.PublishableKey)
	}
	if !strings.HasPrefix(created.SecretKey, "sk_") {
		t.Errorf("secret key %q does not carry the sk_ prefix", created.SecretKey)
	}

	// The keys are the deliverable. Registering a user into the new tenant with the
	// publishable key is the only assertion that proves they resolve to it.
	newUser := env.do(t, http.MethodPost, "/v1/client/auth/signup", map[string]any{
		"email":       "first_customer@acme.example.com",
		"password":    "CustomerPass123!",
		"name":        "First Customer",
		"tenant_id":   created.Tenant.ID,
		"environment": "test",
	}, withHeader("X-Authn-Publishable-Key", created.PublishableKey))
	if newUser.status != http.StatusCreated {
		t.Fatalf("signup into the provisioned tenant with its own publishable key: status %d body %s",
			newUser.status, newUser.body)
	}
}

// TestPlatformProvisioningRequiresVerifiedEmail covers the guard's entry
// condition end to end.
//
// The platform tenant's publishable key is public, so signing up into the control
// plane costs nothing. Address ownership is the only thing that separates a
// stranger from a tenant-minting credential, which is why an unverified member is
// refused and the same member succeeds once the link is followed.
func TestPlatformProvisioningRequiresVerifiedEmail(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "unverified_founder@example.com"
	const password = "PlatformPass123!"

	if resp := env.signUp(t, address, password, "Unverified Founder"); resp.status != http.StatusCreated {
		t.Fatalf("signup: status %d body %s", resp.status, resp.body)
	}

	loginResp := env.login(t, address, password)
	if loginResp.status != http.StatusOK {
		t.Fatalf("login: status %d body %s", loginResp.status, loginResp.body)
	}
	var tokens tokenResponse
	loginResp.json(t, &tokens)

	blocked := env.provision(t, tokens.AccessToken, map[string]any{"name": "Premature Corp"})
	if blocked.status != http.StatusForbidden {
		t.Fatalf("an unverified platform member provisioned a tenant: status %d body %s",
			blocked.status, blocked.body)
	}
	var envelope struct {
		Code string `json:"code"`
	}
	blocked.json(t, &envelope)
	if envelope.Code != "email_verification_required" {
		t.Errorf("got error code %q, want email_verification_required so the client knows to resend the link",
			envelope.Code)
	}

	// The listing route sits behind the same guard, so an unverified member cannot
	// read the control plane either.
	listBlocked := env.do(t, http.MethodGet, "/v1/platform/tenants", nil,
		withHeader("Authorization", "Bearer "+tokens.AccessToken))
	if listBlocked.status != http.StatusForbidden {
		t.Errorf("listing as an unverified member: status %d, want 403; body %s",
			listBlocked.status, listBlocked.body)
	}

	// Nothing may have been created on the way to that refusal. The guard runs
	// before the handler, so a row here would mean provisioning ran regardless.
	if n := env.ownershipRowCount(t); n != 0 {
		t.Errorf("a refused request left %d ownership rows behind", n)
	}

	verifyToken, ok := env.emails.tokenFor(address)
	if !ok {
		t.Fatalf("no verification email was sent to %s", address)
	}
	if resp := env.do(t, http.MethodGet,
		"/v1/client/auth/verify-email?token="+url.QueryEscape(verifyToken), nil); resp.status != http.StatusOK {
		t.Fatalf("verify-email: status %d body %s", resp.status, resp.body)
	}

	// The same token, unchanged. Verification is read from the account on every
	// request rather than baked into the session, so the caller does not have to
	// sign in again to get past the gate.
	allowed := env.provision(t, tokens.AccessToken, map[string]any{"name": "Premature Corp"})
	if allowed.status != http.StatusCreated {
		t.Fatalf("provision after verification: status %d body %s", allowed.status, allowed.body)
	}
}

// TestPlatformProvisioningRecordsOwnershipUnderTheControlPlane pins where the
// ownership row lands.
//
// A ManagedTenant row's own tenant_id is the platform tenant, not the tenant it
// describes. That is what puts it inside the control plane's privacy scope, and it
// is the difference between "only the control plane can read who owns what" and a
// row filed under the customer tenant, where the customer's own admin credential
// would reach it.
func TestPlatformProvisioningRecordsOwnershipUnderTheControlPlane(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	token := env.platformMember(t, "owner_scope@example.com")

	resp := env.provision(t, token, map[string]any{"name": "Scope Test Co", "slug": "scope-test"})
	if resp.status != http.StatusCreated {
		t.Fatalf("provision: status %d body %s", resp.status, resp.body)
	}
	var created provisionReply
	resp.json(t, &created)

	rows := env.ownershipRows(t, created.Tenant.ID)
	if len(rows) != 1 {
		t.Fatalf("got %d ownership rows for the new tenant, want exactly 1", len(rows))
	}
	if rows[0].TenantID != testTenant {
		t.Errorf("ownership row is filed under tenant %q, want the platform tenant %q",
			rows[0].TenantID, testTenant)
	}
	if rows[0].Role != string(entmanagedtenant.RoleOwner) {
		t.Errorf("ownership row records role %q, want owner", rows[0].Role)
	}

	listed := env.listTenants(t, token)
	if listed.Count != 1 || len(listed.Tenants) != 1 {
		t.Fatalf("listing reported %d tenants, want 1: %+v", listed.Count, listed.Tenants)
	}
	if listed.Tenants[0].ID != created.Tenant.ID {
		t.Errorf("listing returned tenant %q, want the one just created (%q)",
			listed.Tenants[0].ID, created.Tenant.ID)
	}
	if listed.Tenants[0].Role != "owner" {
		t.Errorf("listing reports role %q for the creator, want owner", listed.Tenants[0].Role)
	}
	if listed.Tenants[0].AcquiredAt == "" {
		t.Error("listing omitted acquired_at, which the console sorts and displays on")
	}
	// The raw keys appear once, in the creation response. A listing that repeated
	// them would turn a read-only view into a credential dump.
	if strings.Contains(string(resp.body), created.SecretKey) &&
		strings.Contains(string(env.do(t, http.MethodGet, "/v1/platform/tenants", nil,
			withHeader("Authorization", "Bearer "+token)).body), created.SecretKey) {
		t.Error("the secret key is echoed by the listing endpoint")
	}
}

// TestPlatformProvisioningRefusesSlugAlreadyOwned is the test this endpoint most
// needs.
//
// The provisioning service is idempotent by slug, which is right for a container
// entrypoint re-running its own setup and catastrophic on a public endpoint: the
// second caller would be handed the first caller's tenant, and the ownership row
// written next would give them a standing claim on it. The refusal has to land
// before any row is written, so the assertion is on the ownership table as much as
// on the status code.
func TestPlatformProvisioningRefusesSlugAlreadyOwned(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	first := env.platformMember(t, "first_claimant@example.com")
	second := env.platformMember(t, "second_claimant@example.com")

	resp := env.provision(t, first, map[string]any{"name": "Contested Inc", "slug": "contested"})
	if resp.status != http.StatusCreated {
		t.Fatalf("first provision: status %d body %s", resp.status, resp.body)
	}
	var created provisionReply
	resp.json(t, &created)

	stolen := env.provision(t, second, map[string]any{"name": "Contested Inc", "slug": "contested"})
	if stolen.status != http.StatusConflict {
		t.Fatalf("a second caller claiming an owned slug got status %d, want 409; body %s",
			stolen.status, stolen.body)
	}

	rows := env.ownershipRows(t, created.Tenant.ID)
	if len(rows) != 1 {
		t.Fatalf("the contested tenant has %d ownership rows, want 1 — the refused caller acquired a claim",
			len(rows))
	}

	if listed := env.listTenants(t, second); listed.Count != 0 {
		t.Errorf("the refused caller lists %d tenants, want 0: %+v", listed.Count, listed.Tenants)
	}
	if listed := env.listTenants(t, first); listed.Count != 1 {
		t.Errorf("the owner lists %d tenants after the failed claim, want 1", listed.Count)
	}
}

// TestPlatformListingIsScopedToTheCaller checks that two customers of the same
// hosted deployment cannot see each other's tenants.
func TestPlatformListingIsScopedToTheCaller(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	alice := env.platformMember(t, "alice_scoped@example.com")
	bob := env.platformMember(t, "bob_scoped@example.com")

	aliceResp := env.provision(t, alice, map[string]any{"name": "Alice Co", "slug": "alice-co"})
	if aliceResp.status != http.StatusCreated {
		t.Fatalf("alice provision: status %d body %s", aliceResp.status, aliceResp.body)
	}
	bobResp := env.provision(t, bob, map[string]any{"name": "Bob Co", "slug": "bob-co"})
	if bobResp.status != http.StatusCreated {
		t.Fatalf("bob provision: status %d body %s", bobResp.status, bobResp.body)
	}

	var aliceTenant, bobTenant provisionReply
	aliceResp.json(t, &aliceTenant)
	bobResp.json(t, &bobTenant)

	aliceList := env.listTenants(t, alice)
	if aliceList.Count != 1 || aliceList.Tenants[0].ID != aliceTenant.Tenant.ID {
		t.Errorf("alice sees %+v, want only her own tenant %q", aliceList.Tenants, aliceTenant.Tenant.ID)
	}
	bobList := env.listTenants(t, bob)
	if bobList.Count != 1 || bobList.Tenants[0].ID != bobTenant.Tenant.ID {
		t.Errorf("bob sees %+v, want only his own tenant %q", bobList.Tenants, bobTenant.Tenant.ID)
	}
}

// TestPlatformProvisioningIgnoresOwnerInBody pins that the body cannot name the
// owner.
//
// The request struct has no field for it, so the extra keys are dropped. Asserting
// on that is what makes adding one later a deliberate act rather than an
// accidental privilege escalation, since the fields below are exactly what an
// attacker would try.
func TestPlatformProvisioningIgnoresOwnerInBody(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	victim := env.platformMember(t, "victim_owner@example.com")
	attacker := env.platformMember(t, "attacker_owner@example.com")

	// Establish the victim's user ID by giving them a tenant of their own.
	victimResp := env.provision(t, victim, map[string]any{"name": "Victim Co", "slug": "victim-co"})
	if victimResp.status != http.StatusCreated {
		t.Fatalf("victim provision: status %d body %s", victimResp.status, victimResp.body)
	}
	var victimTenant provisionReply
	victimResp.json(t, &victimTenant)
	victimRows := env.ownershipRows(t, victimTenant.Tenant.ID)
	if len(victimRows) != 1 {
		t.Fatalf("victim has %d ownership rows, want 1", len(victimRows))
	}
	victimUserID := victimRows[0].OwnerUserID

	attackerResp := env.provision(t, attacker, map[string]any{
		"name":            "Attacker Co",
		"slug":            "attacker-co",
		"owner_user_id":   victimUserID,
		"user_id":         victimUserID,
		"platform_user":   victimUserID,
		"tenant_id":       victimTenant.Tenant.ID,
		"managed_tenant":  victimTenant.Tenant.ID,
		"roles_installed": 999,
	})
	if attackerResp.status != http.StatusCreated {
		t.Fatalf("attacker provision: status %d body %s", attackerResp.status, attackerResp.body)
	}
	var attackerTenant provisionReply
	attackerResp.json(t, &attackerTenant)

	if attackerTenant.Tenant.ID == victimTenant.Tenant.ID {
		t.Fatal("a tenant_id in the body redirected provisioning onto the victim's tenant")
	}

	rows := env.ownershipRows(t, attackerTenant.Tenant.ID)
	if len(rows) != 1 {
		t.Fatalf("the attacker's tenant has %d ownership rows, want 1", len(rows))
	}
	if rows[0].OwnerUserID == victimUserID {
		t.Error("a user identifier in the body assigned the new tenant to the victim")
	}

	// And the victim's own tenant is untouched.
	if after := env.ownershipRows(t, victimTenant.Tenant.ID); len(after) != 1 ||
		after[0].OwnerUserID != victimUserID {
		t.Errorf("the victim's ownership record changed: %+v", after)
	}
	if listed := env.listTenants(t, victim); listed.Count != 1 ||
		listed.Tenants[0].ID != victimTenant.Tenant.ID {
		t.Errorf("the victim's tenant list changed: %+v", listed.Tenants)
	}
}

// TestPlatformProvisioningRefusesReservedSlug checks both reservation lists.
//
// The control plane's own slug is deployment configuration rather than a constant
// in the provisioning package, so the first case is the assertion that the handler
// actually passes it through — a customer holding it could publish links that look
// like the hosted console's. The rest are the provisioning package's own
// unconditional reservations, refused in any deployment.
func TestPlatformProvisioningRefusesReservedSlug(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	token := env.platformMember(t, "slug_squatter@example.com")

	for _, slug := range []string{platformTenantSlug, "platform", "admin", "api", "authn"} {
		resp := env.provision(t, token, map[string]any{"name": "Squatter Co", "slug": slug})
		if resp.status != http.StatusBadRequest {
			t.Errorf("slug %q: status %d, want 400; body %s", slug, resp.status, resp.body)
		}
	}

	if n := env.ownershipRowCount(t); n != 0 {
		t.Errorf("reserved-slug requests created %d tenants", n)
	}
}

// TestPlatformProvisioningValidatesPayload covers the handler's own bounds.
//
// The Ent schema only requires these fields to be non-empty, so without a bound
// here anyone who can complete a signup decides how much text the database
// stores.
func TestPlatformProvisioningValidatesPayload(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	token := env.platformMember(t, "payload_tester@example.com")

	tooManyOrigins := make([]string, 25)
	for i := range tooManyOrigins {
		tooManyOrigins[i] = "https://example.com"
	}

	cases := []struct {
		name    string
		payload map[string]any
	}{
		{"missing name", map[string]any{"slug": "no-name-co"}},
		{"blank name", map[string]any{"name": "   ", "slug": "blank-name-co"}},
		{"overlong name", map[string]any{"name": strings.Repeat("a", 201)}},
		{"overlong application name", map[string]any{
			"name":             "Fine Co",
			"application_name": strings.Repeat("a", 201),
		}},
		{"too many redirect uris", map[string]any{
			"name":          "Fine Co",
			"redirect_uris": tooManyOrigins,
		}},
		{"overlong redirect uri", map[string]any{
			"name":          "Fine Co",
			"redirect_uris": []string{"https://example.com/" + strings.Repeat("p", 2100)},
		}},
		{"unknown environment", map[string]any{
			"name":        "Fine Co",
			"slug":        "env-co",
			"environment": "staging",
		}},
		{"malformed slug", map[string]any{"name": "Fine Co", "slug": "Not A Slug"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.provision(t, token, tc.payload)
			if resp.status != http.StatusBadRequest {
				t.Errorf("status %d, want 400; body %s", resp.status, resp.body)
			}
		})
	}

	if listed := env.listTenants(t, token); listed.Count != 0 {
		t.Errorf("rejected payloads created %d tenants: %+v", listed.Count, listed.Tenants)
	}
}

// TestPlatformRoutesRefuseNonPlatformCredentials checks the boundary from the
// outside.
//
// The provisioned tenant is a real second tenant with its own users and its own
// keys, which makes this the honest version of the middleware's tenant-mismatch
// unit test: the token here was issued by this engine, to a real user, through the
// ordinary login route. Only the tenant it names disqualifies it.
func TestPlatformRoutesRefuseNonPlatformCredentials(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	founder := env.platformMember(t, "boundary_founder@example.com")

	resp := env.provision(t, founder, map[string]any{"name": "Customer Co", "slug": "customer-co"})
	if resp.status != http.StatusCreated {
		t.Fatalf("provision: status %d body %s", resp.status, resp.body)
	}
	var created provisionReply
	resp.json(t, &created)

	// A user of the customer tenant, signed up and logged in through that tenant's
	// own publishable key.
	const customerEmail = "employee@customer-co.example.com"
	const customerPassword = "EmployeePass123!"
	withCustomerKey := withHeader("X-Authn-Publishable-Key", created.PublishableKey)

	signupResp := env.do(t, http.MethodPost, "/v1/client/auth/signup", map[string]any{
		"email":       customerEmail,
		"password":    customerPassword,
		"name":        "Customer Employee",
		"tenant_id":   created.Tenant.ID,
		"environment": "test",
	}, withCustomerKey)
	if signupResp.status != http.StatusCreated {
		t.Fatalf("customer signup: status %d body %s", signupResp.status, signupResp.body)
	}

	loginResp := env.do(t, http.MethodPost, "/v1/client/auth/login", map[string]any{
		"email":       customerEmail,
		"password":    customerPassword,
		"tenant_id":   created.Tenant.ID,
		"environment": "test",
	}, withCustomerKey)
	if loginResp.status != http.StatusOK {
		t.Fatalf("customer login: status %d body %s", loginResp.status, loginResp.body)
	}
	var customerTokens tokenResponse
	loginResp.json(t, &customerTokens)
	if customerTokens.AccessToken == "" {
		t.Fatalf("customer login returned no access token: %s", loginResp.body)
	}

	blocked := env.provision(t, customerTokens.AccessToken, map[string]any{"name": "Escalation Co"})
	if blocked.status != http.StatusForbidden {
		t.Fatalf("a customer-tenant session reached the control plane: status %d body %s",
			blocked.status, blocked.body)
	}

	listBlocked := env.do(t, http.MethodGet, "/v1/platform/tenants", nil,
		withHeader("Authorization", "Bearer "+customerTokens.AccessToken))
	if listBlocked.status != http.StatusForbidden {
		t.Errorf("listing with a customer-tenant session: status %d, want 403; body %s",
			listBlocked.status, listBlocked.body)
	}

	// The publishable key alone establishes no identity, and the customer's secret
	// key names a tenant rather than a person. Neither may stand in for a session.
	for _, tc := range []struct {
		name     string
		decorate func(*http.Request)
	}{
		{"publishable key only", withCustomerKey},
		{"customer secret key", withHeader("X-Authn-Secret-Key", created.SecretKey)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			anon := env.do(t, http.MethodPost, "/v1/platform/tenants",
				map[string]any{"name": "Anonymous Co"}, tc.decorate)
			if anon.status != http.StatusUnauthorized {
				t.Errorf("status %d, want 401; body %s", anon.status, anon.body)
			}
		})
	}
}
