/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/provisioning/provisioning_test.go
 * Tier: Internal Feature Package / Tenant Provisioning Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package provisioning_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/provisioning"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

const testPepper = "provisioning_test_pepper_32_bytes_long"

func newTestService(t *testing.T) (*provisioning.Service, *clientfactory.ClientFactory) {
	t.Helper()
	dsn := fmt.Sprintf("file:ent_prov_%s?mode=memory&cache=shared&_fk=1", uuid.New().String()[:8])
	factory, err := clientfactory.NewClientFactory("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { factory.Close() })

	keys := apikey.NewService(apikey.NewRepository(factory), testPepper)
	return provisioning.NewService(factory, keys), factory
}

// sysCtx returns a bypass context for assertions that read across tenants.
func sysCtx() context.Context {
	return privacy.NewBypassContext(context.Background())
}

func TestProvision_CreatesCompleteTenant(t *testing.T) {
	svc, factory := newTestService(t)
	ctx := context.Background()

	res, err := svc.Provision(ctx, provisioning.Request{Name: "Acme Corporation"}, provisioning.Options{})
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(res.TenantID, "tnt_"), "tenant id should be prefixed")
	assert.True(t, strings.HasPrefix(res.ApplicationID, "app_"), "application id should be prefixed")
	assert.Equal(t, "acme-corporation", res.TenantSlug, "slug derives from the name")
	assert.Equal(t, "test", res.Environment, "test is the safe default environment")
	assert.False(t, res.AlreadyExisted)

	// The raw keys are returned exactly once, and are usable immediately.
	assert.True(t, strings.HasPrefix(res.PublishableKey, "pk_test_"), "got %q", res.PublishableKey)
	assert.True(t, strings.HasPrefix(res.SecretKey, "sk_test_"), "got %q", res.SecretKey)

	// Without roles a tenant has no administrator, so this is not cosmetic.
	assert.Equal(t, 4, res.RolesInstalled)
	count, err := factory.GetClient(sysCtx(), res.TenantID, "test").Role.Query().
		Where(role.TenantID(res.TenantID)).Count(sysCtx())
	require.NoError(t, err)
	assert.Equal(t, 4, count)

	// The first-admin slot stays open so the first signup claims it.
	tnt, err := factory.GetClient(sysCtx(), res.TenantID, "test").Tenant.Query().
		Where(tenant.ID(res.TenantID)).Only(sysCtx())
	require.NoError(t, err)
	assert.False(t, tnt.FirstAdminClaimed)
}

func TestProvision_KeysAuthenticateAgainstTheNewTenant(t *testing.T) {
	svc, factory := newTestService(t)
	ctx := context.Background()

	res, err := svc.Provision(ctx, provisioning.Request{Name: "Globex"}, provisioning.Options{})
	require.NoError(t, err)

	// The point of provisioning: the printed key resolves to the tenant it was
	// minted for. A key that does not validate makes the tenant unreachable.
	keys := apikey.NewService(apikey.NewRepository(factory), testPepper)
	key, app, err := keys.ValidateKey(sysCtx(), res.PublishableKey, apikey.TypePublishable)
	require.NoError(t, err)
	assert.Equal(t, res.ApplicationID, app.ID)
	assert.Equal(t, res.TenantID, app.TenantID)
	assert.Equal(t, "test", string(key.Environment))
}

func TestProvision_IdempotentBySlug(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	first, err := svc.Provision(ctx, provisioning.Request{Name: "Initech"}, provisioning.Options{})
	require.NoError(t, err)

	second, err := svc.Provision(ctx, provisioning.Request{Name: "Initech"}, provisioning.Options{})
	require.NoError(t, err)

	assert.True(t, second.AlreadyExisted)
	assert.Equal(t, first.TenantID, second.TenantID, "must not create a second tenant")
	// Re-running must not mint fresh credentials for an existing tenant.
	assert.Empty(t, second.PublishableKey)
	assert.Empty(t, second.SecretKey)
}

func TestProvision_RefusesReservedSlugs(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Idempotency-by-slug is what makes this dangerous: without the guard, a
	// caller naming the platform's slug would receive the control-plane tenant
	// and a freshly minted secret key for it.
	for _, name := range []string{"platform", "Admin", "system", "default"} {
		_, err := svc.Provision(ctx, provisioning.Request{Name: name}, provisioning.Options{})
		assert.ErrorIs(t, err, provisioning.ErrReservedSlug, "slug %q must be refused", name)
	}

	_, err := svc.Provision(ctx, provisioning.Request{Name: "Acme", Slug: "acme-platform-tenant"},
		provisioning.Options{ReservedSlugs: []string{"acme-platform-tenant"}})
	assert.ErrorIs(t, err, provisioning.ErrReservedSlug, "configured reservations must apply too")
}

func TestProvision_PlatformTenantShape(t *testing.T) {
	svc, factory := newTestService(t)
	ctx := context.Background()

	res, err := svc.Provision(ctx, provisioning.Request{Name: "Platform", Slug: "platform"},
		provisioning.Options{AllowReservedSlug: true, ClaimFirstAdmin: true, SkipSecretKey: true})
	require.NoError(t, err)

	// The control plane's publishable key ships in a browser bundle, so anyone
	// may sign up into it. If the first-admin slot were open, the first stranger
	// to do so would become tenant_admin of the control plane.
	tnt, err := factory.GetClient(sysCtx(), res.TenantID, "test").Tenant.Query().
		Where(tenant.ID(res.TenantID)).Only(sysCtx())
	require.NoError(t, err)
	assert.True(t, tnt.FirstAdminClaimed, "platform first-admin slot must be pre-closed")

	// No secret key is minted: nothing needs one, and a key that does not exist
	// cannot leak the control plane's admin surface.
	assert.NotEmpty(t, res.PublishableKey)
	assert.Empty(t, res.SecretKey)
}

func TestProvision_RejectsBadInput(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.Provision(ctx, provisioning.Request{Name: "   "}, provisioning.Options{})
	assert.ErrorIs(t, err, provisioning.ErrInvalidName)

	// A name of pure punctuation slugifies to nothing.
	_, err = svc.Provision(ctx, provisioning.Request{Name: "!!!"}, provisioning.Options{})
	assert.ErrorIs(t, err, provisioning.ErrInvalidSlug)

	_, err = svc.Provision(ctx, provisioning.Request{Name: "Acme", Slug: "Not A Slug"}, provisioning.Options{})
	assert.ErrorIs(t, err, provisioning.ErrInvalidSlug)

	_, err = svc.Provision(ctx, provisioning.Request{Name: "Acme", Environment: "staging"}, provisioning.Options{})
	assert.ErrorIs(t, err, provisioning.ErrInvalidEnvironment)
}

func TestProvision_SeparateTenantsDoNotCollide(t *testing.T) {
	svc, factory := newTestService(t)
	ctx := context.Background()

	a, err := svc.Provision(ctx, provisioning.Request{Name: "Tenant A"}, provisioning.Options{})
	require.NoError(t, err)
	b, err := svc.Provision(ctx, provisioning.Request{Name: "Tenant B"}, provisioning.Options{})
	require.NoError(t, err)

	assert.NotEqual(t, a.TenantID, b.TenantID)

	// Role IDs embed the tenant, so the second tenant's roles must not collide
	// with the first's. A shared "role_tenant_admin" would fail to insert here.
	countB, err := factory.GetClient(sysCtx(), b.TenantID, "test").Role.Query().
		Where(role.TenantID(b.TenantID)).Count(sysCtx())
	require.NoError(t, err)
	assert.Equal(t, 4, countB)
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Acme Corporation":      "acme-corporation",
		"  Spaced  Out  ":       "spaced-out",
		"Ünïcødé Ltd":           "n-c-d-ltd",
		"Multi---Hyphen":        "multi-hyphen",
		"UPPER":                 "upper",
		"trailing-":             "trailing",
		"a.b.c":                 "a-b-c",
		strings.Repeat("x", 80): strings.Repeat("x", 63),
	}
	for in, want := range cases {
		assert.Equal(t, want, provisioning.Slugify(in), "input %q", in)
	}
}
