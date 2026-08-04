/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/repository.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Data access layer for social authentication — state token CRUD,
 *              identity upsert, user find/create, and provider config management.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package social

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/identity"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/socialauthstate"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
)

var (
	ErrStateNotFound = errors.New("social auth state not found or already consumed")
	ErrStateExpired  = errors.New("social auth state has expired")
)

type Repository struct {
	factory    *clientfactory.ClientFactory
	encryptKey string
}

func NewRepository(factory *clientfactory.ClientFactory, encryptKey string) *Repository {
	return &Repository{factory: factory, encryptKey: encryptKey}
}

// CreateSocialAuthState persists a new CSRF state token before redirecting the
// browser to the provider. The state string is used as the primary key.
func (r *Repository) CreateSocialAuthState(
	ctx context.Context,
	tenantID, applicationID, environment, provider, redirectURI, postCallbackRedirect string,
) (stateToken string, err error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	stateToken = hex.EncodeToString(b)
	expiresAt := time.Now().Add(10 * time.Minute)

	client := r.factory.GetClient(ctx, tenantID, environment)

	_, err = client.SocialAuthState.Create().
		SetID(stateToken).
		SetTenantID(tenantID).
		SetApplicationID(applicationID).
		SetEnvironment(environment).
		SetProvider(provider).
		SetRedirectURI(redirectURI).
		SetPostCallbackRedirect(postCallbackRedirect).
		SetExpiresAt(expiresAt).
		Save(ctx)

	if err != nil {
		return "", err
	}

	return stateToken, nil
}

// ConsumeSocialAuthState atomically fetches and hard-deletes a state token.
// Returns ErrStateNotFound if missing, ErrStateExpired if past expires_at.
// One-use guarantee: deleted immediately on read so it can never be replayed.
func (r *Repository) ConsumeSocialAuthState(ctx context.Context, tenantID, stateToken string) (*ent.SocialAuthState, error) {
	client := r.factory.GetClient(ctx, tenantID, "test")

	state, err := client.SocialAuthState.Query().
		Where(
			socialauthstate.ID(stateToken),
			socialauthstate.TenantID(tenantID),
		).Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrStateNotFound
		}
		return nil, err
	}

	// Hard-delete immediately to ensure one-time use
	err = client.SocialAuthState.DeleteOneID(stateToken).Exec(ctx)
	if err != nil {
		return nil, err
	}

	if state.ExpiresAt.Before(time.Now()) {
		return nil, ErrStateExpired
	}

	return state, nil
}

// PurgeSocialAuthState deletes all expired state records for a tenant.
// Called from a background goroutine. Non-fatal if it fails.
func (r *Repository) PurgeSocialAuthState(ctx context.Context, tenantID string) error {
	client := r.factory.GetClient(ctx, tenantID, "test")

	_, err := client.SocialAuthState.Delete().
		Where(
			socialauthstate.TenantID(tenantID),
			socialauthstate.ExpiresAtLT(time.Now()),
		).Exec(ctx)

	return err
}

// FindIdentityByProvider looks up an Identity by provider name + provider's user ID.
// Returns nil, nil if not found (not an error — caller handles the not-found case).
func (r *Repository) FindIdentityByProvider(ctx context.Context, provider, providerUserID string) (*ent.Identity, error) {
	client := r.factory.GetClient(ctx, "", "")

	identityResult, err := client.Identity.Query().
		Where(
			identity.Provider(provider),
			identity.ProviderUserID(providerUserID),
		).Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return identityResult, nil
}

// UpsertIdentity creates or updates an Identity record for a provider user.
// If the identity already exists (by provider+providerUserID), it updates the
// encrypted tokens and profile_data. If not, it creates a new Identity linked to userID.
func (r *Repository) UpsertIdentity(
	ctx context.Context,
	userID, provider, providerUserID, email, name, avatarURL string,
	profileData map[string]interface{},
	accessToken, refreshToken string,
) (*ent.Identity, error) {
	client := r.factory.GetClient(ctx, "", "")

	encAccess, err := crypto.EncryptAES256GCM(accessToken, r.encryptKey)
	if err != nil {
		return nil, err
	}

	encRefresh, err := crypto.EncryptAES256GCM(refreshToken, r.encryptKey)
	if err != nil {
		return nil, err
	}

	existing, err := r.FindIdentityByProvider(ctx, provider, providerUserID)
	if err != nil {
		return nil, err
	}

	if existing != nil {
		return existing.Update().
			SetProfileData(profileData).
			SetAccessTokenEncrypted(encAccess).
			SetRefreshTokenEncrypted(encRefresh).
			Save(ctx)
	}

	id := fmt.Sprintf("idn_%s", uuid.New().String()[:12])

	return client.Identity.Create().
		SetID(id).
		SetUserID(userID).
		SetProvider(provider).
		SetProviderUserID(providerUserID).
		SetEmail(email).
		SetAvatarURL(avatarURL).
		SetProfileData(profileData).
		SetAccessTokenEncrypted(encAccess).
		SetRefreshTokenEncrypted(encRefresh).
		Save(ctx)
}

// FindUserByEmailForSocial looks up a user by email within a tenant+environment.
// Used to detect email collisions (existing password user) during social signup.
// Returns nil, nil if not found.
func (r *Repository) FindUserByEmailForSocial(ctx context.Context, tenantID, environment, email string) (*ent.User, error) {
	client := r.factory.GetClient(ctx, tenantID, environment)

	u, err := client.User.Query().
		Where(
			user.TenantID(tenantID),
			user.EnvironmentEQ(user.Environment(environment)),
			user.Email(email),
		).Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return u, nil
}

// CreateSocialUser creates a new User from a social provider profile.
// password_hash is NOT set (social-only user — can be set later via set-password).
// email_verified is set based on the provider's EmailVerified claim.
func (r *Repository) CreateSocialUser(
	ctx context.Context,
	tenantID, environment, email, name, avatarURL string,
	emailVerified bool,
) (*ent.User, error) {
	client := r.factory.GetClient(ctx, tenantID, environment)

	id := fmt.Sprintf("usr_%s", uuid.New().String()[:12])

	return client.User.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetEnvironment(user.Environment(environment)).
		SetEmail(email).
		SetName(name).
		SetAvatarURL(avatarURL).
		SetEmailVerified(emailVerified).
		Save(ctx)
}

// GetProviderConfig reads a single provider's config from Tenant.social_providers.
// Returns nil, nil if the provider is not configured.
// The client_secret_encrypted field is returned AS-IS (still encrypted).
func (r *Repository) GetProviderConfig(ctx context.Context, tenantID, provider string) (*ProviderConfig, error) {
	client := r.factory.GetClient(ctx, tenantID, "test")

	t, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil {
		return nil, err
	}

	if t.SocialProviders == nil {
		return nil, nil
	}

	val, ok := t.SocialProviders[provider]
	if !ok {
		return nil, nil
	}

	b, err := json.Marshal(val)
	if err != nil {
		return nil, err
	}

	var conf ProviderConfig
	if err := json.Unmarshal(b, &conf); err != nil {
		return nil, err
	}

	return &conf, nil
}

// GetAllProviderConfigs returns all configured providers for a tenant.
// Secrets remain encrypted. Returns empty map if none configured.
func (r *Repository) GetAllProviderConfigs(ctx context.Context, tenantID string) (map[string]*ProviderConfig, error) {
	client := r.factory.GetClient(ctx, tenantID, "test")

	t, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil {
		return nil, err
	}

	result := make(map[string]*ProviderConfig)
	if t.SocialProviders == nil {
		return result, nil
	}

	for k, v := range t.SocialProviders {
		b, err := json.Marshal(v)
		if err != nil {
			continue
		}
		var conf ProviderConfig
		if err := json.Unmarshal(b, &conf); err != nil {
			continue
		}
		result[k] = &conf
	}

	return result, nil
}

// SetProviderConfig writes or updates a single provider's config in Tenant.social_providers.
// clientSecret is plaintext — this method encrypts it before storage.
// If clientSecret is empty string, keeps the existing encrypted value (allows updating
// client_id or enabled status without re-entering the secret).
func (r *Repository) SetProviderConfig(
	ctx context.Context,
	tenantID, provider string,
	enabled bool,
	clientID, clientSecret string,
) error {
	client := r.factory.GetClient(ctx, tenantID, "test")

	t, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil {
		return err
	}

	providers := t.SocialProviders
	if providers == nil {
		providers = make(map[string]interface{})
	}

	var existingSecretEncrypted string
	if val, ok := providers[provider]; ok {
		b, err := json.Marshal(val)
		if err == nil {
			var conf ProviderConfig
			if err := json.Unmarshal(b, &conf); err == nil {
				existingSecretEncrypted = conf.ClientSecretEncrypted
			}
		}
	}

	var secretToSave string
	if clientSecret != "" {
		enc, err := crypto.EncryptAES256GCM(clientSecret, r.encryptKey)
		if err != nil {
			return err
		}
		secretToSave = enc
	} else {
		secretToSave = existingSecretEncrypted
	}

	newConf := ProviderConfig{
		Enabled:               enabled,
		ClientID:              clientID,
		ClientSecretEncrypted: secretToSave,
	}

	b, err := json.Marshal(newConf)
	if err != nil {
		return err
	}
	var newConfMap map[string]interface{}
	if err := json.Unmarshal(b, &newConfMap); err != nil {
		return err
	}

	providers[provider] = newConfMap

	return client.Tenant.UpdateOneID(tenantID).SetSocialProviders(providers).Exec(ctx)
}

// DeleteProviderConfig removes a provider from Tenant.social_providers.
func (r *Repository) DeleteProviderConfig(ctx context.Context, tenantID, provider string) error {
	client := r.factory.GetClient(ctx, tenantID, "test")

	t, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil {
		return err
	}

	if t.SocialProviders == nil {
		return nil
	}

	delete(t.SocialProviders, provider)

	return client.Tenant.UpdateOneID(tenantID).SetSocialProviders(t.SocialProviders).Exec(ctx)
}

// GetDecryptedProviderConfig returns a provider's config with client_secret decrypted.
// Used only by the service layer when building the OAuth flow — never returned to API callers.
func (r *Repository) GetDecryptedProviderConfig(ctx context.Context, tenantID, provider string) (clientID, clientSecret string, enabled bool, err error) {
	conf, err := r.GetProviderConfig(ctx, tenantID, provider)
	if err != nil {
		return "", "", false, err
	}
	if conf == nil {
		return "", "", false, nil
	}

	decryptedSecret := ""
	if conf.ClientSecretEncrypted != "" {
		decryptedSecret, err = crypto.DecryptAES256GCM(conf.ClientSecretEncrypted, r.encryptKey)
		if err != nil {
			return "", "", false, err
		}
	}

	return conf.ClientID, decryptedSecret, conf.Enabled, nil
}
