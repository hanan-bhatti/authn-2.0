/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/repository.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Data access for social authentication — the single-use CSRF
 *              state that spans the provider round trip, linked-identity
 *              upsert, user lookup and creation from a provider profile, and
 *              per-tenant provider credentials held encrypted at rest.
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

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/identity"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/socialauthstate"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
)

const (
	// stateEntropyBytes is the randomness behind each CSRF state token,
	// hex-encoded into the value sent to the provider and back.
	stateEntropyBytes = 16

	// idSuffixLength is how much of a generated UUID is kept in a record ID.
	idSuffixLength = 12
)

var (
	// ErrStateNotFound reports a state token that never existed or has already
	// been redeemed.
	ErrStateNotFound = errors.New("social auth state not found or already consumed")
	// ErrStateExpired reports a state token presented after its expiry.
	ErrStateExpired = errors.New("social auth state has expired")
)

// Repository is the storage layer for social authentication.
type Repository struct {
	// factory yields tenant- and environment-scoped database clients.
	factory *clientfactory.ClientFactory
	// policies holds the per-environment settings row that carries provider
	// credentials, so a tenant's test providers are configured independently of
	// its live ones.
	policies *policy.Repository
	// encryptKey is the AES-256-GCM key protecting provider secrets and stored
	// provider tokens at rest.
	encryptKey string
}

// NewRepository constructs a Repository using encryptKey for at-rest encryption.
func NewRepository(factory *clientfactory.ClientFactory, policies *policy.Repository, encryptKey string) *Repository {
	return &Repository{factory: factory, policies: policies, encryptKey: encryptKey}
}

// CreateSocialAuthState records a new CSRF state token, valid for ttl, and
// returns it for inclusion in the provider authorization URL.
//
// The token is the row's primary key, so the database enforces uniqueness and a
// collision fails the write rather than silently overwriting a live flow. The
// destination the user should land on afterwards is stored here so the callback
// does not have to trust a query parameter it receives from the provider.
//
// Returns an error if entropy is unavailable or the write fails.
func (r *Repository) CreateSocialAuthState(
	ctx context.Context,
	tenantID, applicationID, environment, provider, redirectURI, postCallbackRedirect string,
	ttl time.Duration,
) (stateToken string, err error) {
	b := make([]byte, stateEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	stateToken = hex.EncodeToString(b)
	expiresAt := time.Now().Add(ttl)

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

// ConsumeSocialAuthState returns the state row for stateToken and deletes it.
//
// Deletion happens before the expiry check, so a token is spent by the first
// callback that presents it whatever the outcome. A state that survived a
// failed callback could be replayed, which is exactly the cross-site request
// forgery the state parameter exists to prevent.
//
// Returns ErrStateNotFound when the token is unknown or already consumed, and
// ErrStateExpired when it is past its expiry.
func (r *Repository) ConsumeSocialAuthState(ctx context.Context, tenantID, stateToken string) (*ent.SocialAuthState, error) {
	// No environment is named because the row itself records which one the flow
	// began in, and that is not known until after the read.
	client := r.factory.GetClient(ctx, tenantID, "")

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

	err = client.SocialAuthState.DeleteOneID(stateToken).Exec(ctx)
	if err != nil {
		return nil, err
	}

	if state.ExpiresAt.Before(time.Now()) {
		return nil, ErrStateExpired
	}

	return state, nil
}

// PurgeExpiredAuthState deletes state rows whose expiry has passed and returns
// how many were removed. It requires a context carrying a privacy bypass,
// because the sweep spans every tenant.
//
// Abandoned sign-ins never reach the callback that would consume their state, so
// without a sweep those rows accumulate for the lifetime of the deployment. An
// expired row has no remaining use: ConsumeSocialAuthState refuses one before
// returning it, so nothing distinguishes deleting it from leaving it.
//
// Deletion is batched, in ID order, for the same reasons as the session sweep.
func (r *Repository) PurgeExpiredAuthState(ctx context.Context, before time.Time, batchSize int) (int, error) {
	if batchSize <= 0 {
		return 0, fmt.Errorf("social auth state purge: batch size must be positive, got %d", batchSize)
	}

	client := r.factory.GetClient(ctx, "", "")
	total := 0

	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}

		ids, err := client.SocialAuthState.Query().
			Where(socialauthstate.ExpiresAtLT(before)).
			Order(ent.Asc(socialauthstate.FieldID)).
			Limit(batchSize).
			IDs(ctx)
		if err != nil {
			return total, fmt.Errorf("selecting expired social auth state: %w", err)
		}
		if len(ids) == 0 {
			return total, nil
		}

		removed, err := client.SocialAuthState.Delete().
			Where(socialauthstate.IDIn(ids...)).
			Exec(ctx)
		if err != nil {
			return total, fmt.Errorf("deleting expired social auth state: %w", err)
		}
		total += removed

		if removed == 0 || len(ids) < batchSize {
			return total, nil
		}
	}
}

// FindIdentityByProvider looks up the linked identity for a provider and that
// provider's subject ID.
//
// Returns (nil, nil) when no identity is linked — an ordinary outcome on first
// sign-in, not an error.
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

// UpsertIdentity links a provider account to userID, refreshing the stored
// profile and tokens when the link already exists.
//
// Provider access and refresh tokens are encrypted before storage: they grant
// access to the user's account at the provider, so a database leak alone must
// not yield usable credentials.
//
// Returns the stored identity, or an error if encryption or the write fails.
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

	return client.Identity.Create().
		SetID(idgen.New("idn")).
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

// FindUserByEmailForSocial looks up a user by address within a tenant and
// environment, to detect a social profile whose email already belongs to an
// existing account.
//
// Returns (nil, nil) when no user matches.
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

// CreateSocialUser creates a user from a social profile.
//
// No password hash is set: the account has no password until the user chooses
// one, so there is no weak credential to guess. emailVerified reflects the
// provider's own claim rather than being assumed true.
//
// Returns the created user, or an error if the write fails.
func (r *Repository) CreateSocialUser(
	ctx context.Context,
	tenantID, environment, email, name, avatarURL string,
	emailVerified bool,
) (*ent.User, error) {
	client := r.factory.GetClient(ctx, tenantID, environment)

	return client.User.Create().
		SetID(idgen.New("usr")).
		SetTenantID(tenantID).
		SetEnvironment(user.Environment(environment)).
		SetEmail(email).
		SetName(name).
		SetAvatarURL(avatarURL).
		SetEmailVerified(emailVerified).
		Save(ctx)
}

// UpdateUserLastSignIn stamps last_sign_in_at with the current server time.
//
// A social sign-in has to record this itself: nothing else on the callback path
// writes it, and without it an account that only ever signs in through a
// provider reads as dormant in every report that ranks users by last activity.
//
// The error is returned rather than swallowed so the caller can decide, but the
// value is presentational — a failure here should not fail a sign-in that has
// already issued tokens.
func (r *Repository) UpdateUserLastSignIn(ctx context.Context, userID string) error {
	_, err := r.factory.GetClient(ctx, "", "").User.UpdateOneID(userID).
		SetLastSignInAt(time.Now()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed stamping last sign in: %w", err)
	}
	return nil
}

// CreateSignInAuditLog appends the audit record for a completed social sign-in.
//
// The provider is recorded in metadata rather than in the event type, so that
// every sign-in across every method answers to one query on user.signed_in and
// the provider is a filter within it rather than a separate event name to know
// about.
//
// applicationID is optional and identifies which application the sign-in was
// for, which the shared session model cannot otherwise express.
func (r *Repository) CreateSignInAuditLog(
	ctx context.Context,
	tenantID, applicationID, userID, provider, ipAddress, userAgent, origin string,
) error {
	client := r.factory.GetClient(ctx, tenantID, "")

	create := client.AuditLog.Create().
		SetID(idgen.New("aud")).
		SetTenantID(tenantID).
		SetNillableUserID(&userID).
		SetActorType(auditlog.ActorTypeUser).
		SetEventType("user.signed_in").
		SetIPAddress(ipAddress).
		SetUserAgent(userAgent).
		SetRequestOrigin(origin).
		SetMetadata(map[string]interface{}{
			"method":   "social",
			"provider": provider,
		})
	if applicationID != "" {
		create = create.SetApplicationID(applicationID)
	}

	if _, err := create.Save(ctx); err != nil {
		return fmt.Errorf("failed creating social sign-in audit log: %w", err)
	}
	return nil
}

// GetProviderConfig reads one provider's configuration for one environment.
//
// The client secret is returned still encrypted; use GetDecryptedProviderConfig
// when the plaintext is actually needed.
//
// Returns (nil, nil) when the provider is not configured.
func (r *Repository) GetProviderConfig(ctx context.Context, tenantID, environment, provider string) (*ProviderConfig, error) {
	providers, err := r.policies.GetSocialProviders(ctx, tenantID, environment)
	if err != nil {
		return nil, err
	}

	val, ok := providers[provider]
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

// GetAllProviderConfigs returns every provider configured for one environment,
// keyed by provider name, with secrets left encrypted.
//
// An entry that fails to decode is skipped rather than failing the whole read,
// so one malformed provider cannot break the settings screen.
//
// Returns an empty map when nothing is configured.
func (r *Repository) GetAllProviderConfigs(ctx context.Context, tenantID, environment string) (map[string]*ProviderConfig, error) {
	providers, err := r.policies.GetSocialProviders(ctx, tenantID, environment)
	if err != nil {
		return nil, err
	}

	result := make(map[string]*ProviderConfig, len(providers))
	for k, v := range providers {
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

// SetProviderConfig writes a provider's configuration for one environment,
// encrypting clientSecret before storage.
//
// The two environments hold independent credentials, which is the point: a tenant
// registers a separate OAuth application with the provider for its test sign-ins,
// pointed at a test callback URL, and configuring it cannot disturb the live one.
//
// An empty clientSecret keeps the stored ciphertext, so an administrator can
// toggle a provider or correct its client ID without re-entering a secret they
// cannot read back.
//
// Returns an error if encryption or the write fails.
func (r *Repository) SetProviderConfig(
	ctx context.Context,
	tenantID, environment, provider string,
	enabled bool,
	clientID, clientSecret string,
) error {
	providers, err := r.policies.GetSocialProviders(ctx, tenantID, environment)
	if err != nil {
		return err
	}
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

	return r.policies.UpdateSocialProviders(ctx, tenantID, environment, providers)
}

// DeleteProviderConfig removes a provider's configuration from one environment,
// discarding its stored secret.
//
// Returns an error if the read or write fails; removing an absent provider
// succeeds.
func (r *Repository) DeleteProviderConfig(ctx context.Context, tenantID, environment, provider string) error {
	providers, err := r.policies.GetSocialProviders(ctx, tenantID, environment)
	if err != nil {
		return err
	}
	if providers == nil {
		return nil
	}

	delete(providers, provider)

	return r.policies.UpdateSocialProviders(ctx, tenantID, environment, providers)
}

// GetDecryptedProviderConfig returns a provider's client ID, plaintext client
// secret and enabled flag.
//
// The plaintext secret is for building the provider request only and must never
// reach an API response.
//
// Returns zero values when the provider is not configured, or an error if
// decryption fails.
func (r *Repository) GetDecryptedProviderConfig(ctx context.Context, tenantID, environment, provider string) (clientID, clientSecret string, enabled bool, err error) {
	conf, err := r.GetProviderConfig(ctx, tenantID, environment, provider)
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

// newID returns a prefixed record identifier such as "usr_1a2b3c4d5e6f".
func newID(prefix string) string {
	return idgen.New(prefix)
}
