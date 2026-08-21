/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/saml_flow_service.go
 * Tier: Business Logic Layer / Core Service
 *
 * Description: SAML AuthnRequest construction, response validation, SSO user
 *              JIT provisioning, session issuance, and resolution of the
 *              relay-state destination a validated sign-in resumes to.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package saml

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/application"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/samlconnection"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

const (
	// refreshTokenEntropyBytes is the size of the refresh credential minted for
	// an SSO session, matching the password and social paths so no sign-in route
	// produces a weaker token than another.
	refreshTokenEntropyBytes = 32

	// defaultRefreshTokenTTL applies when the deployment has not configured one.
	defaultRefreshTokenTTL = 30 * 24 * time.Hour
)

// ProcessACS consumes a SAML response posted to the Assertion Consumer Service
// and returns the authenticated user, the session carrying them, and where to
// send the browser next.
//
// The subject's email is taken from NameID, falling back to a scan of the
// attribute statement because identity providers differ over which attribute
// name carries the address. Its domain selects the connection, and therefore
// the organization the user is provisioned into.
//
// A subject with no existing user is created on the spot with email_verified
// set, on the basis that the identity provider owns the domain and has already
// verified the address. Membership of the mapped organization is granted the
// same way, so a new hire reaches the right organization without an invitation.
//
// relayState is the destination the browser should resume at. It is treated as
// untrusted input and resolved against the tenant's registered redirect URIs;
// see resolveRelayState. An unusable value yields an empty ResumeURL rather than
// an error, because by this point the assertion has been consumed and refusing
// would cost the user a sign-in they cannot retry.
//
// Returns ErrInvalidAssertion when the payload is unparseable or carries no
// usable email, an error when no connection claims the domain, or a wrapped
// storage error from provisioning or session creation.
func (s *Service) ProcessACS(ctx context.Context, rawSAMLPayload, relayState, ip, userAgent string) (*ACSResult, error) {
	rawSAMLPayload = strings.TrimSpace(rawSAMLPayload)
	if rawSAMLPayload == "" {
		return nil, ErrInvalidAssertion
	}

	// Identity providers send the response base64-encoded under the HTTP-POST
	// binding; a payload that does not decode is treated as raw XML.
	xmlBytes, err := base64.StdEncoding.DecodeString(rawSAMLPayload)
	if err != nil {
		xmlBytes = []byte(rawSAMLPayload)
	}

	doc, err := parseSAMLDocument(xmlBytes)
	if err != nil {
		return nil, err
	}

	// The Issuer is read from unverified XML, so it serves purely as a lookup
	// key: it selects which tenant and which certificate the signature is tested
	// against and grants nothing on its own. Every field used after this point is
	// read from bytes that certificate has proven.
	//
	// The tenant is derived here rather than supplied by the caller. This request
	// carries no Authn credential — the assertion arrives from the user's browser
	// — so there is no authenticated tenant to inherit, and defaulting to one
	// would provision every identity provider's users into the same tenant.
	tenantID, err := s.ResolveTenantByIssuer(ctx, doc.issuer())
	if err != nil {
		return nil, err
	}

	// Scope the rest of this call to the resolved tenant. The request reached no
	// authenticating middleware, so nothing has installed a scope yet, and every
	// query below depends on one.
	ctx = privacy.NewContext(ctx, tenantID, "", "")

	client := s.factory.GetClient(ctx, tenantID, "")
	conn, err := client.SAMLConnection.Query().
		Where(samlconnection.IdpEntityID(doc.issuer())).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: no SAML connection matches the asserted issuer", ErrInvalidAssertion)
	}

	now := time.Now()
	verified, err := verifyAssertion(doc, conn, now, s.spEntityID(conn.OrganizationID))
	if err != nil {
		s.logAudit(ctx, tenantID, "", "saml.login_rejected", "saml_connection", conn.ID, map[string]interface{}{
			"idp_entity_id": conn.IdpEntityID,
			"reason":        err.Error(),
		}, ip, userAgent)
		return nil, err
	}

	// An assertion is single-use. Without this, a captured assertion could be
	// replayed for the remainder of its validity window.
	if !s.replay.consume(tenantID+"|"+verified.assertion.ID, verified.expiresAt, now) {
		return nil, fmt.Errorf("%w: assertion has already been used", ErrInvalidAssertion)
	}

	email := subjectEmail(verified.assertion)
	if email == "" {
		return nil, fmt.Errorf("%w: NameID/Email attribute missing in SAML assertion", ErrInvalidAssertion)
	}

	// The subject's domain must be one this connection is authorized for, so a
	// provider cannot assert identities belonging to another organization.
	domain := email[strings.LastIndex(email, "@")+1:]
	if !connectionAllowsDomain(conn, domain) {
		return nil, fmt.Errorf("%w: issuer is not authorized for domain %q", ErrInvalidAssertion, domain)
	}

	// The connection decides which environment its people belong to, so it is read
	// once here and used both to resolve the subject and to govern the session that
	// carries them.
	environment := string(conn.Environment)

	usrObj, provisioned, err := s.resolveOrProvisionSubject(ctx, client, tenantID, environment, email)
	if err != nil {
		return nil, err
	}

	// Reported where the account is known to be new rather than from the
	// provisioning helper, which has no dispatcher and would emit for the
	// connection tests that call it. via names the identity provider as the route,
	// and no user.signup accompanies it: nobody registered here, an assertion
	// arrived for an address the tenant had not seen.
	if provisioned && s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, environment, "user.created", map[string]interface{}{
			"user_id":        usrObj.ID,
			"email":          usrObj.Email,
			"via":            "saml",
			"org_id":         conn.OrganizationID,
			"email_verified": usrObj.EmailVerified,
		})
	}

	orgObj, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(conn.OrganizationID)).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query organization: %w", err)
	}

	isMember, err := client.OrgMember.Query().
		Where(orgmember.OrganizationID(conn.OrganizationID), orgmember.UserID(usrObj.ID)).
		Exist(ctx)
	if err == nil && !isMember {
		defaultRole, _ := client.Role.Query().
			Where(role.TenantID(tenantID), role.Slug(defaultMemberRoleSlug)).
			Only(ctx)
		roleID := defaultMemberRoleID
		if defaultRole != nil {
			roleID = defaultRole.ID
		}

		// A failed membership write leaves the user signed in without org
		// access, which is recoverable by an administrator; it is not worth
		// failing an otherwise valid authentication over.
		_, memberErr := client.OrgMember.Create().
			SetID(idgen.New("mem")).
			SetOrganizationID(conn.OrganizationID).
			SetUserID(usrObj.ID).
			SetRoleID(roleID).
			Save(ctx)

		// Announced only when the row exists, and named the same way the invitation
		// and direct-add paths name it, so a subscriber keeping its own roster in step
		// sees the people an identity provider brings in too.
		if memberErr == nil && s.dispatcher != nil {
			s.dispatcher.Dispatch(tenantID, environment, "org.member_joined", map[string]interface{}{
				"org_id":  conn.OrganizationID,
				"user_id": usrObj.ID,
				"role_id": roleID,
				"via":     "saml",
			})
		}
	}

	s.logAudit(ctx, tenantID, usrObj.ID, "saml.login_success", "user", usrObj.ID, map[string]interface{}{
		"email":   email,
		"domain":  domain,
		"org_id":  conn.OrganizationID,
		"idp_url": conn.IdpSSOURL,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, environment, "saml.login_success", map[string]interface{}{
			"user_id": usrObj.ID,
			"email":   email,
			"domain":  domain,
			"org_id":  conn.OrganizationID,
		})
	}

	// The session is created before the relay state is resolved. An unusable
	// destination degrades to a token in the response body, so the sign-in has to
	// exist by then; resolving first would mean a rejected destination had decided
	// whether the user is signed in at all.
	result, err := s.issueSession(ctx, usrObj, tenantID, environment, ip, userAgent)
	if err != nil {
		return nil, err
	}
	result.Organization = orgObj
	result.ResumeURL = s.resolveRelayState(ctx, tenantID, relayState)

	return result, nil
}

// resolveOrProvisionSubject returns the user an assertion's subject maps to
// within one environment, creating one if the address is new to it, and reports
// whether it created one.
//
// environment comes from the SAML connection, which is what decides where the
// people arriving through an identity provider belong. The assertion itself
// carries no environment and the request reached no authenticating middleware, so
// the connection is the only thing that can say; taking it from there means a
// connection pointed at test provisions sandbox accounts and cannot touch the live
// ones sharing an address with them.
//
// Narrowing by environment also makes the lookup single-valued by construction,
// which matters for the write below: the unique index is on
// (tenant, environment, email), so an unnarrowed query that matched two rows would
// fall through to a create the index rejects, locking that subject out of SSO for
// good rather than for one attempt.
func (s *Service) resolveOrProvisionSubject(ctx context.Context, client *ent.Client, tenantID, environment, email string) (*ent.User, bool, error) {
	existing, err := client.User.Query().
		Where(
			user.TenantID(tenantID),
			user.EnvironmentEQ(user.Environment(environment)),
			user.Email(email),
		).
		Only(ctx)
	if err == nil && existing != nil {
		return existing, false, nil
	}

	created, err := client.User.Create().
		SetID(idgen.New("usr")).
		SetTenantID(tenantID).
		SetEnvironment(user.Environment(environment)).
		SetEmail(email).
		SetEmailVerified(true).
		Save(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("failed to JIT provision user: %w", err)
	}
	return created, true, nil
}

// issueSession creates the session an authenticated SSO subject is carried by
// and returns it with the credentials that address it.
//
// Returns a wrapped error if the session row or the access token cannot be
// produced. Both are fatal to the sign-in: unlike the bookkeeping above, a user
// with no session and no token has not been signed in at all.
func (s *Service) issueSession(
	ctx context.Context,
	usrObj *ent.User,
	tenantID, environment, ip, userAgent string,
) (*ACSResult, error) {
	if s.sessions == nil {
		return nil, fmt.Errorf("saml: no session store configured, cannot complete sign-in")
	}

	// Checked here rather than left to the signer, which accepts an empty key
	// without complaint and returns a well-formed token signed with it. Such a
	// token is forgeable by anyone who notices, so an unconfigured deployment must
	// fail the sign-in instead of issuing one.
	signingSecret := s.signingSecret()
	if signingSecret == "" {
		return nil, fmt.Errorf("saml: no signing key configured, cannot issue an access token")
	}

	// The role claim is resolved from recorded roles rather than left blank: an
	// SSO subject may be a tenant administrator arriving through their employer's
	// identity provider, and an empty role would silently strip that privilege.
	role := rbac.ResolveConsoleRoleClaim(ctx, s.factory.GetClient(ctx, "", ""), usrObj.ID)

	// Minted here rather than left to the session store's fallback so that the
	// credential this path produces has the same shape and strength as the one the
	// password path produces.
	tokenBytes := make([]byte, refreshTokenEntropyBytes)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed generating refresh token: %w", err)
	}

	sess, rawRefreshToken, err := s.sessions.CreateSession(
		ctx,
		tenantID,
		environment,
		usrObj.ID,
		hex.EncodeToString(tokenBytes),
		ip,
		userAgent,
		"",
		"",
		s.refreshTokenTTL(ctx, tenantID, environment),
	)
	if err != nil {
		return nil, fmt.Errorf("failed creating session for SAML sign-in: %w", err)
	}

	accessToken, err := jwtpkg.IssueAccessTokenWithSession(
		usrObj.ID, tenantID, environment, usrObj.Email, usrObj.Name, role,
		sess.ID, signingSecret, s.accessTokenTTL(ctx, tenantID, environment),
	)
	if err != nil {
		return nil, fmt.Errorf("failed issuing access token: %w", err)
	}

	return &ACSResult{
		User:         usrObj,
		AccessToken:  accessToken,
		RefreshToken: rawRefreshToken,
		SessionID:    sess.ID,
		Environment:  environment,
	}, nil
}

// resolveRelayState returns the destination a validated sign-in may resume at,
// or "" when the value is absent or not authorized.
//
// RelayState is echoed back by the identity provider from whatever it was handed
// when the flow started, and anyone can start a flow: a link to the provider's
// SSO URL carrying RelayState=https://attacker.example costs nothing to craft.
// Since the resume redirect carries an access token, an unchecked value is not
// merely an open redirect but a working handover of a real employee's session to
// whoever chose the URL. So the value grants nothing on its own and is only ever
// matched against destinations the tenant registered in advance.
//
// The match is against every application in the tenant rather than one, because
// the ACS has no application context — an assertion identifies an organization,
// not the app the user started from — and the environment is left unnarrowed for
// the same reason. The tenant is the boundary that matters: a destination that
// tenant registered for any of its own applications is inside its own trust
// boundary, and nothing here can reach another tenant's rows, since the privacy
// scope installed above confines the query.
//
// A rejection is logged rather than returned. By the time this runs the
// assertion has been consumed and the session exists, so refusing the sign-in
// would cost the user an authentication they cannot retry in order to punish a
// destination the caller may simply have misconfigured. The caller falls back to
// returning the token in the response body, which reveals it to nobody the
// browser has not already trusted.
func (s *Service) resolveRelayState(ctx context.Context, tenantID, relayState string) string {
	relayState = strings.TrimSpace(relayState)
	if relayState == "" {
		return ""
	}

	target, err := url.Parse(relayState)
	if err != nil {
		return ""
	}

	scheme := strings.ToLower(target.Scheme)
	if (scheme != "http" && scheme != "https") || target.Host == "" {
		log.Printf("[SAML] relay state refused for tenant %s: destination is not an absolute http(s) URL", tenantID)
		return ""
	}

	apps, err := s.factory.GetClient(ctx, tenantID, "").Application.Query().
		Where(application.TenantID(tenantID)).
		All(ctx)
	if err != nil {
		log.Printf("[SAML] relay state refused for tenant %s: registered destinations unreadable: %v", tenantID, err)
		return ""
	}

	for _, app := range apps {
		for _, raw := range app.ExactRedirectUris {
			if raw == relayState {
				return relayState
			}
			registered, err := url.Parse(raw)
			if err != nil {
				continue
			}
			if strings.EqualFold(registered.Scheme, scheme) && strings.EqualFold(registered.Host, target.Host) {
				return relayState
			}
		}
	}

	log.Printf("[SAML] relay state refused for tenant %s: %q is not a registered redirect destination", tenantID, target.Host)
	return ""
}

// refreshTokenTTL is how long an SSO session for tenantID in environment may be
// refreshed before the user authenticates again, resolved from the tenant's own
// session policy and bounded by the same test-environment ceiling as every other
// sign-in path.
//
// A nil resolver falls back to the deployment default, and a Service built without
// a Config to defaultRefreshTokenTTL, so an SSO session ages out alongside a
// password one whatever is wired.
func (s *Service) refreshTokenTTL(ctx context.Context, tenantID, environment string) time.Duration {
	if s.tokenTTL != nil {
		return s.tokenTTL.RefreshTokenTTL(ctx, tenantID, environment)
	}
	if s.cfg == nil {
		return defaultRefreshTokenTTL
	}
	if s.cfg.RefreshTokenTTL > 0 {
		return s.cfg.RefreshTokenTTLFor(environment)
	}
	return s.cfg.ClampSessionTTL(environment, defaultRefreshTokenTTL)
}

// accessTokenTTL is the access-token lifetime for an SSO session belonging to
// tenantID in environment, preferring the tenant's own setting over the
// deployment default. A zero value is passed through, since the signer applies its
// own documented default.
func (s *Service) accessTokenTTL(ctx context.Context, tenantID, environment string) time.Duration {
	if s.tokenTTL != nil {
		return s.tokenTTL.AccessTokenTTL(ctx, tenantID, environment)
	}
	if s.cfg != nil {
		return s.cfg.AccessTokenTTLFor(environment)
	}
	return 0
}

// signingSecret returns the key SSO access tokens are signed with, or "" when the
// deployment configured none.
//
// The emptiness is the caller's to act on: HMAC signing accepts a zero-length key
// and produces a token indistinguishable in shape from a real one, so nothing
// downstream will notice on its behalf.
func (s *Service) signingSecret() string {
	if s.cfg == nil {
		return ""
	}
	return s.cfg.EncryptionKey
}
