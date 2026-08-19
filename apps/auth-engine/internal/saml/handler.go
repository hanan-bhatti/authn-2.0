/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/handler.go
 * Tier: HTTP Controller Layer / Fiber Endpoints
 *
 * Description: Fiber handlers for Enterprise SAML 2.0 SSO (FR-16) — per-
 *              organization connection CRUD, the domain lookup that tells a
 *              sign-in page whether an email address must go through SSO, the
 *              Assertion Consumer Service that identity providers post
 *              assertions to, and the service-provider metadata document.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package saml

import (
	"errors"
	"fmt"
	"log"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/authcookie"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
)

const (
	// metadataCacheControl is sent on the service-provider metadata document.
	// Identity providers refetch it periodically and it changes only when the
	// deployment's own address does.
	metadataCacheControl = "public, max-age=3600"
)

// Handler exposes the SAML endpoints over HTTP.
type Handler struct {
	// service performs the underlying SAML operations.
	service *Service
	// cookies builds the refresh cookie the ACS writes. It is never nil:
	// NewHandler installs one backed by default tenant policy, and
	// WithSessionPolicyResolver replaces it with one that reads live policy.
	cookies *authcookie.Writer
}

// NewHandler constructs a Handler bound to service.
func NewHandler(service *Service) *Handler {
	return &Handler{
		service: service,
		cookies: authcookie.NewWriter(service.cfg, nil),
	}
}

// WithSessionPolicyResolver points cookie construction at a live source of tenant
// session policy, and returns the handler for chaining.
//
// An SSO sign-in ends in the same refresh cookie as a password sign-in, so it has
// to honour the same tenant SameSite and lifetime settings; without a resolver
// both paths fall back to policy.DefaultSessionPolicy, which is correct but deaf
// to a customer's configuration.
func (h *Handler) WithSessionPolicyResolver(r authcookie.SessionPolicyResolver) *Handler {
	h.cookies = authcookie.NewWriter(h.service.cfg, r)
	return h
}

// RegisterRoutes mounts the SAML endpoints on app.
//
// The ACS and metadata routes are deliberately unauthenticated: an identity
// provider posts assertions and fetches metadata without any credential of
// ours. Their protection is assertion validation, not a middleware.
//
// pkMiddleware guards the client-facing routes. adminMiddleware, when supplied,
// mounts a parallel tenant-scoped copy of the connection CRUD routes.
func (h *Handler) RegisterRoutes(app *fiber.App, pkMiddleware fiber.Handler, adminMiddleware fiber.Handler) {
	app.Post("/v1/saml/acs", h.ProcessACS)
	app.Get("/v1/saml/metadata/:orgId", h.GetSPMetadata)

	clientGroup := app.Group("/v1/client", pkMiddleware)
	clientGroup.Post("/auth/domain-lookup", h.LookupDomainSSO)

	clientGroup.Post("/organizations/:orgId/saml", h.CreateSAMLConnection)
	clientGroup.Get("/organizations/:orgId/saml", h.GetSAMLConnection)
	clientGroup.Patch("/organizations/:orgId/saml", h.UpdateSAMLConnection)
	clientGroup.Delete("/organizations/:orgId/saml", h.DeleteSAMLConnection)

	if adminMiddleware != nil {
		adminGroup := app.Group("/v1/tenant", adminMiddleware)
		adminGroup.Post("/organizations/:orgId/saml", h.CreateSAMLConnection)
		adminGroup.Get("/organizations/:orgId/saml", h.GetSAMLConnection)
		adminGroup.Patch("/organizations/:orgId/saml", h.UpdateSAMLConnection)
		adminGroup.Delete("/organizations/:orgId/saml", h.DeleteSAMLConnection)
	}
}

// getTenantID returns the tenant resolved by the authenticating middleware, or
// "" when none was resolved.
//
// There is deliberately no default tenant: a request that reaches a handler with
// no resolved tenant is not authenticated, and substituting one would turn a
// middleware misconfiguration into a cross-tenant read or write.
//
// The two unauthenticated SAML protocol endpoints do not use this. They derive
// their tenant from the protocol identifier they carry — see tenant_resolver.go.
func getTenantID(c *fiber.Ctx) string {
	if val, ok := c.Locals("tenantID").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("tenant_id").(string); ok && val != "" {
		return val
	}
	return ""
}

// requireTenantID returns the resolved tenant, or a written 401 response when
// the tenant is unknown. Callers must return the response as-is when ok is false.
//
// Every route using it sits behind the publishable-key or admin middleware, both
// of which set the tenant on success and reject the request otherwise, so an
// empty tenant means the request was never authenticated.
func requireTenantID(c *fiber.Ctx) (string, error, bool) {
	tenantID := getTenantID(c)
	if tenantID == "" {
		return "", httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"tenant could not be resolved for this request"), false
	}
	return tenantID, nil, true
}

// getUserID returns the acting user's ID for audit attribution, or "" when the
// request is not user-authenticated.
func getUserID(c *fiber.Ctx) string {
	return rbac.ExtractUserID(c)
}

// sendConfigValidationError maps a configuration-validation failure onto a
// client-safe 400 shared by create and update.
//
// The domain-conflict message names no organization. The underlying error
// identifies the organization already holding the domain, and returning that
// would disclose another tenant's organization ID to anyone able to guess a
// domain name.
func sendConfigValidationError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, ErrInvalidEntityID):
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			fmt.Sprintf("invalid IdP entity ID length (must be %d-%d chars)", MinEntityIDLength, MaxEntityIDLength))
	case errors.Is(err, ErrInvalidSSOURL):
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"invalid IdP SSO URL format (must be valid http/https URL)")
	case errors.Is(err, ErrInvalidCert):
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"invalid IdP certificate (must be valid PEM formatted X.509 certificate)")
	case errors.Is(err, ErrInvalidDomains):
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			fmt.Sprintf("allowed_domains must contain between 1 and %d valid domain names", MaxAllowedDomains))
	case errors.Is(err, ErrInvalidEnvironment):
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"environment must be \"test\" or \"live\"")
	default:
		return httperr.BadRequest(c, httperr.CodeAlreadyExists,
			"one or more domains are already mapped to another SAML connection in this tenant")
	}
}

// isConfigValidationError reports whether err is one of the configuration
// failures sendConfigValidationError has a client-safe message for.
//
// Create and update both consult this so the two routes cannot drift over which
// failures are the caller's fault: a sentinel missing from one of them would be
// reported as a 500, telling an administrator the engine is broken when their
// request was simply malformed.
func isConfigValidationError(err error) bool {
	for _, sentinel := range []error{
		ErrInvalidEntityID,
		ErrInvalidSSOURL,
		ErrInvalidCert,
		ErrInvalidDomains,
		ErrInvalidEnvironment,
		ErrDomainConflict,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// isDomainConflict reports whether err is the domain-already-mapped failure.
func isDomainConflict(err error) bool {
	return errors.Is(err, ErrDomainConflict)
}

// sendLiveKeyRequired answers 403 for a test credential addressing a live
// connection.
//
// The message names the credential rather than the permission, because the
// operator being refused usually holds the live key already and has reached for
// the wrong one. Refusing with the sentinel's own text keeps the create, update
// and delete paths saying the same thing.
func sendLiveKeyRequired(c *fiber.Ctx) error {
	return httperr.Forbidden(c, httperr.CodeLiveKeyRequired, ErrLiveKeyRequired.Error())
}

// CreateSAMLConnection handles POST .../organizations/:orgId/saml and responds
// 201 with the stored connection.
//
// Returns 409 when the organization already has a connection, 403 when a test key
// asks for a live connection — including by omitting the environment, which
// defaults to live — 400 for invalid configuration or a domain claimed by another
// connection, and 500 otherwise.
func (h *Handler) CreateSAMLConnection(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	actorID := getUserID(c)
	orgID := c.Params("orgId")

	var req CreateSAMLRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	// The organization comes from the path, not the body, so a caller cannot
	// configure SSO for an organization other than the one they addressed.
	req.OrganizationID = orgID

	resp, err := h.service.CreateSAMLConnection(c.UserContext(), tenantID, actorID, req, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrSAMLExists) {
			return httperr.Conflict(c, httperr.CodeAlreadyExists,
				"SAML connection already exists for this organization")
		}
		if errors.Is(err, ErrLiveKeyRequired) {
			return sendLiveKeyRequired(c)
		}
		if errors.Is(err, ErrOrgNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "organization not found")
		}
		if isConfigValidationError(err) {
			return sendConfigValidationError(c, err)
		}
		return httperr.SendInternal(c, "saml.create_connection", err)
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

// GetSAMLConnection handles GET .../organizations/:orgId/saml and responds 200
// with the connection.
//
// Returns 404 when the organization has no connection and 500 otherwise.
func (h *Handler) GetSAMLConnection(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	orgID := c.Params("orgId")

	resp, err := h.service.GetSAMLConnection(c.UserContext(), tenantID, orgID)
	if err != nil {
		if errors.Is(err, ErrSAMLNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "SAML connection configuration not found")
		}
		return httperr.SendInternal(c, "saml.get_connection", err)
	}

	return c.JSON(resp)
}

// UpdateSAMLConnection handles PATCH .../organizations/:orgId/saml and responds
// 200 with the updated connection. Omitted fields keep their stored values.
//
// Returns 404 when no connection exists, 403 when a test key edits a live
// connection or promotes one into live, 400 for invalid configuration or a domain
// claimed elsewhere, and 500 otherwise.
func (h *Handler) UpdateSAMLConnection(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	actorID := getUserID(c)
	orgID := c.Params("orgId")

	var req UpdateSAMLRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	resp, err := h.service.UpdateSAMLConnection(c.UserContext(), tenantID, actorID, orgID, req, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrSAMLNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "SAML connection configuration not found")
		}
		if errors.Is(err, ErrLiveKeyRequired) {
			return sendLiveKeyRequired(c)
		}
		if isConfigValidationError(err) {
			return sendConfigValidationError(c, err)
		}
		return httperr.SendInternal(c, "saml.update_connection", err)
	}

	return c.JSON(resp)
}

// DeleteSAMLConnection handles DELETE .../organizations/:orgId/saml and
// responds 200 once the connection is removed.
//
// Returns 404 when no connection exists, 403 when a test key addresses a live
// connection, and 500 otherwise.
func (h *Handler) DeleteSAMLConnection(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	actorID := getUserID(c)
	orgID := c.Params("orgId")

	err := h.service.DeleteSAMLConnection(c.UserContext(), tenantID, actorID, orgID, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrSAMLNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "SAML connection configuration not found")
		}
		if errors.Is(err, ErrLiveKeyRequired) {
			return sendLiveKeyRequired(c)
		}
		return httperr.SendInternal(c, "saml.delete_connection", err)
	}

	return c.JSON(fiber.Map{
		"message": "SAML connection deleted successfully",
		"org_id":  orgID,
	})
}

// LookupDomainSSO handles POST /v1/client/auth/domain-lookup and responds 200
// with whether the email's domain is mapped to an SSO connection and whether
// SSO is mandatory for it.
//
// Returns 400 when neither a usable email nor a domain is supplied. A lookup
// failure inside the service reaches the same branch: the detail goes to the
// log rather than to this unauthenticated-adjacent caller.
func (h *Handler) LookupDomainSSO(c *fiber.Ctx) error {
	tenantID := getTenantID(c)

	var req DomainLookupRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	resp, err := h.service.LookupDomainSSO(c.UserContext(), tenantID, req)
	if err != nil {
		log.Printf("[error] %s %s saml.domain_lookup: %v", c.Method(), c.Path(), err)
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"email or valid domain is required")
	}

	return c.JSON(resp)
}

// ProcessACS handles POST /v1/saml/acs, the Assertion Consumer Service that
// identity providers post SAML responses to.
//
// The payload is read from the JSON body or, as identity providers actually
// send it, from an HTTP-POST-binding form field.
//
// A validated assertion is carried on a real session: the refresh cookie is set
// and, when the assertion's RelayState names a destination the tenant has
// registered, the browser is redirected there with the access token in the URL
// fragment. Otherwise the token is returned in the body with 200.
//
// The redirect is what makes enterprise SSO usable at all. The user's browser
// arrives here by form POST from the identity provider, so a body response
// leaves them looking at raw JSON on the authentication host with no way onward
// to the application they were trying to reach.
//
// Returns 400 when no assertion is present and 403 when the assertion does not
// validate. The rejection reason is never itemized: this endpoint takes
// unauthenticated input, and distinguishing "unknown domain" from "malformed
// XML" from "provisioning failed" would let anyone probe the tenant's SSO
// configuration by posting crafted assertions.
func (h *Handler) ProcessACS(c *fiber.Ctx) error {
	var req ACSRequest
	if err := c.BodyParser(&req); err != nil {
		req.SAMLResponse = c.FormValue("SAMLResponse")
		req.RelayState = c.FormValue("RelayState")
	}

	if req.SAMLResponse == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "missing SAMLResponse payload")
	}

	// The tenant is not passed in: this endpoint is unauthenticated, and the
	// service derives the tenant from the assertion's issuer.
	result, err := h.service.ProcessACS(c.UserContext(), req.SAMLResponse, req.RelayState, c.IP(), c.Get("User-Agent"))
	if err != nil {
		log.Printf("[error] %s %s saml.process_acs: %v", c.Method(), c.Path(), err)
		return httperr.Forbidden(c, httperr.CodeForbidden,
			"SAML assertion could not be validated for this service provider")
	}

	tenantID := result.User.TenantID
	// The environment comes from the provisioned user rather than from the request:
	// this endpoint is unauthenticated, so there is no key to read one from, and the
	// SAML connection already decided which environment the account belongs to.
	environment := string(result.User.Environment)

	// The cookie lifetime comes from tenant policy while the session row was
	// created with the deployment default, matching the password and social paths
	// rather than diverging from them.
	h.cookies.SetRefreshToken(c, tenantID, environment, result.RefreshToken,
		h.cookies.RefreshTokenTTL(c.UserContext(), tenantID, environment))

	if result.ResumeURL != "" {
		resumeURL, err := buildResumeRedirect(result.ResumeURL, result.AccessToken)
		if err != nil {
			return httperr.SendInternal(c, "saml.acs.build_redirect", err)
		}
		return c.Redirect(resumeURL, fiber.StatusFound)
	}

	return c.JSON(fiber.Map{
		"message":      "SAML SSO authentication successful",
		"access_token": result.AccessToken,
		"token_type":   "Bearer",
		"user": fiber.Map{
			"id":             result.User.ID,
			"email":          result.User.Email,
			"email_verified": result.User.EmailVerified,
		},
		"organization": fiber.Map{
			"id":   result.Organization.ID,
			"name": result.Organization.Name,
			"slug": result.Organization.Slug,
		},
	})
}

// buildResumeRedirect returns base with the access token attached in the URL
// fragment.
//
// The token must stay in the fragment and must not be moved to the query string.
// A fragment is never transmitted to any server, so the token stays inside the
// browser that earned it. A query parameter, by contrast, is written to the
// browser's history, this server's access log, every proxy log along the way, and
// the Referer header of any cross-origin subresource the landing page loads.
//
// The URL is assembled through net/url so a destination that already carries a
// query string keeps it intact and both components are escaped; concatenating
// would produce a second "?" and fold the token into the preceding parameter's
// value.
//
// The fragment is appended literally rather than assigned to url.URL.Fragment,
// because URL.String re-escapes that field and would percent-encode the encoded
// values a second time, handing the client a mangled token. Any fragment already
// on the destination is dropped, since this slot carries the token.
//
// This mirrors the social path's redirect deliberately: a client that can read a
// Google sign-in's result can read an Okta sign-in's result without a second
// code path.
//
// Returns an error if base is not a parseable URL.
func buildResumeRedirect(base, accessToken string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	u.Fragment = ""
	u.RawFragment = ""

	frag := url.Values{}
	frag.Set("access_token", accessToken)
	frag.Set("token_type", "Bearer")

	return u.String() + "#" + frag.Encode(), nil
}

// GetSPMetadata handles GET /v1/saml/metadata/:orgId and responds 200 with the
// SAML 2.0 service-provider metadata XML for the organization.
//
// An identity provider administrator consumes this document to configure their
// side of the connection, so the ACS location it advertises is the address the
// provider will post assertions back to.
//
// WantAssertionsSigned is asserted so a conforming identity provider signs the
// assertion rather than only the response envelope.
//
// Returns 404 when the organization has no SAML connection and 500 otherwise.
func (h *Handler) GetSPMetadata(c *fiber.Ctx) error {
	orgID := c.Params("orgId")

	// This endpoint is fetched by the identity provider, which presents no Authn
	// credential, so no middleware has established a tenant. The organization ID
	// in the path is the only thing identifying the request, and it is resolved
	// to its owning tenant before any scoped query runs.
	tenantID, err := h.service.ResolveTenantByOrganization(c.UserContext(), orgID)
	if err != nil {
		if errors.Is(err, ErrSAMLNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "SAML connection configuration not found for organization")
		}
		return httperr.SendInternal(c, "saml.get_sp_metadata", err)
	}

	// Install the scope the authenticating middleware would have set, now that
	// the tenant is known. Everything below this line runs tenant-scoped.
	c.SetUserContext(privacy.NewContext(c.UserContext(), tenantID, "", ""))

	if _, err := h.service.GetSAMLConnection(c.UserContext(), tenantID, orgID); err != nil {
		if errors.Is(err, ErrSAMLNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "SAML connection configuration not found for organization")
		}
		return httperr.SendInternal(c, "saml.get_sp_metadata", err)
	}

	spEntityID := h.service.spEntityID(orgID)
	acsURL := h.service.AssertionConsumerURL()

	xmlMetadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="%s" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>`, spEntityID, acsURL)

	c.Set("Content-Type", "application/xml")
	c.Set("Cache-Control", metadataCacheControl)
	return c.SendString(xmlMetadata)
}
