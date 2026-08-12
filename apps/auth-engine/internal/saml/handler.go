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

	"github.com/gofiber/fiber/v2"
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
}

// NewHandler constructs a Handler bound to service.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
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
	default:
		return httperr.BadRequest(c, httperr.CodeAlreadyExists,
			"one or more domains are already mapped to another SAML connection in this tenant")
	}
}

// isDomainConflict reports whether err is the domain-already-mapped failure.
func isDomainConflict(err error) bool {
	return errors.Is(err, ErrDomainConflict)
}

// CreateSAMLConnection handles POST .../organizations/:orgId/saml and responds
// 201 with the stored connection.
//
// Returns 409 when the organization already has a connection, 400 for invalid
// configuration or a domain claimed by another connection, and 500 otherwise.
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
		if errors.Is(err, ErrOrgNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "organization not found")
		}
		if errors.Is(err, ErrInvalidEntityID) || errors.Is(err, ErrInvalidSSOURL) || errors.Is(err, ErrInvalidCert) || errors.Is(err, ErrInvalidDomains) || isDomainConflict(err) {
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
// Returns 404 when no connection exists, 400 for invalid configuration or a
// domain claimed elsewhere, and 500 otherwise.
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
		if errors.Is(err, ErrInvalidEntityID) || errors.Is(err, ErrInvalidSSOURL) || errors.Is(err, ErrInvalidCert) || errors.Is(err, ErrInvalidDomains) || isDomainConflict(err) {
			return sendConfigValidationError(c, err)
		}
		return httperr.SendInternal(c, "saml.update_connection", err)
	}

	return c.JSON(resp)
}

// DeleteSAMLConnection handles DELETE .../organizations/:orgId/saml and
// responds 200 once the connection is removed.
//
// Returns 404 when no connection exists and 500 otherwise.
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
// identity providers post SAML responses to. It responds 200 with the
// authenticated user and their organization.
//
// The payload is read from the JSON body or, as identity providers actually
// send it, from an HTTP-POST-binding form field.
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
	userObj, orgObj, err := h.service.ProcessACS(c.UserContext(), req.SAMLResponse, c.IP(), c.Get("User-Agent"))
	if err != nil {
		log.Printf("[error] %s %s saml.process_acs: %v", c.Method(), c.Path(), err)
		return httperr.Forbidden(c, httperr.CodeForbidden,
			"SAML assertion could not be validated for this service provider")
	}

	return c.JSON(fiber.Map{
		"message": "SAML SSO authentication successful",
		"user": fiber.Map{
			"id":             userObj.ID,
			"email":          userObj.Email,
			"email_verified": userObj.EmailVerified,
		},
		"organization": fiber.Map{
			"id":   orgObj.ID,
			"name": orgObj.Name,
			"slug": orgObj.Slug,
		},
	})
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
