/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/handler.go
 * Tier: HTTP Controller Layer / Fiber Endpoints
 *
 * Description: Fiber HTTP handlers exposing Client (/v1/client/organizations/:orgId/saml),
 *              Domain Lookup (/v1/client/auth/domain-lookup), Assertion Consumer Service (/v1/saml/acs),
 *              and Service Provider Metadata (/v1/saml/metadata/:orgId) REST API endpoints (FR-16).
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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes registers all SAML configuration, domain lookup, ACS, and metadata routes.
func (h *Handler) RegisterRoutes(app *fiber.App, pkMiddleware fiber.Handler, adminMiddleware fiber.Handler) {
	// Public / Unauthenticated SAML Execution Endpoints
	app.Post("/v1/saml/acs", h.ProcessACS)
	app.Get("/v1/saml/metadata/:orgId", h.GetSPMetadata)

	// Client Domain Lookup Endpoint (/v1/client/auth/domain-lookup)
	clientGroup := app.Group("/v1/client", pkMiddleware)
	clientGroup.Post("/auth/domain-lookup", h.LookupDomainSSO)

	// Organization SAML Management Endpoints (Client Publishable Key & Admin Secret Key)
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

func getTenantID(c *fiber.Ctx) string {
	if val, ok := c.Locals("tenantID").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("tenant_id").(string); ok && val != "" {
		return val
	}
	return "tnt_default"
}

func getUserID(c *fiber.Ctx) string {
	return rbac.ExtractUserID(c)
}

// sendConfigValidationError maps SAML config-validation failures onto static,
// client-safe prose for the 400 branch shared by create and update.
//
// Note the domain-conflict arm: the previous code returned err.Error() verbatim,
// which echoed the *other* organization's ID back to the caller
// ("domain 'x' is already mapped to organization 'org_abc123'") — an org-ID
// disclosure across the tenant. The message here is deliberately generic.
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
		// Kept at 400 (not 409) to preserve the existing status for this branch.
		return httperr.BadRequest(c, httperr.CodeAlreadyExists,
			"one or more domains are already mapped to another SAML connection in this tenant")
	}
}

// isDomainConflict reports whether err is the "domain already mapped" failure.
//
// service.go wraps ErrDomainConflict with %w at both construction sites, so the
// sentinel check is sufficient and there is no string matching left here.
func isDomainConflict(err error) bool {
	return errors.Is(err, ErrDomainConflict)
}

// Handlers Implementation

func (h *Handler) CreateSAMLConnection(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	actorID := getUserID(c)
	orgID := c.Params("orgId")

	var req CreateSAMLRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	req.OrganizationID = orgID

	resp, err := h.service.CreateSAMLConnection(c.UserContext(), tenantID, actorID, req, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrSAMLExists) {
			return httperr.Conflict(c, httperr.CodeAlreadyExists,
				"SAML connection already exists for this organization")
		}
		if errors.Is(err, ErrInvalidEntityID) || errors.Is(err, ErrInvalidSSOURL) || errors.Is(err, ErrInvalidCert) || errors.Is(err, ErrInvalidDomains) || isDomainConflict(err) {
			return sendConfigValidationError(c, err)
		}
		return httperr.SendInternal(c, "saml.create_connection", err)
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

func (h *Handler) GetSAMLConnection(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
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

func (h *Handler) UpdateSAMLConnection(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
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

func (h *Handler) DeleteSAMLConnection(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
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

func (h *Handler) LookupDomainSSO(c *fiber.Ctx) error {
	tenantID := getTenantID(c)

	var req DomainLookupRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	resp, err := h.service.LookupDomainSSO(c.UserContext(), tenantID, req)
	if err != nil {
		// This branch collapses two very different failures: a caller-fixable
		// bad request, and an internal connection-query failure that used to
		// return raw ent/SQL text under a 400. The status is preserved, but the
		// detail now only goes to the log.
		log.Printf("[error] %s %s saml.domain_lookup: %v", c.Method(), c.Path(), err)
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"email or valid domain is required")
	}

	return c.JSON(resp)
}

func (h *Handler) ProcessACS(c *fiber.Ctx) error {
	tenantID := getTenantID(c)

	var req ACSRequest
	if err := c.BodyParser(&req); err != nil {
		// Fallback to form value
		req.SAMLResponse = c.FormValue("SAMLResponse")
		req.RelayState = c.FormValue("RelayState")
	}

	if req.SAMLResponse == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "missing SAMLResponse payload")
	}

	userObj, orgObj, err := h.service.ProcessACS(c.UserContext(), tenantID, req.SAMLResponse, c.IP(), c.Get("User-Agent"))
	if err != nil {
		// Unauthenticated endpoint: the assertion-rejection reason is never
		// itemized to the caller. The prior code returned err.Error() here,
		// which exposed XML parser output, the unmatched email domain, and
		// wrapped ent errors from JIT provisioning to anyone POSTing to /acs.
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

func (h *Handler) GetSPMetadata(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	orgID := c.Params("orgId")

	_, err := h.service.GetSAMLConnection(c.UserContext(), tenantID, orgID)
	if err != nil {
		if errors.Is(err, ErrSAMLNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "SAML connection configuration not found for organization")
		}
		return httperr.SendInternal(c, "saml.get_sp_metadata", err)
	}

	spEntityID := fmt.Sprintf("https://authn.com/saml/sp/%s", orgID)
	acsURL := fmt.Sprintf("http://localhost:8080/v1/saml/acs")

	xmlMetadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="%s" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>`, spEntityID, acsURL)

	c.Set("Content-Type", "application/xml")
	c.Set("Cache-Control", "public, max-age=3600")
	return c.SendString(xmlMetadata)
}
