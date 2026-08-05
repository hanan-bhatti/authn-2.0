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
	"strings"

	"github.com/gofiber/fiber/v2"
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

	// Organization SAML Management Endpoints
	clientGroup.Post("/organizations/:orgId/saml", h.CreateSAMLConnection)
	clientGroup.Get("/organizations/:orgId/saml", h.GetSAMLConnection)
	clientGroup.Patch("/organizations/:orgId/saml", h.UpdateSAMLConnection)
	clientGroup.Delete("/organizations/:orgId/saml", h.DeleteSAMLConnection)
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

// Handlers Implementation

func (h *Handler) CreateSAMLConnection(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	actorID := getUserID(c)
	orgID := c.Params("orgId")

	var req CreateSAMLRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request JSON body"})
	}

	req.OrganizationID = orgID

	resp, err := h.service.CreateSAMLConnection(c.UserContext(), tenantID, actorID, req, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrSAMLExists) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": err.Error()})
		}
		if errors.Is(err, ErrInvalidEntityID) || errors.Is(err, ErrInvalidSSOURL) || errors.Is(err, ErrInvalidCert) || errors.Is(err, ErrInvalidDomains) || strings.Contains(err.Error(), "already mapped") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

func (h *Handler) GetSAMLConnection(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	orgID := c.Params("orgId")

	resp, err := h.service.GetSAMLConnection(c.UserContext(), tenantID, orgID)
	if err != nil {
		if errors.Is(err, ErrSAMLNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "SAML connection configuration not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(resp)
}

func (h *Handler) UpdateSAMLConnection(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	actorID := getUserID(c)
	orgID := c.Params("orgId")

	var req UpdateSAMLRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request JSON body"})
	}

	resp, err := h.service.UpdateSAMLConnection(c.UserContext(), tenantID, actorID, orgID, req, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrSAMLNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "SAML connection configuration not found"})
		}
		if errors.Is(err, ErrInvalidEntityID) || errors.Is(err, ErrInvalidSSOURL) || errors.Is(err, ErrInvalidCert) || errors.Is(err, ErrInvalidDomains) || strings.Contains(err.Error(), "already mapped") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
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
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "SAML connection configuration not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request JSON body"})
	}

	resp, err := h.service.LookupDomainSSO(c.UserContext(), tenantID, req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing SAMLResponse payload"})
	}

	userObj, orgObj, err := h.service.ProcessACS(c.UserContext(), tenantID, req.SAMLResponse, c.IP(), c.Get("User-Agent"))
	if err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
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
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "SAML connection configuration not found for organization"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
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
