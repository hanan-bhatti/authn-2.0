/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/platform/handler.go
 * Tier: HTTP Handler Layer / Hosted Control Plane
 *
 * The self-serve front door: /v1/platform/tenants.
 *
 * A customer who has signed up on the platform tenant provisions a tenant of
 * their own here and receives its first API key pair. Every route in this file
 * sits behind middleware.RequirePlatformAuth, which establishes that the caller
 * is a verified member of the platform tenant, and takes the caller's identity
 * from the request locals that guard populates — never from the request body.
 *
 * Security Notice:
 *   - The raw publishable and secret keys appear in the creation response and
 *     nowhere else. They are never logged, and only their hashes are stored.
 *   - Provisioning is idempotent by slug at the service layer, which is right for
 *     a container entrypoint and wrong for a public endpoint: handing back an
 *     existing tenant would let a caller claim ownership of somebody else's. A
 *     slug already in use is refused here instead.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package platform

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/provisioning"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
)

const (
	// provisionBudget is how many tenants one platform user may create per the
	// limiter's configured window.
	//
	// The window is the limiter's, not this package's, so the budget is expressed
	// as a count rather than a rate: a deployment tunes the period once and every
	// metered operation follows it. A handful is generous for the legitimate case
	// — a customer sets up one tenant, occasionally a second for staging — while
	// still bounding what one signup can spend of the database.
	provisionBudget = 5

	// maxNameLength bounds the tenant and application display names. The schema
	// only requires non-empty, so without a bound here a self-serve caller
	// decides how much text the database stores.
	maxNameLength = 200

	// maxURIListLength and maxURILength bound the initial redirect and CORS
	// allowlists. Both are stored as JSON columns, so an unbounded list is a
	// write amplification anyone with a signup can trigger.
	maxURIListLength = 20
	maxURILength     = 2048
)

// Handler serves the hosted control plane.
type Handler struct {
	// provisioner creates the tenant, its first application, the key pair and the
	// system roles.
	provisioner *provisioning.Service
	// repo records and reads which platform user owns which tenant.
	repo *Repository
	// limiter meters provisioning per platform user. Nil disables metering, which
	// is for tests only — the endpoint is reachable by anyone who can sign up.
	limiter *ratelimit.Limiter
	// platformTenantSlug is refused as a customer slug, so no customer tenant can
	// impersonate the control plane in a URL.
	platformTenantSlug string
}

// NewHandler constructs the control-plane handler.
//
// platformTenantSlug is added to the provisioner's reserved list rather than
// hardcoded there: which slug the control plane occupies is deployment
// configuration, and the provisioning package must not have to know it.
func NewHandler(provisioner *provisioning.Service, repo *Repository, limiter *ratelimit.Limiter, platformTenantSlug string) *Handler {
	return &Handler{
		provisioner:        provisioner,
		repo:               repo,
		limiter:            limiter,
		platformTenantSlug: strings.TrimSpace(strings.ToLower(platformTenantSlug)),
	}
}

// RegisterRoutes mounts the control plane behind platformMiddleware.
//
// A nil guard mounts nothing. These routes provision tenants and mint API keys
// on behalf of whoever the guard identified, so an unguarded registration would
// expose that to anonymous callers; Fiber also accepts a nil handler at
// registration and only dereferences it on the first request, turning the
// mistake into a router panic rather than a status code.
func (h *Handler) RegisterRoutes(app *fiber.App, platformMiddleware fiber.Handler) {
	if platformMiddleware == nil {
		return
	}

	group := app.Group("/v1/platform", platformMiddleware)
	group.Post("/tenants", h.CreateTenant)
	group.Get("/tenants", h.ListTenants)
}

// createTenantRequest is the provisioning payload.
//
// Notably absent is any identifier for the owner: ownership is attributed to the
// caller the guard resolved. Accepting one would let any platform member
// provision a tenant into another member's account.
type createTenantRequest struct {
	// Name is the organization name. Required.
	Name string `json:"name"`
	// Slug is the URL identifier. Derived from Name when omitted.
	Slug string `json:"slug"`
	// Environment is "test" or "live" for the first application and key pair.
	// Defaults to "test".
	Environment string `json:"environment"`
	// ApplicationName labels the first application. Defaults to "Default".
	ApplicationName string `json:"application_name"`
	// RedirectURIs is the initial exact-match OAuth redirect allowlist.
	RedirectURIs []string `json:"redirect_uris"`
	// AllowedCorsOrigins is the initial browser-origin allowlist.
	AllowedCorsOrigins []string `json:"allowed_cors_origins"`
}

// CreateTenant provisions a tenant owned by the calling platform user.
//
// POST /v1/platform/tenants
//
// Answers 201 with the tenant, its first application and the raw key pair; 400
// for an unusable name, slug or environment; 409 when the slug is taken; 429 when
// the caller has exhausted their provisioning budget.
func (h *Handler) CreateTenant(c *fiber.Ctx) error {
	platformTenantID, err := middleware.RequireTenantID(c)
	if err != nil {
		return err
	}
	ownerUserID := middleware.PlatformUserID(c)
	if ownerUserID == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"platform caller could not be identified")
	}

	var req createTenantRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	if verr := validateCreateRequest(&req); verr != "" {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, verr)
	}

	if limitErr := h.checkBudget(c, ownerUserID); limitErr != nil {
		return limitErr
	}

	result, err := h.provisioner.Provision(c.UserContext(), provisioning.Request{
		Name:               req.Name,
		Slug:               req.Slug,
		Environment:        req.Environment,
		ApplicationName:    req.ApplicationName,
		RedirectURIs:       req.RedirectURIs,
		AllowedCorsOrigins: req.AllowedCorsOrigins,
	}, provisioning.Options{
		ReservedSlugs: h.reservedSlugs(),
	})
	if err != nil {
		return h.sendProvisionError(c, err)
	}

	// Idempotency is a service-layer property that suits a container entrypoint
	// re-running its own provisioning. On a public endpoint it would be a
	// vulnerability: the caller would be handed the tenant that already owns this
	// slug, and the ownership row written below would give them a claim on
	// somebody else's data. The slug is simply unavailable.
	if result.AlreadyExisted {
		return httperr.Conflict(c, httperr.CodeAlreadyExists,
			"that tenant slug is already in use: choose another")
	}

	if err := h.repo.RecordOwnership(c.UserContext(), platformTenantID, ownerUserID, result.TenantID); err != nil {
		// The tenant exists at this point and the caller is about to be told it
		// does not, which is the least bad of the available outcomes: reporting
		// success would hand out keys for a tenant that appears in nobody's list
		// and can never be administered. The orphan is visible in the tenants
		// table and its slug is now taken, so a retry with the same slug returns
		// the 409 above rather than silently repairing itself.
		return httperr.SendInternal(c, "platform.create_tenant.record_ownership", err)
	}

	body := fiber.Map{
		"tenant": fiber.Map{
			"id":          result.TenantID,
			"name":        result.TenantName,
			"slug":        result.TenantSlug,
			"environment": result.Environment,
		},
		"application": fiber.Map{
			"id":   result.ApplicationID,
			"name": applicationNameOf(&req),
		},
		"roles_installed": result.RolesInstalled,
		"publishable_key": result.PublishableKey,
		"secret_key":      result.SecretKey,
		"message": "store the secret key now: it is shown only in this response and only its hash is retained. " +
			"the publishable key is safe to ship to a browser; the secret key must never leave a server.",
	}
	return c.Status(fiber.StatusCreated).JSON(body)
}

// ListTenants returns the tenants the calling platform user owns.
//
// GET /v1/platform/tenants
func (h *Handler) ListTenants(c *fiber.Ctx) error {
	ownerUserID := middleware.PlatformUserID(c)
	if ownerUserID == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"platform caller could not be identified")
	}

	owned, err := h.repo.OwnedTenants(c.UserContext(), ownerUserID)
	if err != nil {
		return httperr.SendInternal(c, "platform.list_tenants", err)
	}

	items := make([]fiber.Map, 0, len(owned))
	for _, t := range owned {
		items = append(items, fiber.Map{
			"id":          t.ID,
			"name":        t.Name,
			"slug":        t.Slug,
			"role":        t.Role,
			"acquired_at": t.AcquiredAt,
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"tenants": items,
		"count":   len(items),
	})
}

// reservedSlugs returns the deployment-specific slugs a customer may not claim.
func (h *Handler) reservedSlugs() []string {
	if h.platformTenantSlug == "" {
		return nil
	}
	return []string{h.platformTenantSlug}
}

// checkBudget meters provisioning against the caller's per-window allowance,
// returning nil when the request may proceed.
//
// The key is the user, not the IP: signing up is free, so an IP budget alone
// would be defeated by one more signup, while a per-user budget costs an
// attacker a fresh verified email address per bucket.
func (h *Handler) checkBudget(c *fiber.Ctx, ownerUserID string) error {
	if h.limiter == nil {
		return nil
	}

	key := fmt.Sprintf("platform:provision:%s", ownerUserID)
	allowed, retryAfter, err := h.limiter.CheckWithLimit(c.UserContext(), key, provisionBudget)
	if err != nil {
		if errors.Is(err, ratelimit.ErrRedisUnavailable) {
			return httperr.Send(c, fiber.StatusServiceUnavailable, httperr.CodeServiceUnavailable,
				"rate limit service unavailable")
		}
		return httperr.SendInternal(c, "platform.create_tenant.ratelimit", err)
	}
	if !allowed {
		if retryAfter > 0 {
			c.Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
		}
		return httperr.TooManyRequests(c, httperr.CodeRateLimited,
			"too many tenants provisioned from this account: please try again later")
	}
	return nil
}

// sendProvisionError maps a provisioning failure onto a status code.
//
// The sentinel errors are input problems and become 400s. A uniqueness conflict
// means a concurrent caller won the same slug between the service's existence
// check and its insert, which is the same condition as an already-used slug and
// gets the same 409. Anything else is a storage failure.
func (h *Handler) sendProvisionError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, provisioning.ErrInvalidName):
		return httperr.BadRequest(c, httperr.CodeValidationFailed, provisioning.ErrInvalidName.Error())
	case errors.Is(err, provisioning.ErrInvalidSlug):
		return httperr.BadRequest(c, httperr.CodeValidationFailed, provisioning.ErrInvalidSlug.Error())
	case errors.Is(err, provisioning.ErrReservedSlug):
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"that tenant slug is reserved: choose another")
	case errors.Is(err, provisioning.ErrInvalidEnvironment):
		return httperr.BadRequest(c, httperr.CodeValidationFailed, provisioning.ErrInvalidEnvironment.Error())
	case ent.IsConstraintError(err):
		return httperr.Conflict(c, httperr.CodeAlreadyExists,
			"that tenant slug is already in use: choose another")
	default:
		return httperr.SendInternal(c, "platform.create_tenant", err)
	}
}

// validateCreateRequest trims the payload in place and returns the first problem
// with it, or "" when it is acceptable.
//
// The bounds here are about what a self-serve caller may cause to be stored; the
// shape of a name or slug is the provisioning service's judgement and is left to
// it, so the two do not disagree about what a valid tenant looks like.
func validateCreateRequest(req *createTenantRequest) string {
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.TrimSpace(req.Slug)
	req.Environment = strings.TrimSpace(req.Environment)
	req.ApplicationName = strings.TrimSpace(req.ApplicationName)

	if req.Name == "" {
		return "name is required"
	}
	if len(req.Name) > maxNameLength {
		return fmt.Sprintf("name must be at most %d characters", maxNameLength)
	}
	if len(req.ApplicationName) > maxNameLength {
		return fmt.Sprintf("application_name must be at most %d characters", maxNameLength)
	}

	if problem := validateURIList("redirect_uris", req.RedirectURIs); problem != "" {
		return problem
	}
	if problem := validateURIList("allowed_cors_origins", req.AllowedCorsOrigins); problem != "" {
		return problem
	}
	return ""
}

// validateURIList bounds one of the allowlists by entry count and entry length.
func validateURIList(field string, values []string) string {
	if len(values) > maxURIListLength {
		return fmt.Sprintf("%s must contain at most %d entries", field, maxURIListLength)
	}
	for _, v := range values {
		if len(v) > maxURILength {
			return fmt.Sprintf("each %s entry must be at most %d characters", field, maxURILength)
		}
	}
	return ""
}

// applicationNameOf reports the application name the provisioner will have used,
// so the response names the application the caller actually got rather than the
// empty string they may have sent.
func applicationNameOf(req *createTenantRequest) string {
	if req.ApplicationName != "" {
		return req.ApplicationName
	}
	return "Default"
}
