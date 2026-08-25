/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/useradmin/handler.go
 * Tier: HTTP Delivery Layer (Fiber Handlers)
 *
 * The tenant administrator's user directory: listing and filtering accounts,
 * reading one account's sign-in surface, editing a profile, and the lifecycle
 * actions — ban, suspend, reinstate, retire, restore, forced sign-out, and
 * administrative email verification.
 *
 * Every response is built from an explicit field projection rather than by
 * serialising the ORM row. A row carries columns no caller should receive and
 * gains more over time; a projection means a new column appears in this API only
 * when someone adds it here on purpose.
 *
 * Query parameters are validated at this boundary rather than passed through.
 * The repository clamps and allowlists what it receives as a safety net, but a
 * caller who mistypes a filter should be told so instead of being served a
 * quietly different page.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package useradmin

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	entuser "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/username"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/validator"
)

// maxReasonLength bounds the operator-supplied reason recorded on an audit row.
// The value lands in a JSON column read back on every audit query, so it is
// bounded here rather than left to the caller.
const maxReasonLength = 500

// Handler serves the administrative user-directory endpoints.
type Handler struct {
	// svc applies the account lifecycle rules behind every endpoint.
	svc *Service
}

// NewHandler returns a handler bound to svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// RegisterRoutes mounts the user administration endpoints under /v1/admin/users.
//
// adminMiddleware is attached per route rather than to the group. Group
// middleware applies to every path beneath its prefix, and /v1/admin/users is
// also the prefix of the role-assignment routes the RBAC package registers — a
// prefix-wide guard here would authenticate those requests a second time,
// repeating a key lookup for no gain.
func (h *Handler) RegisterRoutes(app *fiber.App, adminMiddleware fiber.Handler) {
	g := app.Group("/v1/admin/users")

	g.Get("", guarded(adminMiddleware, h.ListUsers)...)
	g.Get("/", guarded(adminMiddleware, h.ListUsers)...)
	g.Get("/:user_id", guarded(adminMiddleware, h.GetUser)...)
	g.Patch("/:user_id", guarded(adminMiddleware, h.UpdateUser)...)
	g.Delete("/:user_id", guarded(adminMiddleware, h.DeleteUser)...)

	g.Post("/:user_id/ban", guarded(adminMiddleware, h.BanUser)...)
	g.Post("/:user_id/unban", guarded(adminMiddleware, h.UnbanUser)...)
	g.Post("/:user_id/suspend", guarded(adminMiddleware, h.SuspendUser)...)
	g.Post("/:user_id/unsuspend", guarded(adminMiddleware, h.UnsuspendUser)...)
	g.Post("/:user_id/restore", guarded(adminMiddleware, h.RestoreUser)...)
	g.Post("/:user_id/logout", guarded(adminMiddleware, h.ForceLogout)...)
	g.Post("/:user_id/verify-email", guarded(adminMiddleware, h.VerifyEmail)...)
}

// guarded returns the handler chain for one route, prefixed by guard when a guard
// was supplied. A nil guard is accepted so tests can mount the routes without
// standing up authentication.
func guarded(guard, handler fiber.Handler) []fiber.Handler {
	if guard == nil {
		return []fiber.Handler{handler}
	}
	return []fiber.Handler{guard, handler}
}

// UserDTO is the account representation this API returns.
//
// The fields are enumerated rather than inherited from the ORM row, which also
// carries the password hash, the outstanding email-verification and magic-link
// tokens, and the recovery lockout counters. None of those belong in a directory
// listing, and enumerating the ones that do means a column added to the schema
// later does not appear here by accident.
type UserDTO struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Username      string `json:"username,omitempty"`
	Name          string `json:"name,omitempty"`
	AvatarURL     string `json:"avatar_url,omitempty"`
	PhoneNumber   string `json:"phone_number,omitempty"`
	PhoneVerified bool   `json:"phone_verified"`
	Locale        string `json:"locale,omitempty"`
	Status        string `json:"status"`
	Environment   string `json:"environment"`
	// HasPassword reports whether the account can sign in with a password at all.
	// A social-only account has no hash, and telling the two apart is what stops
	// an operator sending a password reset to someone who has never had one.
	HasPassword bool `json:"has_password"`
	// SecurityReviewRequired marks an account flagged by the recovery flow.
	SecurityReviewRequired bool                   `json:"security_review_required"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt              time.Time              `json:"created_at"`
	UpdatedAt              time.Time              `json:"updated_at"`
	LastSignInAt           *time.Time             `json:"last_sign_in_at,omitempty"`
	// DeletedAt is set on a retired account. Present so a console can render a
	// restore action instead of showing the account as ordinary.
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// UserDetailDTO adds the sign-in surface an operator needs before acting.
type UserDetailDTO struct {
	UserDTO
	// ActiveSessions is how many sessions a forced sign-out would end.
	ActiveSessions int `json:"active_sessions"`
	// SocialProviders and TwoFactorTypes are always present, empty rather than
	// omitted, so a client can distinguish "none enrolled" from a field this
	// version of the API did not send.
	SocialProviders []string `json:"social_providers"`
	TwoFactorTypes  []string `json:"two_factor_types"`
}

// newUserDTO projects one row.
func newUserDTO(u *ent.User) UserDTO {
	dto := UserDTO{
		ID:                     u.ID,
		Email:                  u.Email,
		EmailVerified:          u.EmailVerified,
		Name:                   u.Name,
		AvatarURL:              u.AvatarURL,
		PhoneNumber:            u.PhoneNumber,
		PhoneVerified:          u.PhoneVerified,
		Locale:                 u.Locale,
		Status:                 string(u.Status),
		Environment:            string(u.Environment),
		HasPassword:            u.PasswordHash != "",
		SecurityReviewRequired: u.SecurityReviewRequired,
		// The account's own attributes, with the engine's verification state and
		// security-answer hashes left out. An operator reading a console has no use
		// for either, and answer hashes are low-entropy enough that showing them is
		// close to showing the answers.
		Metadata:     user.PublicMetadata(u.Metadata),
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
		LastSignInAt: u.LastSignInAt,
		DeletedAt:    u.DeletedAt,
	}
	if u.Username != nil {
		dto.Username = *u.Username
	}
	return dto
}

// newUserDetailDTO projects one account and its sign-in surface.
func newUserDetailDTO(d *Detail) UserDetailDTO {
	return UserDetailDTO{
		UserDTO:         newUserDTO(d.User),
		ActiveSessions:  d.ActiveSessions,
		SocialProviders: nonNil(d.SocialProviders),
		TwoFactorTypes:  nonNil(d.TwoFactorTypes),
	}
}

// nonNil returns an empty slice for a nil one, so the field serialises as [] and
// a client need not handle null.
func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// ListUsers handles GET /v1/admin/users.
//
// It answers 200 with one page of the caller's tenant, 400 for an unusable
// filter, and 500 when the query fails. The effective limit and offset are
// echoed because the server clamps the requested page size: a caller who asked
// for a thousand rows needs to know how many it may actually have received.
func (h *Handler) ListUsers(c *fiber.Ctx) error {
	if _, okTenant := middleware.RequireTenantID(c); !okTenant {
		return nil
	}

	filter, bad := parseListFilter(c)
	if bad != nil {
		return bad.send(c)
	}

	users, total, err := h.svc.List(c.UserContext(), filter)
	if err != nil {
		return httperr.SendInternal(c, "useradmin.list", err)
	}

	dtos := make([]UserDTO, 0, len(users))
	for _, u := range users {
		dtos = append(dtos, newUserDTO(u))
	}

	limit, offset := filter.page()
	return c.JSON(fiber.Map{
		"users":  dtos,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetUser handles GET /v1/admin/users/:user_id, answering 200 with the account
// and its sign-in surface, 404 when no such account exists in the caller's
// tenant, and 500 when a supporting query fails.
func (h *Handler) GetUser(c *fiber.Ctx) error {
	if _, okTenant := middleware.RequireTenantID(c); !okTenant {
		return nil
	}

	userID := c.Params("user_id")
	if userID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "user_id is required")
	}

	detail, err := h.svc.Detail(c.UserContext(), userID)
	if err != nil {
		return sendServiceError(c, "useradmin.get", err)
	}

	return c.JSON(newUserDetailDTO(detail))
}

// UpdateUser handles PATCH /v1/admin/users/:user_id.
//
// Only the supplied fields change. An omitted field and a field set to null are
// both left alone; clearing a value is expressed by sending an empty string,
// which is the only form that distinguishes "remove this" from "do not touch
// this" over JSON. It answers 200 with the updated account, 400 for an
// unparseable body or an empty patch, 404 for an unknown account, 409 when the
// username is taken, 422 for a value that fails validation, and 500 otherwise.
func (h *Handler) UpdateUser(c *fiber.Ctx) error {
	tenantID, okTenant := middleware.RequireTenantID(c)
	if !okTenant {
		return nil
	}

	userID := c.Params("user_id")
	if userID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "user_id is required")
	}

	var req struct {
		Name        *string                `json:"name"`
		Username    *string                `json:"username"`
		AvatarURL   *string                `json:"avatar_url"`
		PhoneNumber *string                `json:"phone_number"`
		Locale      *string                `json:"locale"`
		Metadata    map[string]interface{} `json:"metadata"`
	}
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	patch := ProfilePatch{Metadata: req.Metadata}

	// Refused for an operator on the same footing as for the account holder. These
	// keys are what make an email address count as verified, and an operator who can
	// write the digest can mark an address confirmed that the user never confirmed —
	// which is the one thing an audit trail of administrative email changes cannot
	// tell apart from a real confirmation.
	if reserved := user.FirstReservedMetadataKey(req.Metadata); reserved != "" {
		return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
			fmt.Sprintf("metadata key %q is written by the engine as part of email verification and account recovery, so it cannot be set directly — choose another key", reserved))
	}

	// Each value is sanitised against the same bounds the self-serve profile
	// endpoint applies. An administrative path that accepted what the user's own
	// path rejects would be a way around the rule rather than an exception to it.
	if req.Name != nil {
		clean, verr := validator.SanitizeString(*req.Name, 1, 100)
		if verr != nil {
			return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
				"name must be 1-100 characters and contain no markup or control characters")
		}
		patch.Name = &clean
	}
	if req.Username != nil {
		clean := strings.TrimSpace(*req.Username)
		if clean != "" {
			// Validated against the handle rules rather than the generic string
			// sanitiser, which accepts spaces, punctuation and mixed scripts. A
			// handle is compared, mentioned and placed in a URL, so a value that is
			// merely free of markup is not enough.
			if _, verr := username.Canonical(clean); verr != nil {
				return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
					username.Explain(verr))
			}
		}
		patch.Username = &clean
	}
	if req.AvatarURL != nil {
		clean, verr := validator.ValidateImageURL(*req.AvatarURL)
		if verr != nil {
			return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
				"avatar_url must be an http or https URL")
		}
		patch.AvatarURL = &clean
	}
	if req.PhoneNumber != nil {
		clean := strings.TrimSpace(*req.PhoneNumber)
		if clean != "" {
			var verr error
			clean, verr = validator.SanitizeString(clean, 5, 32)
			if verr != nil {
				return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
					"phone_number must be 5-32 characters and contain no markup or control characters")
			}
		}
		patch.PhoneNumber = &clean
	}
	if req.Locale != nil {
		clean, verr := validator.SanitizeString(*req.Locale, 2, 20)
		if verr != nil {
			return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
				"locale must be 2-20 characters and contain no markup or control characters")
		}
		patch.Locale = &clean
	}

	if patch.IsEmpty() {
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"request must supply at least one field to update")
	}

	updated, err := h.svc.UpdateProfile(c.UserContext(), tenantID, userID, patch, actorFrom(c))
	if err != nil {
		return sendServiceError(c, "useradmin.update", err)
	}

	return c.JSON(newUserDTO(updated))
}

// DeleteUser handles DELETE /v1/admin/users/:user_id, retiring the account.
//
// The row is kept, so the email address stays reserved and the account can be
// restored. It answers 200, 404 for an unknown account, 409 when the account is
// already retired or the caller is acting on their own account, and 500
// otherwise.
func (h *Handler) DeleteUser(c *fiber.Ctx) error {
	tenantID, okTenant := middleware.RequireTenantID(c)
	if !okTenant {
		return nil
	}

	userID := c.Params("user_id")
	if userID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "user_id is required")
	}

	reason, bad := reasonFromBody(c)
	if bad != nil {
		return bad.send(c)
	}

	if err := h.svc.SoftDelete(c.UserContext(), tenantID, userID, reason, actorFrom(c)); err != nil {
		return sendServiceError(c, "useradmin.delete", err)
	}

	return c.JSON(fiber.Map{
		"message": "account retired",
		"user_id": userID,
	})
}

// BanUser handles POST /v1/admin/users/:user_id/ban.
func (h *Handler) BanUser(c *fiber.Ctx) error {
	return h.transition(c, "useradmin.ban", h.svc.Ban)
}

// UnbanUser handles POST /v1/admin/users/:user_id/unban.
func (h *Handler) UnbanUser(c *fiber.Ctx) error {
	return h.transition(c, "useradmin.unban", h.svc.Unban)
}

// SuspendUser handles POST /v1/admin/users/:user_id/suspend.
func (h *Handler) SuspendUser(c *fiber.Ctx) error {
	return h.transition(c, "useradmin.suspend", h.svc.Suspend)
}

// UnsuspendUser handles POST /v1/admin/users/:user_id/unsuspend.
func (h *Handler) UnsuspendUser(c *fiber.Ctx) error {
	return h.transition(c, "useradmin.unsuspend", h.svc.Unsuspend)
}

// RestoreUser handles POST /v1/admin/users/:user_id/restore.
//
// The account returns to whatever status it held when it was retired, so
// restoring a banned account leaves it banned.
func (h *Handler) RestoreUser(c *fiber.Ctx) error {
	return h.transition(c, "useradmin.restore", h.svc.Restore)
}

// transition runs one status-changing action and renders the resulting account.
//
// Each of them takes the same inputs and reports the same refusals, so they
// share one path: divergence between "ban" and "suspend" at the transport layer
// would be a difference in how a rule is reported rather than in the rule.
func (h *Handler) transition(
	c *fiber.Ctx,
	op string,
	action func(ctx context.Context, tenantID, userID, reason string, actor Actor) (*ent.User, error),
) error {
	tenantID, okTenant := middleware.RequireTenantID(c)
	if !okTenant {
		return nil
	}

	userID := c.Params("user_id")
	if userID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "user_id is required")
	}

	reason, bad := reasonFromBody(c)
	if bad != nil {
		return bad.send(c)
	}

	updated, err := action(c.UserContext(), tenantID, userID, reason, actorFrom(c))
	if err != nil {
		return sendServiceError(c, op, err)
	}

	return c.JSON(newUserDTO(updated))
}

// ForceLogout handles POST /v1/admin/users/:user_id/logout.
//
// It ends every session and refuses the account's outstanding access tokens
// without changing its status, which is the response to a suspected token theft
// on an account that has done nothing wrong. The reported count is the sessions
// that were revoked, so an operator can see whether there was anything live to
// cut off.
func (h *Handler) ForceLogout(c *fiber.Ctx) error {
	tenantID, okTenant := middleware.RequireTenantID(c)
	if !okTenant {
		return nil
	}

	userID := c.Params("user_id")
	if userID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "user_id is required")
	}

	reason, bad := reasonFromBody(c)
	if bad != nil {
		return bad.send(c)
	}

	revoked, err := h.svc.ForceLogout(c.UserContext(), tenantID, userID, reason, actorFrom(c))
	if err != nil {
		return sendServiceError(c, "useradmin.logout", err)
	}

	return c.JSON(fiber.Map{
		"message":          "sessions revoked",
		"user_id":          userID,
		"sessions_revoked": revoked,
	})
}

// VerifyEmail handles POST /v1/admin/users/:user_id/verify-email, marking the
// address verified on the administrator's authority for the support case where
// the owner cannot receive mail at it. It answers 409 when the address is
// already verified.
func (h *Handler) VerifyEmail(c *fiber.Ctx) error {
	tenantID, okTenant := middleware.RequireTenantID(c)
	if !okTenant {
		return nil
	}

	userID := c.Params("user_id")
	if userID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "user_id is required")
	}

	updated, err := h.svc.VerifyEmail(c.UserContext(), tenantID, userID, actorFrom(c))
	if err != nil {
		return sendServiceError(c, "useradmin.verify_email", err)
	}

	return c.JSON(newUserDTO(updated))
}

// refusal is a client-facing rejection produced by a validation helper and
// written by the handler that received it.
//
// Helpers report a refusal rather than writing it. A handler must return nil
// once it has written a response, or the global error handler answers the
// request a second time — so "already answered" and "nothing wrong" would be
// the same return value, and a caller that forgot to check would proceed as if
// the input had passed. A concrete pointer cannot be mistaken for either.
type refusal struct {
	// status and code are the HTTP status and the machine-readable code.
	status int
	code   httperr.Code
	// message is the prose reason, written for the caller to read.
	message string
}

// Error lets a refusal travel as an error where one is wanted for logging.
func (r *refusal) Error() string { return r.message }

// send answers the request with r, returning what the handler should return.
func (r *refusal) send(c *fiber.Ctx) error {
	return httperr.Send(c, r.status, r.code, r.message)
}

// badFilter returns the 400 refusal used for every unusable query parameter.
func badFilter(message string) *refusal {
	return &refusal{
		status:  fiber.StatusBadRequest,
		code:    httperr.CodeValidationFailed,
		message: message,
	}
}

// parseListFilter builds a ListFilter from the query string, refusing any
// parameter that cannot be honoured.
//
// An unusable filter is refused rather than dropped. Silently ignoring
// ?status=bannned would answer a question the caller did not ask, and a console
// paging that result would report every account as unrestricted.
func parseListFilter(c *fiber.Ctx) (ListFilter, *refusal) {
	f := ListFilter{
		Search: strings.TrimSpace(c.Query("q")),
		Email:  strings.TrimSpace(c.Query("email")),
		Sort:   strings.TrimSpace(c.Query("sort")),
	}

	if status := strings.TrimSpace(c.Query("status")); status != "" {
		if err := entuser.StatusValidator(entuser.Status(status)); err != nil {
			return f, badFilter("status must be one of: active, suspended, banned, recovery_hold")
		}
		f.Status = status
	}

	verified, bad := queryBool(c, "email_verified")
	if bad != nil {
		return f, bad
	}
	f.EmailVerified = verified

	deleted, bad := queryBool(c, "deleted")
	if bad != nil {
		return f, bad
	}
	// One parameter covers both directions: deleted=true lists only retired
	// accounts, deleted=false is the default, and include_deleted asks for both.
	if deleted != nil && *deleted {
		f.OnlyDeleted = true
	}

	includeDeleted, bad := queryBool(c, "include_deleted")
	if bad != nil {
		return f, bad
	}
	if includeDeleted != nil && *includeDeleted {
		f.IncludeDeleted = true
	}

	if f.Sort != "" && !IsSortable(f.Sort) {
		return f, badFilter("sort must be one of: " + strings.Join(SortableFields(), ", "))
	}

	// An absent order and an explicit desc are the same request: a directory opens
	// newest first.
	switch order := strings.ToLower(strings.TrimSpace(c.Query("order"))); order {
	case "", "desc":
		f.Ascending = false
	case "asc":
		f.Ascending = true
	default:
		return f, badFilter("order must be asc or desc")
	}

	after, bad := queryTime(c, "created_after")
	if bad != nil {
		return f, bad
	}
	f.CreatedAfter = after

	before, bad := queryTime(c, "created_before")
	if bad != nil {
		return f, bad
	}
	f.CreatedBefore = before

	if f.CreatedAfter != nil && f.CreatedBefore != nil && f.CreatedAfter.After(*f.CreatedBefore) {
		return f, badFilter("created_after must not be later than created_before")
	}

	limit, bad := queryInt(c, "limit")
	if bad != nil {
		return f, bad
	}
	if limit != nil {
		if *limit < 1 {
			return f, badFilter("limit must be a positive integer")
		}
		f.Limit = *limit
	}

	offset, bad := queryInt(c, "offset")
	if bad != nil {
		return f, bad
	}
	if offset != nil {
		if *offset < 0 {
			return f, badFilter("offset must not be negative")
		}
		f.Offset = *offset
	}

	return f, nil
}

// queryBool reads a boolean query parameter, returning nil when absent so an
// omitted filter stays distinct from one explicitly set to false.
func queryBool(c *fiber.Ctx, key string) (*bool, *refusal) {
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		return nil, nil
	}
	switch strings.ToLower(raw) {
	case "true", "1":
		v := true
		return &v, nil
	case "false", "0":
		v := false
		return &v, nil
	default:
		return nil, badFilter(key + " must be true or false")
	}
}

// queryInt reads an integer query parameter, returning nil when absent.
func queryInt(c *fiber.Ctx, key string) (*int, *refusal) {
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		return nil, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return nil, badFilter(key + " must be an integer")
	}
	return &v, nil
}

// queryTime reads an RFC 3339 timestamp query parameter, returning nil when
// absent.
func queryTime(c *fiber.Ctx, key string) (*time.Time, *refusal) {
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, badFilter(key + " must be an RFC 3339 timestamp, e.g. 2026-01-31T00:00:00Z")
	}
	return &t, nil
}

// reasonFromBody reads the operator's optional reason for an action.
//
// The body itself is optional: these are single-purpose actions whose meaning is
// in the path, and requiring a body would make a ban fail for want of an empty
// object.
func reasonFromBody(c *fiber.Ctx) (string, *refusal) {
	if len(c.Body()) == 0 {
		return "", nil
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if err := c.BodyParser(&req); err != nil {
		return "", &refusal{
			status:  fiber.StatusBadRequest,
			code:    httperr.CodeInvalidRequestBody,
			message: "request body could not be parsed as JSON",
		}
	}

	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return "", nil
	}

	clean, err := validator.SanitizeString(reason, 1, maxReasonLength)
	if err != nil {
		return "", &refusal{
			status:  fiber.StatusUnprocessableEntity,
			code:    httperr.CodeValidationFailed,
			message: "reason must be at most 500 characters and contain no markup or control characters",
		}
	}
	return clean, nil
}

// actorFrom reads the acting administrator from the request locals set by the
// admin authentication middleware.
//
// Both admin credential kinds are read. A secret key names a key and no person;
// a console session names the administrator and no key. Recording whichever is
// present keeps every audit row attributable to something.
func actorFrom(c *fiber.Ctx) Actor {
	return Actor{
		ConsoleUserID:    localString(c, "console_user_id"),
		ConsoleUserEmail: localString(c, "console_user_email"),
		APIKeyID:         localString(c, "api_key_id"),
		AuthMethod:       localString(c, "admin_auth_method"),
		IPAddress:        c.IP(),
		UserAgent:        c.Get("User-Agent"),
		Origin:           c.Get("Origin"),
	}
}

// localString reads a string request local, returning "" when unset or of
// another type.
func localString(c *fiber.Ctx, key string) string {
	if v, ok := c.Locals(key).(string); ok {
		return v
	}
	return ""
}

// sendServiceError maps a service refusal to a status code.
//
// The state refusals are 409 rather than 400: the request is well formed and
// would have succeeded against a different account state, which is what
// separates "retry with a corrected request" from "the account is not in a state
// this action applies to".
func sendServiceError(c *fiber.Ctx, op string, err error) error {
	switch {
	case errors.Is(err, ErrUserNotFound):
		return httperr.NotFound(c, httperr.CodeNotFound, "user not found")
	case errors.Is(err, ErrRecoveryHoldActive):
		return httperr.Conflict(c, httperr.CodeConflict,
			"account is under a recovery hold and cannot be restricted until the hold expires")
	case errors.Is(err, ErrUserDeleted):
		return httperr.Conflict(c, httperr.CodeConflict,
			"account is retired; restore it before changing its status")
	case errors.Is(err, ErrNotDeleted):
		return httperr.Conflict(c, httperr.CodeConflict, "account is not retired")
	case errors.Is(err, ErrAlreadyInState):
		return httperr.Conflict(c, httperr.CodeConflict,
			"account is already in the requested state")
	case errors.Is(err, ErrNotInState):
		return httperr.Conflict(c, httperr.CodeConflict,
			"account does not hold the restriction being lifted")
	case errors.Is(err, ErrSelfAction):
		return httperr.Conflict(c, httperr.CodeConflict,
			"an administrator cannot restrict or retire their own account")
	case errors.Is(err, ErrUsernameTaken):
		return httperr.Conflict(c, httperr.CodeAlreadyExists,
			"username is already taken")
	case errors.Is(err, ErrUsernameInvalid):
		return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
			username.Explain(err))
	default:
		return httperr.SendInternal(c, op, err)
	}
}
