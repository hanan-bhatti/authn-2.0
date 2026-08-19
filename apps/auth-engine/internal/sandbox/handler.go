/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sandbox/handler.go
 * Tier: HTTP REST Route Handler Layer
 *
 * The sandbox inbox — read, list and empty the messages the test environment
 * captured — and the one endpoint that deliberately does the opposite and sends a
 * real message through the configured provider.
 *
 * The two answer different questions and neither substitutes for the other. The
 * inbox proves the engine produced the right message with the right code in it,
 * which is what a signup or a second-factor test needs and which no provider is
 * involved in. Delivery verification proves the credentials in configuration
 * reach a provider that accepts mail, which nothing captured can establish.
 *
 * Security Notice:
 *   - Captured bodies carry live verification links and one-time codes for the
 *     test environment. Reads are confined to the caller's tenant and environment
 *     by the privacy interceptor, and the inbox is refused outright to a live
 *     credential.
 *   - Delivery verification takes no recipient from the request. The address is
 *     the authenticated operator's own, so the endpoint cannot be pointed at a
 *     third party by construction rather than by validation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sandbox

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/sandboxmessage"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/sms"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// verifyAttemptsPerWindow caps how many real messages one tenant may have sent
// on its own behalf per rate-limit window.
//
// The limit is low because a higher one buys nothing: the endpoint sends to the
// operator's own address through the tenant's own provider account, so the second
// message tells them exactly what the first one did. It bounds the cost of a
// misconfigured retry loop rather than an abuse, which this endpoint does not
// open — anyone able to call it already holds the provider credentials it uses.
const verifyAttemptsPerWindow = 3

// Handler serves the sandbox inbox and delivery verification.
type Handler struct {
	store   *Store
	factory *clientfactory.ClientFactory
	cfg     *config.Config

	// emailProvider and smsProvider are the providers as configured, without the
	// sandbox wrapper. Verification exists to reach a provider, so it holds the
	// undecorated ones on purpose.
	emailProvider email.EmailProvider
	smsProvider   sms.SMSProvider

	// limiter bounds delivery verification. A nil limiter leaves it unbounded,
	// matching how the rest of the engine treats an unconfigured limiter.
	limiter *ratelimit.Limiter
}

// NewHandler returns a sandbox handler.
func NewHandler(
	store *Store,
	factory *clientfactory.ClientFactory,
	cfg *config.Config,
	emailProvider email.EmailProvider,
	smsProvider sms.SMSProvider,
) *Handler {
	return &Handler{
		store:         store,
		factory:       factory,
		cfg:           cfg,
		emailProvider: emailProvider,
		smsProvider:   smsProvider,
	}
}

// WithLimiter attaches the rate limiter that bounds delivery verification.
func (h *Handler) WithLimiter(limiter *ratelimit.Limiter) *Handler {
	h.limiter = limiter
	return h
}

// RegisterRoutes mounts the inbox and delivery verification routes.
func (h *Handler) RegisterRoutes(app *fiber.App, adminMiddleware fiber.Handler) {
	inbox := app.Group("/v1/tenant/sandbox/messages")
	inbox.Get("", adminMiddleware, h.ListMessages)
	inbox.Delete("", adminMiddleware, h.PurgeMessages)
	inbox.Get("/:id", adminMiddleware, h.GetMessage)

	delivery := app.Group("/v1/tenant/delivery")
	delivery.Post("/verify", adminMiddleware, h.VerifyDelivery)
}

// MessageDTO is a captured message as returned to clients.
//
// Body is populated only when reading a single message. A listing that carried
// every rendered document would be tens of times larger than the fields anyone
// pages through it for, and the values a harness reads — the code and the action
// link — are present either way.
type MessageDTO struct {
	ID          string                 `json:"id"`
	Channel     string                 `json:"channel"`
	Environment string                 `json:"environment"`
	Recipient   string                 `json:"recipient"`
	Subject     string                 `json:"subject,omitempty"`
	Template    string                 `json:"template,omitempty"`
	Code        string                 `json:"code,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   string                 `json:"created_at"`
	Body        string                 `json:"body,omitempty"`
}

// toDTO converts a stored message, including the body only when asked.
func toDTO(m *ent.SandboxMessage, withBody bool) MessageDTO {
	dto := MessageDTO{
		ID:          m.ID,
		Channel:     string(m.Channel),
		Environment: string(m.Environment),
		Recipient:   m.Recipient,
		Subject:     m.Subject,
		Template:    m.Template,
		Code:        m.Code,
		Metadata:    m.Metadata,
		CreatedAt:   m.CreatedAt.Format(time.RFC3339),
	}
	if withBody {
		dto.Body = m.Body
	}
	return dto
}

// requireSandboxScope returns the caller's tenant, or answers and reports false.
//
// The inbox is refused to a live credential rather than answered with an empty
// list. Nothing is ever captured outside test, so an empty list would be a true
// answer to the wrong question, and "my message is missing" is a far worse thing
// to leave an operator concluding than "you are looking at the wrong
// environment".
func requireSandboxScope(c *fiber.Ctx) (string, bool) {
	tenantID, ok := middleware.RequireTenantID(c)
	if !ok {
		return "", false
	}

	environment := middleware.GetEnvironment(c)
	if environment != string(sandboxmessage.EnvironmentTest) {
		_ = httperr.Forbidden(c, httperr.CodeForbidden,
			"the sandbox inbox exists only in the test environment; this credential addresses "+environment)
		return "", false
	}

	return tenantID, true
}

// ListMessages handles GET /v1/tenant/sandbox/messages.
func (h *Handler) ListMessages(c *fiber.Ctx) error {
	if _, ok := requireSandboxScope(c); !ok {
		return nil
	}

	filter := Filter{
		Recipient: strings.TrimSpace(c.Query("recipient")),
	}

	if channel := strings.TrimSpace(c.Query("channel")); channel != "" {
		if err := sandboxmessage.ChannelValidator(sandboxmessage.Channel(channel)); err != nil {
			return httperr.BadRequest(c, httperr.CodeValidationFailed,
				"channel must be 'email' or 'sms'")
		}
		filter.Channel = channel
	}

	if limit := c.Query("limit"); limit != "" {
		parsed, err := strconv.Atoi(limit)
		if err != nil {
			return httperr.BadRequest(c, httperr.CodeValidationFailed, "limit must be an integer")
		}
		filter.Limit = parsed
	}
	if offset := c.Query("offset"); offset != "" {
		parsed, err := strconv.Atoi(offset)
		if err != nil {
			return httperr.BadRequest(c, httperr.CodeValidationFailed, "offset must be an integer")
		}
		filter.Offset = parsed
	}

	messages, total, err := h.store.List(c.UserContext(), filter)
	if err != nil {
		return httperr.SendInternal(c, "sandbox.list", err)
	}

	dtos := make([]MessageDTO, 0, len(messages))
	for _, m := range messages {
		dtos = append(dtos, toDTO(m, false))
	}

	return c.JSON(fiber.Map{
		"environment": middleware.GetEnvironment(c),
		"messages":    dtos,
		"total":       total,
	})
}

// GetMessage handles GET /v1/tenant/sandbox/messages/:id.
func (h *Handler) GetMessage(c *fiber.Ctx) error {
	if _, ok := requireSandboxScope(c); !ok {
		return nil
	}

	id := strings.TrimSpace(c.Params("id"))
	if id == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "message id is required")
	}

	message, err := h.store.Get(c.UserContext(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			return httperr.NotFound(c, httperr.CodeNotFound, "captured message not found")
		}
		return httperr.SendInternal(c, "sandbox.get", err)
	}

	return c.JSON(fiber.Map{
		"environment": middleware.GetEnvironment(c),
		"message":     toDTO(message, true),
	})
}

// PurgeMessages handles DELETE /v1/tenant/sandbox/messages.
//
// Emptying the inbox between runs is what lets a test assert on "the newest
// message" without the previous run's captures standing in front of it.
func (h *Handler) PurgeMessages(c *fiber.Ctx) error {
	if _, ok := requireSandboxScope(c); !ok {
		return nil
	}

	removed, err := h.store.Purge(c.UserContext())
	if err != nil {
		return httperr.SendInternal(c, "sandbox.purge", err)
	}

	return c.JSON(fiber.Map{
		"message":     "sandbox inbox emptied",
		"environment": middleware.GetEnvironment(c),
		"removed":     removed,
	})
}

// VerifyDeliveryRequest asks for one real message on the configured provider.
//
// There is deliberately no recipient field. The address is the authenticated
// operator's own, which makes it impossible to aim this endpoint at somebody else
// rather than merely against the rules — and a check of whether a provider
// accepts mail does not need a choice of target to answer.
type VerifyDeliveryRequest struct {
	// Channel is "email" or "sms".
	Channel string `json:"channel"`
}

// VerifyDelivery handles POST /v1/tenant/delivery/verify.
//
// It sends one real message through the configured provider, bypassing the
// sandbox. That bypass is the entire purpose: a captured message never reaches a
// provider, so no amount of sandbox traffic establishes that the credentials in
// configuration work. Sending is the only test of a send.
func (h *Handler) VerifyDelivery(c *fiber.Ctx) error {
	tenantID, ok := middleware.RequireTenantID(c)
	if !ok {
		return nil
	}

	var req VerifyDeliveryRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	channel := strings.ToLower(strings.TrimSpace(req.Channel))
	if channel != string(sandboxmessage.ChannelEmail) && channel != string(sandboxmessage.ChannelSms) {
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"channel must be 'email' or 'sms'")
	}

	operator, ok := h.operator(c, tenantID)
	if !ok {
		return nil
	}

	if !h.allowVerify(c, tenantID, channel) {
		return nil
	}

	switch channel {
	case string(sandboxmessage.ChannelEmail):
		return h.verifyEmail(c, operator)
	default:
		return h.verifySMS(c, operator)
	}
}

// operator returns the console user making the request, or answers and reports
// false.
//
// A secret key is refused: it identifies an application rather than a person, so
// there is no address behind it that the engine has seen anybody prove control
// of. Requiring the console credential is what keeps the recipient something the
// engine already knows instead of something the caller supplies.
//
// Refusal is signalled by the boolean and not by an error, because every httperr
// helper returns nil after writing its response — an error return here would
// always read as success and leave the caller dereferencing a nil user.
func (h *Handler) operator(c *fiber.Ctx, tenantID string) (*ent.User, bool) {
	consoleUserID, _ := c.Locals("console_user_id").(string)
	if consoleUserID == "" {
		_ = httperr.Forbidden(c, httperr.CodeForbidden,
			"delivery verification requires a console session: it sends to the signed-in operator's own address, and a secret key has none")
		return nil, false
	}

	user, err := h.factory.
		GetClient(c.UserContext(), tenantID, middleware.GetEnvironment(c)).
		User.Get(c.UserContext(), consoleUserID)
	if err != nil {
		if ent.IsNotFound(err) {
			_ = httperr.NotFound(c, httperr.CodeNotFound,
				"the signed-in operator's account could not be read in this environment")
			return nil, false
		}
		_ = httperr.SendInternal(c, "sandbox.verify.operator", err)
		return nil, false
	}

	return user, true
}

// allowVerify reports whether this tenant may send another verification message,
// answering 429 and reporting false when it may not.
func (h *Handler) allowVerify(c *fiber.Ctx, tenantID string, channel string) bool {
	if h.limiter == nil {
		return true
	}

	key := fmt.Sprintf("%s:delivery_verify:%s", tenantID, channel)
	allowed, retryAfter, err := h.limiter.CheckWithLimit(c.UserContext(), key, verifyAttemptsPerWindow)
	if err != nil {
		if errors.Is(err, ratelimit.ErrRedisUnavailable) {
			_ = httperr.Send(c, fiber.StatusServiceUnavailable, httperr.CodeServiceUnavailable,
				"rate limit service unavailable")
			return false
		}
		_ = httperr.SendInternal(c, "sandbox.verify.ratelimit", err)
		return false
	}
	if allowed {
		return true
	}

	if retryAfter > 0 {
		c.Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
	}
	_ = httperr.TooManyRequests(c, httperr.CodeRateLimited,
		"too many delivery verification messages; the provider's own answer does not change between attempts")
	return false
}

// verifyEmail sends the verification message over email.
func (h *Handler) verifyEmail(c *fiber.Ctx, operator *ent.User) error {
	if h.emailProvider == nil {
		return httperr.Send(c, fiber.StatusServiceUnavailable, httperr.CodeServiceUnavailable,
			"no email provider is configured")
	}
	if !operator.EmailVerified {
		return httperr.Forbidden(c, httperr.CodeEmailVerificationRequired,
			"verify your own email address before using it to test delivery")
	}

	subject := "Authn delivery test"
	body := fmt.Sprintf(
		"This message confirms that the %s driver accepted mail from this deployment and delivered it.\n\nRequested at: %s",
		h.emailDriver(), time.Now().UTC().Format(time.RFC3339),
	)

	// The privacy-scoped request context is deliberately not used. The providers
	// held here are the undecorated ones, and passing a context carrying the test
	// scope would route the send into the sandbox the moment anything upstream
	// hands this handler a wrapped provider instead.
	if err := h.emailProvider.Send(c.Context(), operator.Email, subject, "<p>"+body+"</p>", body); err != nil {
		return httperr.Send(c, fiber.StatusBadGateway, httperr.CodeServiceUnavailable,
			"the email provider rejected the message: "+err.Error())
	}

	return c.JSON(fiber.Map{
		"message":   "delivery test accepted by the provider",
		"channel":   "email",
		"recipient": operator.Email,
		"driver":    h.emailDriver(),
	})
}

// verifySMS sends the verification message over SMS.
func (h *Handler) verifySMS(c *fiber.Ctx, operator *ent.User) error {
	if h.smsProvider == nil {
		return httperr.Send(c, fiber.StatusServiceUnavailable, httperr.CodeServiceUnavailable,
			"no SMS provider is configured")
	}
	if operator.PhoneNumber == "" || !operator.PhoneVerified {
		return httperr.Forbidden(c, httperr.CodeForbidden,
			"add and verify a phone number on your own account before using it to test delivery")
	}

	body := fmt.Sprintf("Authn delivery test: the %s driver accepted this message.", h.smsDriver())

	if err := h.smsProvider.SendSMS(c.Context(), operator.PhoneNumber, body); err != nil {
		return httperr.Send(c, fiber.StatusBadGateway, httperr.CodeServiceUnavailable,
			"the SMS provider rejected the message: "+err.Error())
	}

	return c.JSON(fiber.Map{
		"message":   "delivery test accepted by the provider",
		"channel":   "sms",
		"recipient": operator.PhoneNumber,
		"driver":    h.smsDriver(),
	})
}

// emailDriver names the configured email driver for the response, so an operator
// can see which backend answered rather than inferring it from configuration they
// may not be looking at.
func (h *Handler) emailDriver() string {
	if h.cfg == nil || h.cfg.EmailDriver == "" {
		return "smtp"
	}
	return h.cfg.EmailDriver
}

// smsDriver names the configured SMS driver for the response.
func (h *Handler) smsDriver() string {
	if h.cfg == nil || h.cfg.SMSDriver == "" {
		return "noop"
	}
	return h.cfg.SMSDriver
}
