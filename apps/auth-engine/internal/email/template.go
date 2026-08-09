/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/template.go
 * Tier: Internal Service Package / Email Rendering
 *
 * Renders the transactional emails the engine sends, each as a matched pair of
 * HTML and plain-text bodies.
 *
 * Templates are compiled from string constants rather than loaded from disk, so
 * rendering cannot fail because of a missing file and the binary ships
 * self-contained.
 *
 * The HTML side uses html/template and the text side text/template. That split
 * matters: html/template escapes by context, so a display name containing
 * markup is neutralised inside an attribute, a URL and an element body alike,
 * whereas text/template performs no escaping at all and is correct only because
 * its output is never parsed as markup.
 *
 * Styling is inlined in a <style> block because mail clients strip external
 * stylesheets, and layout stays on tables and simple blocks for the same
 * reason.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package email

import (
	"bytes"

	htmlTmpl "html/template"
	textTmpl "text/template"
)

// Fallbacks applied when a caller leaves a field unset, so a rendered message
// never shows a blank product name or an expiry of "0".
const (
	// fallbackAppName is the product name shown when none is supplied.
	fallbackAppName = "Authn Platform"
	// fallbackVerificationHours mirrors the configured verification link
	// lifetime and is shown only when the caller passes none.
	fallbackVerificationHours = 24
	// fallbackMagicLinkMinutes mirrors the configured magic link lifetime.
	fallbackMagicLinkMinutes = 15
	// fallbackImpersonationMinutes mirrors the default support session length.
	fallbackImpersonationMinutes = 15
)

// VerificationEmailData fills the email verification templates.
type VerificationEmailData struct {
	// UserName is the recipient's display name; the greeting falls back to
	// "there" when empty.
	UserName string
	// VerificationLink is the absolute URL that confirms the address. It is a
	// single-use credential, which is why these messages are not forwarded or
	// logged.
	VerificationLink string
	// AppName is the product name shown in the message.
	AppName string
	// ExpiresInHours is the link's stated lifetime, which must match the
	// lifetime actually enforced or the message misleads the recipient.
	ExpiresInHours int
}

// verificationHTMLTemplate is the HTML body for email verification.
const verificationHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify your email address</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 40px 20px; }
    .container { max-width: 560px; margin: 0 auto; background-color: #1e293b; border-radius: 12px; padding: 40px; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    .brand { font-size: 20px; font-weight: 700; color: #6366f1; letter-spacing: -0.5px; margin-bottom: 24px; text-transform: uppercase; }
    h1 { font-size: 22px; font-weight: 600; color: #ffffff; margin-top: 0; margin-bottom: 16px; }
    p { font-size: 15px; line-height: 1.6; color: #94a3b8; margin-bottom: 24px; }
    .btn-container { text-align: center; margin: 32px 0; }
    .btn { display: inline-block; background-color: #6366f1; color: #ffffff; font-weight: 600; font-size: 15px; padding: 14px 32px; border-radius: 8px; text-decoration: none; box-shadow: 0 4px 12px rgba(99, 102, 241, 0.4); }
    .link-alt { font-size: 12px; color: #64748b; word-break: break-all; margin-top: 24px; }
    .footer { font-size: 12px; color: #475569; text-align: center; margin-top: 32px; border-top: 1px solid #334155; padding-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">{{.AppName}}</div>
    <h1>Verify your email address</h1>
    <p>Hi {{if .UserName}}{{.UserName}}{{else}}there{{end}},</p>
    <p>Welcome to {{.AppName}}! Please verify your email address by clicking the button below. This link is valid for {{.ExpiresInHours}} hours.</p>
    <div class="btn-container">
      <a href="{{.VerificationLink}}" class="btn" target="_blank">Verify Email Address</a>
    </div>
    <p class="link-alt">If the button above doesn't work, copy and paste this URL into your web browser:<br><a href="{{.VerificationLink}}" style="color: #6366f1;">{{.VerificationLink}}</a></p>
    <div class="footer">
      <p>If you didn't create an account with {{.AppName}}, you can safely ignore this email.</p>
    </div>
  </div>
</body>
</html>`

// verificationTextTemplate is the plain-text alternative for email verification.
const verificationTextTemplate = `Verify your email address for {{.AppName}}

Hi {{if .UserName}}{{.UserName}}{{else}}there{{end}},

Welcome to {{.AppName}}! Please verify your email address by visiting the link below:

{{.VerificationLink}}

This link is valid for {{.ExpiresInHours}} hours.

If you didn't create an account with {{.AppName}}, you can safely ignore this email.`

// RenderVerificationEmail renders the HTML and plain-text bodies of the email
// verification message, in that order.
//
// Unset AppName and ExpiresInHours take their fallbacks, so a caller supplying
// only the link and the name still produces a coherent message.
//
// Returns an error if a template fails to parse or execute. Both indicate a
// defect in the templates themselves rather than in the caller's data, since
// the data is plain values that cannot fail to render.
func RenderVerificationEmail(data VerificationEmailData) (string, string, error) {
	if data.AppName == "" {
		data.AppName = fallbackAppName
	}
	if data.ExpiresInHours == 0 {
		data.ExpiresInHours = fallbackVerificationHours
	}

	hTmpl, err := htmlTmpl.New("verification_html").Parse(verificationHTMLTemplate)
	if err != nil {
		return "", "", err
	}
	var htmlBuf bytes.Buffer
	if err := hTmpl.Execute(&htmlBuf, data); err != nil {
		return "", "", err
	}

	tTmpl, err := textTmpl.New("verification_text").Parse(verificationTextTemplate)
	if err != nil {
		return "", "", err
	}
	var textBuf bytes.Buffer
	if err := tTmpl.Execute(&textBuf, data); err != nil {
		return "", "", err
	}

	return htmlBuf.String(), textBuf.String(), nil
}

// MagicLinkEmailData fills the passwordless sign-in templates.
type MagicLinkEmailData struct {
	// UserName is the recipient's display name; the greeting falls back to
	// "there" when empty.
	UserName string
	// MagicLink is the absolute sign-in URL. It grants a session on its own, so
	// it is the most sensitive value this package renders.
	MagicLink string
	// AppName is the product name shown in the message.
	AppName string
	// ExpiresInMinutes is the link's stated lifetime, kept short because the
	// link alone authenticates.
	ExpiresInMinutes int
}

// magicLinkHTMLTemplate is the HTML body for passwordless sign-in.
const magicLinkHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your Magic Login Link</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 40px 20px; }
    .container { max-width: 560px; margin: 0 auto; background-color: #1e293b; border-radius: 12px; padding: 40px; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    .brand { font-size: 20px; font-weight: 700; color: #6366f1; letter-spacing: -0.5px; margin-bottom: 24px; text-transform: uppercase; }
    h1 { font-size: 22px; font-weight: 600; color: #ffffff; margin-top: 0; margin-bottom: 16px; }
    p { font-size: 15px; line-height: 1.6; color: #94a3b8; margin-bottom: 24px; }
    .btn-container { text-align: center; margin: 32px 0; }
    .btn { display: inline-block; background-color: #6366f1; color: #ffffff; font-weight: 600; font-size: 15px; padding: 14px 32px; border-radius: 8px; text-decoration: none; box-shadow: 0 4px 12px rgba(99, 102, 241, 0.4); }
    .link-alt { font-size: 12px; color: #64748b; word-break: break-all; margin-top: 24px; }
    .footer { font-size: 12px; color: #475569; text-align: center; margin-top: 32px; border-top: 1px solid #334155; padding-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">{{.AppName}}</div>
    <h1>Log in to {{.AppName}}</h1>
    <p>Hi {{if .UserName}}{{.UserName}}{{else}}there{{end}},</p>
    <p>Click the button below to log in to your account. This link is single-use and valid for {{.ExpiresInMinutes}} minutes.</p>
    <div class="btn-container">
      <a href="{{.MagicLink}}" class="btn" target="_blank">Log In to {{.AppName}}</a>
    </div>
    <p class="link-alt">If the button above doesn't work, copy and paste this URL into your browser:<br><a href="{{.MagicLink}}" style="color: #6366f1;">{{.MagicLink}}</a></p>
    <div class="footer">
      <p>If you didn't request this login link, you can safely ignore this email.</p>
    </div>
  </div>
</body>
</html>`

// magicLinkTextTemplate is the plain-text alternative for passwordless sign-in.
const magicLinkTextTemplate = `Log in to {{.AppName}}

Hi {{if .UserName}}{{.UserName}}{{else}}there{{end}},

Use the link below to log in to your account:

{{.MagicLink}}

This link is single-use and valid for {{.ExpiresInMinutes}} minutes.

If you didn't request this login link, you can safely ignore this email.`

// RenderMagicLinkEmail renders the HTML and plain-text bodies of the
// passwordless sign-in message, in that order.
//
// Unset AppName and ExpiresInMinutes take their fallbacks. Returns an error if
// a template fails to parse or execute.
func RenderMagicLinkEmail(data MagicLinkEmailData) (string, string, error) {
	if data.AppName == "" {
		data.AppName = fallbackAppName
	}
	if data.ExpiresInMinutes == 0 {
		data.ExpiresInMinutes = fallbackMagicLinkMinutes
	}

	hTmpl, err := htmlTmpl.New("magic_link_html").Parse(magicLinkHTMLTemplate)
	if err != nil {
		return "", "", err
	}
	var htmlBuf bytes.Buffer
	if err := hTmpl.Execute(&htmlBuf, data); err != nil {
		return "", "", err
	}

	tTmpl, err := textTmpl.New("magic_link_text").Parse(magicLinkTextTemplate)
	if err != nil {
		return "", "", err
	}
	var textBuf bytes.Buffer
	if err := tTmpl.Execute(&textBuf, data); err != nil {
		return "", "", err
	}

	return htmlBuf.String(), textBuf.String(), nil
}

// ImpersonationEmailData fills the support access notification templates.
//
// This message is a security notice, not a courtesy: it is what lets a user
// notice support access they did not ask for. It is sent whether or not the
// access was legitimate.
type ImpersonationEmailData struct {
	// UserName is the account holder's display name; the greeting falls back to
	// "there" when empty.
	UserName string
	// AdminName identifies the operator who accessed the account, falling back
	// to a generic label when unavailable.
	AdminName string
	// Reason is the justification recorded for the access.
	Reason string
	// TicketID references the support ticket, omitted from the message when
	// empty.
	TicketID string
	// DurationMinutes is how long the support session lasts before expiring.
	DurationMinutes int
	// AppName is the product name shown in the message.
	AppName string
}

// impersonationHTMLTemplate is the HTML body for the support access notice.
const impersonationHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Notice: Support Access to Your Account</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 40px 20px; }
    .container { max-width: 560px; margin: 0 auto; background-color: #1e293b; border-radius: 12px; padding: 40px; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    .brand { font-size: 20px; font-weight: 700; color: #6366f1; letter-spacing: -0.5px; margin-bottom: 24px; text-transform: uppercase; }
    h1 { font-size: 20px; font-weight: 600; color: #ffffff; margin-top: 0; margin-bottom: 16px; }
    p { font-size: 15px; line-height: 1.6; color: #94a3b8; margin-bottom: 20px; }
    .details { background-color: #0f172a; border-radius: 8px; padding: 20px; margin: 24px 0; border: 1px solid #334155; font-size: 14px; color: #cbd5e1; }
    .details p { color: #cbd5e1; margin-bottom: 8px; font-size: 14px; }
    .footer { font-size: 12px; color: #475569; text-align: center; margin-top: 32px; border-top: 1px solid #334155; padding-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">{{.AppName}}</div>
    <h1>🛡️ Security Notice: Support Access</h1>
    <p>Hi {{if .UserName}}{{.UserName}}{{else}}there{{end}},</p>
    <p>A member of our support team accessed your account for troubleshooting and customer assistance.</p>
    <div class="details">
      <p><strong>Support Agent:</strong> {{if .AdminName}}{{.AdminName}}{{else}}Support Representative{{end}}</p>
      <p><strong>Reason:</strong> {{.Reason}}</p>
      {{if .TicketID}}<p><strong>Ticket ID:</strong> {{.TicketID}}</p>{{end}}
      <p><strong>Access Duration:</strong> {{.DurationMinutes}} minutes (Expires automatically)</p>
    </div>
    <div class="footer">
      <p>If you requested assistance from our team, no action is required. If you did not request support, please contact our security team immediately.</p>
    </div>
  </div>
</body>
</html>`

// impersonationTextTemplate is the plain-text alternative for the support
// access notice.
const impersonationTextTemplate = `Security Notice: Support Access for {{.AppName}}

Hi {{if .UserName}}{{.UserName}}{{else}}there{{end}},

A member of our support team accessed your account for troubleshooting and customer assistance.

Session Details:
- Support Agent: {{if .AdminName}}{{.AdminName}}{{else}}Support Representative{{end}}
- Reason: {{.Reason}}
{{if .TicketID}}- Ticket ID: {{.TicketID}}{{end}}
- Access Duration: {{.DurationMinutes}} minutes

If you requested assistance, no action is required. If you did not request support, please contact our security team immediately.`

// RenderImpersonationEmail renders the HTML and plain-text bodies of the
// support access notice, in that order.
//
// Unset AppName and DurationMinutes take their fallbacks. Returns an error if a
// template fails to parse or execute.
func RenderImpersonationEmail(data ImpersonationEmailData) (string, string, error) {
	if data.AppName == "" {
		data.AppName = fallbackAppName
	}
	if data.DurationMinutes == 0 {
		data.DurationMinutes = fallbackImpersonationMinutes
	}

	hTmpl, err := htmlTmpl.New("impersonation_html").Parse(impersonationHTMLTemplate)
	if err != nil {
		return "", "", err
	}
	var htmlBuf bytes.Buffer
	if err := hTmpl.Execute(&htmlBuf, data); err != nil {
		return "", "", err
	}

	tTmpl, err := textTmpl.New("impersonation_text").Parse(impersonationTextTemplate)
	if err != nil {
		return "", "", err
	}
	var textBuf bytes.Buffer
	if err := tTmpl.Execute(&textBuf, data); err != nil {
		return "", "", err
	}

	return htmlBuf.String(), textBuf.String(), nil
}
