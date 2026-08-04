/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/template.go
 * Tier: Internal Service Package / Email Template System
 *
 * Description: Minimal HTML/Text email template rendering engine using Go's
 *              built-in html/template and text/template packages.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package email

import (
	"bytes"

	htmlTmpl "html/template"
	textTmpl "text/template"
)

// VerificationEmailData contains data required to render verification emails.
type VerificationEmailData struct {
	UserName         string
	VerificationLink string
	AppName          string
	ExpiresInHours   int
}

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

const verificationTextTemplate = `Verify your email address for {{.AppName}}

Hi {{if .UserName}}{{.UserName}}{{else}}there{{end}},

Welcome to {{.AppName}}! Please verify your email address by visiting the link below:

{{.VerificationLink}}

This link is valid for {{.ExpiresInHours}} hours.

If you didn't create an account with {{.AppName}}, you can safely ignore this email.`

// RenderVerificationEmail renders HTML and plain text email verification templates.
func RenderVerificationEmail(data VerificationEmailData) (string, string, error) {
	if data.AppName == "" {
		data.AppName = "Authn Platform"
	}
	if data.ExpiresInHours == 0 {
		data.ExpiresInHours = 24
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

// MagicLinkEmailData contains data required to render magic login link emails.
type MagicLinkEmailData struct {
	UserName         string
	MagicLink        string
	AppName          string
	ExpiresInMinutes int
}

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

const magicLinkTextTemplate = `Log in to {{.AppName}}

Hi {{if .UserName}}{{.UserName}}{{else}}there{{end}},

Use the link below to log in to your account:

{{.MagicLink}}

This link is single-use and valid for {{.ExpiresInMinutes}} minutes.

If you didn't request this login link, you can safely ignore this email.`

// RenderMagicLinkEmail renders HTML and plain text magic link emails.
func RenderMagicLinkEmail(data MagicLinkEmailData) (string, string, error) {
	if data.AppName == "" {
		data.AppName = "Authn Platform"
	}
	if data.ExpiresInMinutes == 0 {
		data.ExpiresInMinutes = 15
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
