/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/smtp.go
 * Tier: Internal Service Package / SMTP Email Driver Implementation
 *
 * Description: Standard SMTP email driver implementing EmailProvider interface.
 *              Supports both unauthenticated local catchers (Mailpit/MailHog) and
 *              TLS-authenticated production SMTP relays.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package email

import (
	"context"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SMTPConfig holds setup parameters for the SMTP driver.
type SMTPConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

// SMTPProvider implements EmailProvider via standard SMTP protocol.
type SMTPProvider struct {
	cfg SMTPConfig
}

// NewSMTPProvider constructs a new SMTPProvider instance.
func NewSMTPProvider(cfg SMTPConfig) *SMTPProvider {
	if cfg.Port == "" {
		cfg.Port = "1025"
	}
	if cfg.Host == "" {
		cfg.Host = "localhost"
	}
	if cfg.From == "" {
		cfg.From = "noreply@authn.local"
	}
	return &SMTPProvider{cfg: cfg}
}

// Send formats a MIME multipart email and delivers it over SMTP.
func (p *SMTPProvider) Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error {
	addr := net.JoinHostPort(p.cfg.Host, p.cfg.Port)

	boundary := fmt.Sprintf("bnd_%d", time.Now().UnixNano())

	headers := make(map[string]string)
	headers["From"] = p.cfg.From
	headers["To"] = to
	headers["Subject"] = mime.QEncoding.Encode("UTF-8", subject)
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = fmt.Sprintf("multipart/alternative; boundary=\"%s\"", boundary)

	var msgBuilder strings.Builder
	for k, v := range headers {
		msgBuilder.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	msgBuilder.WriteString("\r\n")

	// Plain Text Part
	msgBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msgBuilder.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msgBuilder.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	msgBuilder.WriteString(textBody)
	msgBuilder.WriteString("\r\n\r\n")

	// HTML Part
	msgBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msgBuilder.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msgBuilder.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	msgBuilder.WriteString(htmlBody)
	msgBuilder.WriteString("\r\n\r\n")

	msgBuilder.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	rawMsg := []byte(msgBuilder.String())

	var auth smtp.Auth
	if p.cfg.Username != "" || p.cfg.Password != "" {
		auth = smtp.PlainAuth("", p.cfg.Username, p.cfg.Password, p.cfg.Host)
	}

	// Dial SMTP server
	conn, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed connecting to SMTP server at %s: %w", addr, err)
	}
	defer conn.Close()

	if auth != nil {
		if err := conn.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	if err := conn.Mail(p.cfg.From); err != nil {
		return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
	}

	if err := conn.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT TO failed: %w", err)
	}

	w, err := conn.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA command failed: %w", err)
	}

	_, err = w.Write(rawMsg)
	if err != nil {
		_ = w.Close()
		return fmt.Errorf("failed writing SMTP payload: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed closing SMTP payload stream: %w", err)
	}

	return conn.Quit()
}
