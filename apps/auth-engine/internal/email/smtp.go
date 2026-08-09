/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/smtp.go
 * Tier: Internal Service Package / SMTP Email Driver
 *
 * Delivery over plain SMTP, for deployments that route mail through their own
 * relay and for local development against a mail catcher such as Mailpit.
 *
 * Messages are built as multipart/alternative carrying both a plain-text and an
 * HTML body. Offering both is not decoration: a text/html-only message scores
 * as spam with most filters, and the text part is what a client without HTML
 * rendering shows.
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
	"strconv"
	"strings"
	"time"
)

// SMTPConfig holds the connection settings for the SMTP driver.
type SMTPConfig struct {
	// Host is the relay's hostname. It also names the server during
	// authentication, which binds credentials to the intended host.
	Host string
	// Port is the relay's TCP port.
	Port int
	// Username is the SMTP account, empty for an unauthenticated local catcher.
	Username string
	// Password accompanies Username.
	Password string
	// From is the envelope sender and the From header.
	From string
}

// SMTPProvider delivers mail by speaking SMTP to a configured relay.
type SMTPProvider struct {
	// cfg holds the relay connection settings; it is read-only after
	// construction, which is what makes the provider safe to share.
	cfg SMTPConfig
}

// NewSMTPProvider constructs a provider for the given relay.
//
// Host, port and sender address come from the configuration layer, which owns
// every default; this constructor substitutes no values of its own.
func NewSMTPProvider(cfg SMTPConfig) *SMTPProvider {
	return &SMTPProvider{cfg: cfg}
}

// Send builds a multipart/alternative message and delivers it over SMTP.
//
// Returns an error when the relay is unreachable, rejects the credentials,
// refuses the sender or recipient, or fails during transfer. The error names
// the protocol stage that failed, since "connect", "auth" and "RCPT TO"
// point at three different misconfigurations.
func (p *SMTPProvider) Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error {
	addr := net.JoinHostPort(p.cfg.Host, strconv.Itoa(p.cfg.Port))

	// The boundary must not occur in either body. Deriving it from the current
	// nanosecond keeps it unpredictable enough that generated content cannot
	// collide with it and split the message.
	boundary := fmt.Sprintf("bnd_%d", time.Now().UnixNano())

	headers := make(map[string]string)
	headers["From"] = p.cfg.From
	headers["To"] = to
	// Subjects carry user-supplied names. Q-encoding keeps non-ASCII characters
	// legal in a header and prevents a crafted subject from injecting one.
	headers["Subject"] = mime.QEncoding.Encode("UTF-8", subject)
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = fmt.Sprintf("multipart/alternative; boundary=\"%s\"", boundary)

	var msgBuilder strings.Builder
	for k, v := range headers {
		msgBuilder.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	msgBuilder.WriteString("\r\n")

	// Plain text first. multipart/alternative is ordered least to most
	// preferred, so the HTML part must follow for a capable client to pick it.
	msgBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msgBuilder.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msgBuilder.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	msgBuilder.WriteString(textBody)
	msgBuilder.WriteString("\r\n\r\n")

	msgBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msgBuilder.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msgBuilder.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	msgBuilder.WriteString(htmlBody)
	msgBuilder.WriteString("\r\n\r\n")

	// The trailing "--" closes the multipart body; without it a client treats
	// the message as truncated.
	msgBuilder.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	rawMsg := []byte(msgBuilder.String())

	// Authentication is attempted only when a credential is configured, so the
	// same driver serves an authenticated relay and an anonymous local catcher.
	var auth smtp.Auth
	if p.cfg.Username != "" || p.cfg.Password != "" {
		auth = smtp.PlainAuth("", p.cfg.Username, p.cfg.Password, p.cfg.Host)
	}

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
		// Close the writer before returning so the connection is left in a
		// state the deferred Close can shut down cleanly.
		_ = w.Close()
		return fmt.Errorf("failed writing SMTP payload: %w", err)
	}

	// Closing the data writer is what commits the message; a relay that
	// rejects content reports it here rather than at Write.
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed closing SMTP payload stream: %w", err)
	}

	return conn.Quit()
}
