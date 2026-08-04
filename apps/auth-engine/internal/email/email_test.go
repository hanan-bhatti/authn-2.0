/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/email_test.go
 * Tier: Internal Service Package / Unit Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package email_test

import (
	"context"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderVerificationEmail(t *testing.T) {
	data := email.VerificationEmailData{
		UserName:         "Alice Smith",
		VerificationLink: "http://localhost:8080/v1/client/verify-email?token=abcdef123456",
		AppName:          "Authn Test App",
		ExpiresInHours:   24,
	}

	html, text, err := email.RenderVerificationEmail(data)
	require.NoError(t, err)

	assert.Contains(t, html, "Verify your email address")
	assert.Contains(t, html, "Alice Smith")
	assert.Contains(t, html, "http://localhost:8080/v1/client/verify-email?token=abcdef123456")
	assert.Contains(t, html, "Authn Test App")

	assert.Contains(t, text, "Verify your email address for Authn Test App")
	assert.Contains(t, text, "Alice Smith")
	assert.Contains(t, text, "http://localhost:8080/v1/client/verify-email?token=abcdef123456")
}

func TestNoopProvider_Send(t *testing.T) {
	provider := email.NewNoopProvider()
	err := provider.Send(context.Background(), "user@example.com", "Test Subject", "<p>HTML</p>", "Text")
	assert.NoError(t, err)
}

func TestRenderMagicLinkEmail(t *testing.T) {
	data := email.MagicLinkEmailData{
		UserName:         "Bob Jones",
		MagicLink:        "http://localhost:8080/v1/client/auth/magic-link/verify?token=1234567890",
		AppName:          "Authn Test App",
		ExpiresInMinutes: 15,
	}

	html, text, err := email.RenderMagicLinkEmail(data)
	require.NoError(t, err)

	assert.Contains(t, html, "Log in to Authn Test App")
	assert.Contains(t, html, "Bob Jones")
	assert.Contains(t, html, "http://localhost:8080/v1/client/auth/magic-link/verify?token=1234567890")

	assert.Contains(t, text, "Log in to Authn Test App")
	assert.Contains(t, text, "Bob Jones")
	assert.Contains(t, text, "http://localhost:8080/v1/client/auth/magic-link/verify?token=1234567890")
}

func TestNewEmailProvider_Factory(t *testing.T) {
	tests := []struct {
		name      string
		driver    string
		expectErr bool
	}{
		{"SMTP Default", "smtp", false},
		{"Noop Driver", "noop", false},
		{"Disabled Driver", "disabled", false},
		{"Resend Missing Key", "resend", true},
		{"SendGrid Missing Key", "sendgrid", true},
		{"Postmark Missing Token", "postmark", true},
		{"AWS SES Driver", "aws_ses", false},
		{"Unsupported Driver", "unknown_provider", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.EnvConfig{
				EmailDriver:      tt.driver,
				EmailFromAddress: "noreply@example.com",
			}
			p, err := email.NewEmailProvider(cfg)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, p)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, p)
			}
		})
	}
}
