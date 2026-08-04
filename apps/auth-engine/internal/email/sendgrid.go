/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/sendgrid.go
 * Tier: Internal Service Package / Email Drivers
 *
 * Description: SendGrid EmailProvider implementation using SendGrid v3 Web API.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SendGridProvider implements EmailProvider interface for SendGrid API.
type SendGridProvider struct {
	apiKey      string
	fromAddress string
	httpClient  *http.Client
}

// NewSendGridProvider constructs a new SendGridProvider.
func NewSendGridProvider(apiKey string, fromAddress string) *SendGridProvider {
	return &SendGridProvider{
		apiKey:      apiKey,
		fromAddress: fromAddress,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

type sendGridEmailObj struct {
	Email string `json:"email"`
}

type sendGridPersonalization struct {
	To []sendGridEmailObj `json:"to"`
}

type sendGridContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type sendGridSendRequest struct {
	Personalizations []sendGridPersonalization `json:"personalizations"`
	From             sendGridEmailObj        `json:"from"`
	Subject          string                  `json:"subject"`
	Content          []sendGridContent       `json:"content"`
}

// Send transmits an email using SendGrid v3 API.
func (p *SendGridProvider) Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error {
	if p.apiKey == "" {
		return fmt.Errorf("sendgrid API key is not configured")
	}

	contents := []sendGridContent{}
	if textBody != "" {
		contents = append(contents, sendGridContent{Type: "text/plain", Value: textBody})
	}
	if htmlBody != "" {
		contents = append(contents, sendGridContent{Type: "text/html", Value: htmlBody})
	}

	payload := sendGridSendRequest{
		Personalizations: []sendGridPersonalization{
			{
				To: []sendGridEmailObj{{Email: to}},
			},
		},
		From:    sendGridEmailObj{Email: p.fromAddress},
		Subject: subject,
		Content: contents,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed marshaling sendgrid payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.sendgrid.com/v3/mail/send", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed creating sendgrid HTTP request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed executing sendgrid HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("sendgrid API error (%d): %s", resp.StatusCode, string(respBytes))
	}

	return nil
}
