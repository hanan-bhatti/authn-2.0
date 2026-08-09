/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/sendgrid.go
 * Tier: Internal Service Package / Email Drivers
 *
 * Delivery through the SendGrid v3 Web API.
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
)

// sendGridSendEndpoint is the SendGrid v3 mail-send resource.
const sendGridSendEndpoint = "https://api.sendgrid.com/v3/mail/send"

// SendGridProvider delivers mail through SendGrid.
type SendGridProvider struct {
	// apiKey authenticates as a Bearer token and must carry the mail.send
	// scope.
	apiKey string
	// fromAddress is the sender; SendGrid requires a verified sender identity.
	fromAddress string
	// httpClient is reused across sends so connections are pooled.
	httpClient *http.Client
}

// NewSendGridProvider constructs a SendGrid-backed provider.
func NewSendGridProvider(apiKey string, fromAddress string) *SendGridProvider {
	return &SendGridProvider{
		apiKey:      apiKey,
		fromAddress: fromAddress,
		httpClient:  &http.Client{Timeout: providerHTTPTimeout},
	}
}

// sendGridEmailObj is SendGrid's address representation.
type sendGridEmailObj struct {
	// Email is the address itself.
	Email string `json:"email"`
}

// sendGridPersonalization is one delivery grouping. This driver sends a single
// message to a single recipient, so exactly one is ever built.
type sendGridPersonalization struct {
	// To lists the recipients of this grouping.
	To []sendGridEmailObj `json:"to"`
}

// sendGridContent is one body alternative.
type sendGridContent struct {
	// Type is the MIME type, "text/plain" or "text/html".
	Type string `json:"type"`
	// Value is the body text.
	Value string `json:"value"`
}

// sendGridSendRequest is the mail-send request body.
type sendGridSendRequest struct {
	// Personalizations groups recipients and per-recipient substitutions.
	Personalizations []sendGridPersonalization `json:"personalizations"`
	// From is the verified sender identity.
	From sendGridEmailObj `json:"from"`
	// Subject is the message subject.
	Subject string `json:"subject"`
	// Content holds the body alternatives, ordered least to most preferred.
	Content []sendGridContent `json:"content"`
}

// Send delivers one message through SendGrid.
//
// Returns an error when the API key is unset, the request cannot be built or
// executed, or the API answers 4xx or 5xx. SendGrid signals acceptance with 202
// and an empty body, so unlike the other drivers there is no body to inspect on
// success.
func (p *SendGridProvider) Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error {
	if p.apiKey == "" {
		return fmt.Errorf("sendgrid API key is not configured")
	}

	// SendGrid requires content alternatives in ascending order of preference,
	// and rejects the request outright if HTML precedes plain text. Empty
	// bodies are omitted rather than sent blank, which would show the recipient
	// an empty message in whichever alternative their client picked.
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

	req, err := http.NewRequestWithContext(ctx, "POST", sendGridSendEndpoint, bytes.NewBuffer(bodyBytes))
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
