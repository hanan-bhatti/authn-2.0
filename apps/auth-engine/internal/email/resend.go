/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/resend.go
 * Tier: Internal Service Package / Email Drivers
 *
 * Delivery through the Resend v1 REST API.
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

// resendSendEndpoint is the Resend send-message resource.
const resendSendEndpoint = "https://api.resend.com/emails"

// ResendProvider delivers mail through Resend.
type ResendProvider struct {
	// apiKey authenticates as a Bearer token.
	apiKey string
	// fromAddress is the sender; Resend requires its domain to be verified on
	// the account.
	fromAddress string
	// httpClient is reused across sends so connections are pooled rather than
	// renegotiated per message.
	httpClient *http.Client
}

// NewResendProvider constructs a Resend-backed provider.
func NewResendProvider(apiKey string, fromAddress string) *ResendProvider {
	return &ResendProvider{
		apiKey:      apiKey,
		fromAddress: fromAddress,
		httpClient:  &http.Client{Timeout: providerHTTPTimeout},
	}
}

// resendSendRequest is the send-message request body.
type resendSendRequest struct {
	// From is the verified sender address.
	From string `json:"from"`
	// To is the recipient list; this driver always sends to exactly one.
	To []string `json:"to"`
	// Subject is the message subject.
	Subject string `json:"subject"`
	// HTML is the HTML body.
	HTML string `json:"html"`
	// Text is the plain-text alternative, omitted when empty.
	Text string `json:"text,omitempty"`
}

// resendSendResponse is the send-message response body.
type resendSendResponse struct {
	// ID identifies the accepted message.
	ID string `json:"id"`
	// Error is populated on a rejection reported in the body rather than by
	// status code.
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// Send delivers one message through Resend.
//
// Returns an error when the API key is unset, the request cannot be built or
// executed, the API answers 4xx or 5xx, or the response body reports an error
// alongside a success status. The body is checked as well as the status because
// a 200 carrying an error object still means the message was not sent.
func (p *ResendProvider) Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error {
	if p.apiKey == "" {
		return fmt.Errorf("resend API key is not configured")
	}

	payload := resendSendRequest{
		From:    p.fromAddress,
		To:      []string{to},
		Subject: subject,
		HTML:    htmlBody,
		Text:    textBody,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed marshaling resend payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", resendSendEndpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed creating resend HTTP request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed executing resend HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("resend API error (%d): %s", resp.StatusCode, string(respBytes))
	}

	// An unparseable body on a success status is treated as success: the
	// message was accepted, and only a well-formed error object contradicts it.
	var parsed resendSendResponse
	if err := json.Unmarshal(respBytes, &parsed); err == nil && parsed.Error != nil {
		return fmt.Errorf("resend API error: %s", parsed.Error.Message)
	}

	return nil
}
