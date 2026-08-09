/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/postmark.go
 * Tier: Internal Service Package / Email Drivers
 *
 * Delivery through the Postmark REST API.
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

// postmarkSendEndpoint is the Postmark single-message resource.
const postmarkSendEndpoint = "https://api.postmarkapp.com/email"

// PostmarkProvider delivers mail through Postmark.
type PostmarkProvider struct {
	// serverToken authenticates against one Postmark server.
	serverToken string
	// fromAddress is the sender; Postmark requires it to be a confirmed sender
	// signature on the account.
	fromAddress string
	// httpClient is reused across sends so connections are pooled.
	httpClient *http.Client
}

// NewPostmarkProvider constructs a Postmark-backed provider.
func NewPostmarkProvider(serverToken string, fromAddress string) *PostmarkProvider {
	return &PostmarkProvider{
		serverToken: serverToken,
		fromAddress: fromAddress,
		httpClient:  &http.Client{Timeout: providerHTTPTimeout},
	}
}

// postmarkSendRequest is the send-message request body. Postmark's field names
// are capitalised, hence the explicit tags.
type postmarkSendRequest struct {
	// From is the confirmed sender signature.
	From string `json:"From"`
	// To is the recipient address.
	To string `json:"To"`
	// Subject is the message subject.
	Subject string `json:"Subject"`
	// HtmlBody is the HTML alternative, omitted when empty.
	HtmlBody string `json:"HtmlBody,omitempty"`
	// TextBody is the plain-text alternative, omitted when empty.
	TextBody string `json:"TextBody,omitempty"`
}

// postmarkSendResponse is the send-message response body.
type postmarkSendResponse struct {
	// ErrorCode is zero on success and a Postmark-specific code otherwise.
	ErrorCode int `json:"ErrorCode"`
	// Message describes the failure when ErrorCode is non-zero.
	Message string `json:"Message"`
}

// Send delivers one message through Postmark.
//
// Returns an error when the server token is unset, the request cannot be built
// or executed, the API answers 4xx or 5xx, or the response reports a non-zero
// ErrorCode. Postmark signals some rejections — a suppressed or inactive
// recipient among them — in the body of a 200, so the body is checked as well.
func (p *PostmarkProvider) Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error {
	if p.serverToken == "" {
		return fmt.Errorf("postmark server token is not configured")
	}

	payload := postmarkSendRequest{
		From:     p.fromAddress,
		To:       to,
		Subject:  subject,
		HtmlBody: htmlBody,
		TextBody: textBody,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed marshaling postmark payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", postmarkSendEndpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed creating postmark HTTP request: %w", err)
	}

	req.Header.Set("X-Postmark-Server-Token", p.serverToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed executing postmark HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("postmark API error (%d): %s", resp.StatusCode, string(respBytes))
	}

	// An unparseable body on a success status is treated as success; only an
	// explicit non-zero ErrorCode contradicts the status.
	var parsed postmarkSendResponse
	if err := json.Unmarshal(respBytes, &parsed); err == nil && parsed.ErrorCode != 0 {
		return fmt.Errorf("postmark error (%d): %s", parsed.ErrorCode, parsed.Message)
	}

	return nil
}
