/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/postmark.go
 * Tier: Internal Service Package / Email Drivers
 *
 * Description: Postmark EmailProvider implementation using Postmark REST API.
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

// PostmarkProvider implements EmailProvider interface for Postmark API.
type PostmarkProvider struct {
	serverToken string
	fromAddress string
	httpClient  *http.Client
}

// NewPostmarkProvider constructs a new PostmarkProvider.
func NewPostmarkProvider(serverToken string, fromAddress string) *PostmarkProvider {
	return &PostmarkProvider{
		serverToken: serverToken,
		fromAddress: fromAddress,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

type postmarkSendRequest struct {
	From     string `json:"From"`
	To       string `json:"To"`
	Subject  string `json:"Subject"`
	HtmlBody string `json:"HtmlBody,omitempty"`
	TextBody string `json:"TextBody,omitempty"`
}

type postmarkSendResponse struct {
	ErrorCode int    `json:"ErrorCode"`
	Message   string `json:"Message"`
}

// Send transmits an email using Postmark HTTP API.
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

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.postmarkapp.com/email", bytes.NewBuffer(bodyBytes))
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

	var pResp postmarkSendResponse
	if err := json.Unmarshal(respBytes, &pResp); err == nil && pResp.ErrorCode != 0 {
		return fmt.Errorf("postmark error (%d): %s", pResp.ErrorCode, pResp.Message)
	}

	return nil
}
