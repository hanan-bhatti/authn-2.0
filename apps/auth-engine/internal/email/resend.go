/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/resend.go
 * Tier: Internal Service Package / Email Drivers
 *
 * Description: Resend EmailProvider implementation using Resend v1 REST API.
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

// ResendProvider implements EmailProvider interface for Resend API.
type ResendProvider struct {
	apiKey      string
	fromAddress string
	httpClient  *http.Client
}

// NewResendProvider constructs a new ResendProvider.
func NewResendProvider(apiKey string, fromAddress string) *ResendProvider {
	return &ResendProvider{
		apiKey:      apiKey,
		fromAddress: fromAddress,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

type resendSendRequest struct {
	From    string `json:"from"`
	To      []string `json:"to"`
	Subject string `json:"subject"`
	HTML    string `json:"html"`
	Text    string `json:"text,omitempty"`
}

type resendSendResponse struct {
	ID    string `json:"id"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// Send transmits an email using Resend HTTP API.
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

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.resend.com/emails", bytes.NewBuffer(bodyBytes))
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

	var resres resendSendResponse
	if err := json.Unmarshal(respBytes, &resres); err == nil && resres.Error != nil {
		return fmt.Errorf("resend API error: %s", resres.Error.Message)
	}

	return nil
}
