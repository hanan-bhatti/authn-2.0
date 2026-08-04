/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sms/messagebird.go
 * Tier: Internal Service Package / SMS Drivers
 *
 * Description: MessageBird REST API SMSProvider implementation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MessageBirdProvider implements SMSProvider for MessageBird API.
type MessageBirdProvider struct {
	accessKey  string
	originator string
	httpClient *http.Client
}

// NewMessageBirdProvider constructs a new MessageBirdProvider.
func NewMessageBirdProvider(accessKey string, originator string) *MessageBirdProvider {
	if originator == "" {
		originator = "Authn"
	}
	return &MessageBirdProvider{
		accessKey:  accessKey,
		originator: originator,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

type messageBirdSendRequest struct {
	Originator string   `json:"originator"`
	Recipients []string `json:"recipients"`
	Body       string   `json:"body"`
}

type messageBirdError struct {
	Code    int    `json:"code"`
	Description string `json:"description"`
}

type messageBirdSendResponse struct {
	ID     string             `json:"id"`
	Errors []messageBirdError `json:"errors,omitempty"`
}

// SendSMS transmits an SMS message using MessageBird HTTP API.
func (p *MessageBirdProvider) SendSMS(ctx context.Context, toPhoneNumber string, message string) error {
	if p.accessKey == "" {
		return fmt.Errorf("messagebird access key is not configured")
	}

	payload := messageBirdSendRequest{
		Originator: p.originator,
		Recipients: []string{toPhoneNumber},
		Body:       message,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed marshaling messagebird payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://rest.messagebird.com/messages", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed creating messagebird HTTP request: %w", err)
	}

	req.Header.Set("Authorization", "AccessKey "+p.accessKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed executing messagebird HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("messagebird API error (%d): %s", resp.StatusCode, string(respBytes))
	}

	var mbResp messageBirdSendResponse
	if err := json.Unmarshal(respBytes, &mbResp); err == nil && len(mbResp.Errors) > 0 {
		return fmt.Errorf("messagebird error (%d): %s", mbResp.Errors[0].Code, mbResp.Errors[0].Description)
	}

	return nil
}
