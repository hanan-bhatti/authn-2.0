/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sms/messagebird.go
 * Tier: Internal Service Package / SMS Drivers
 *
 * Delivery through the MessageBird REST API.
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
)

const (
	// messageBirdSendEndpoint is the MessageBird messages resource.
	messageBirdSendEndpoint = "https://rest.messagebird.com/messages"

	// fallbackOriginator is the sender label used when none is configured.
	//
	// It is alphanumeric rather than a phone number, which several countries
	// require registration for and others reject outright; where it is not
	// accepted the carrier substitutes its own sender, and recipients cannot
	// reply. Deployments serving those regions configure a real number instead.
	fallbackOriginator = "Authn"
)

// MessageBirdProvider sends messages through MessageBird.
type MessageBirdProvider struct {
	// accessKey authenticates the account.
	accessKey string
	// originator is the sender shown to the recipient: a phone number or an
	// alphanumeric label.
	originator string
	// httpClient is reused across sends so connections are pooled.
	httpClient *http.Client
}

// NewMessageBirdProvider constructs a MessageBird-backed provider, defaulting
// the originator when none is configured.
func NewMessageBirdProvider(accessKey string, originator string) *MessageBirdProvider {
	if originator == "" {
		originator = fallbackOriginator
	}
	return &MessageBirdProvider{
		accessKey:  accessKey,
		originator: originator,
		httpClient: &http.Client{Timeout: providerHTTPTimeout},
	}
}

// messageBirdSendRequest is the send-message request body.
type messageBirdSendRequest struct {
	// Originator is the sender shown to the recipient.
	Originator string `json:"originator"`
	// Recipients lists the destination numbers; this driver always sends to
	// exactly one.
	Recipients []string `json:"recipients"`
	// Body is the message text.
	Body string `json:"body"`
}

// messageBirdError is one entry in a MessageBird error list.
type messageBirdError struct {
	// Code is the MessageBird error number.
	Code int `json:"code"`
	// Description explains the failure.
	Description string `json:"description"`
}

// messageBirdSendResponse is the send-message response body.
type messageBirdSendResponse struct {
	// ID identifies the accepted message.
	ID string `json:"id"`
	// Errors is non-empty when the request was rejected.
	Errors []messageBirdError `json:"errors,omitempty"`
}

// SendSMS delivers one message through MessageBird.
//
// Returns an error when the access key is unset, the request cannot be built or
// executed, the API answers 4xx or 5xx, or the response body carries errors.
// Only the first error is reported, since they describe the same rejection.
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

	req, err := http.NewRequestWithContext(ctx, "POST", messageBirdSendEndpoint, bytes.NewBuffer(bodyBytes))
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

	// An unparseable body on a success status is treated as success; only a
	// populated error list contradicts the status.
	var parsed messageBirdSendResponse
	if err := json.Unmarshal(respBytes, &parsed); err == nil && len(parsed.Errors) > 0 {
		return fmt.Errorf("messagebird error (%d): %s", parsed.Errors[0].Code, parsed.Errors[0].Description)
	}

	return nil
}
