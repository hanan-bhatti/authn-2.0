/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sms/twilio.go
 * Tier: Internal Service Package / SMS Drivers
 *
 * Delivery through the Twilio Programmable Messaging REST API.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sms

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// TwilioProvider sends messages through Twilio.
type TwilioProvider struct {
	// accountSID identifies the Twilio account and appears in the request path
	// as well as in the credentials.
	accountSID string
	// authToken is the account's secret, sent as the HTTP Basic password.
	authToken string
	// fromNumber is the sending number or messaging service. Twilio requires it
	// to be a number owned by the account.
	fromNumber string
	// httpClient is reused across sends so connections are pooled.
	httpClient *http.Client
}

// NewTwilioProvider constructs a Twilio-backed provider.
func NewTwilioProvider(accountSID string, authToken string, fromNumber string) *TwilioProvider {
	return &TwilioProvider{
		accountSID: accountSID,
		authToken:  authToken,
		fromNumber: fromNumber,
		httpClient: &http.Client{Timeout: providerHTTPTimeout},
	}
}

// twilioSendResponse is the create-message response body.
type twilioSendResponse struct {
	// SID identifies the created message.
	SID string `json:"sid"`
	// Status is the delivery state at the time of the reply, typically "queued".
	Status string `json:"status"`
	// ErrorCode is a Twilio error number, nil when none occurred. It is a
	// pointer so that an absent field is distinguishable from a zero code.
	ErrorCode *int `json:"error_code,omitempty"`
	// ErrorMessage describes the failure when ErrorCode is set.
	ErrorMessage string `json:"error_message,omitempty"`
}

// SendSMS delivers one message through Twilio.
//
// Returns an error when credentials are unset, the request cannot be built or
// executed, the API answers 4xx or 5xx, or the response carries a non-zero
// error code. The body is inspected as well as the status because Twilio
// reports some per-message failures — an unreachable or blocked number among
// them — inside an otherwise successful response.
func (p *TwilioProvider) SendSMS(ctx context.Context, toPhoneNumber string, message string) error {
	if p.accountSID == "" || p.authToken == "" {
		return fmt.Errorf("twilio account SID or auth token is not configured")
	}

	endpoint := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", p.accountSID)

	// Twilio's messaging API predates its JSON endpoints and takes form
	// encoding. url.Values escapes the values, so a message body containing an
	// ampersand cannot add parameters of its own.
	data := url.Values{}
	data.Set("To", toPhoneNumber)
	data.Set("From", p.fromNumber)
	data.Set("Body", message)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed creating twilio HTTP request: %w", err)
	}

	req.SetBasicAuth(p.accountSID, p.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed executing twilio HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("twilio API error (%d): %s", resp.StatusCode, string(respBytes))
	}

	// An unparseable body on a success status is treated as success; only an
	// explicit non-zero error code contradicts the status.
	var parsed twilioSendResponse
	if err := json.Unmarshal(respBytes, &parsed); err == nil && parsed.ErrorCode != nil && *parsed.ErrorCode != 0 {
		return fmt.Errorf("twilio error (%d): %s", *parsed.ErrorCode, parsed.ErrorMessage)
	}

	return nil
}
