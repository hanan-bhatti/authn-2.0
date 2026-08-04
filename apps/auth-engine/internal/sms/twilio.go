/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sms/twilio.go
 * Tier: Internal Service Package / SMS Drivers
 *
 * Description: Twilio Programmable SMS/WhatsApp SMSProvider implementation.
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
	"time"
)

// TwilioProvider implements SMSProvider for Twilio.
type TwilioProvider struct {
	accountSID string
	authToken  string
	fromNumber string
	httpClient *http.Client
}

// NewTwilioProvider constructs a new TwilioProvider.
func NewTwilioProvider(accountSID string, authToken string, fromNumber string) *TwilioProvider {
	return &TwilioProvider{
		accountSID: accountSID,
		authToken:  authToken,
		fromNumber: fromNumber,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

type twilioSendResponse struct {
	SID          string `json:"sid"`
	Status       string `json:"status"`
	ErrorCode    *int   `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// SendSMS transmits an SMS/WhatsApp message using Twilio REST API.
func (p *TwilioProvider) SendSMS(ctx context.Context, toPhoneNumber string, message string) error {
	if p.accountSID == "" || p.authToken == "" {
		return fmt.Errorf("twilio account SID or auth token is not configured")
	}

	endpoint := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", p.accountSID)

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

	var tResp twilioSendResponse
	if err := json.Unmarshal(respBytes, &tResp); err == nil && tResp.ErrorCode != nil && *tResp.ErrorCode != 0 {
		return fmt.Errorf("twilio error (%d): %s", *tResp.ErrorCode, tResp.ErrorMessage)
	}

	return nil
}
