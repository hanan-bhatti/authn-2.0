/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sms/aws_sns.go
 * Tier: Internal Service Package / SMS Drivers
 *
 * Description: AWS Simple Notification Service (SNS) SMS SMSProvider implementation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sms

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AWSSNSProvider implements SMSProvider for AWS SNS.
type AWSSNSProvider struct {
	accessKeyID     string
	secretAccessKey string
	region          string
	httpClient      *http.Client
}

// NewAWSSNSProvider constructs a new AWSSNSProvider.
func NewAWSSNSProvider(accessKeyID string, secretAccessKey string, region string) *AWSSNSProvider {
	if region == "" {
		region = "us-east-1"
	}
	return &AWSSNSProvider{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		region:          region,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
	}
}

// SendSMS transmits an SMS message using AWS SNS Publish Query API.
func (p *AWSSNSProvider) SendSMS(ctx context.Context, toPhoneNumber string, message string) error {
	endpoint := fmt.Sprintf("https://sns.%s.amazonaws.com/", p.region)

	data := url.Values{}
	data.Set("Action", "Publish")
	data.Set("PhoneNumber", toPhoneNumber)
	data.Set("Message", message)
	data.Set("Version", "2010-03-31")

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed creating AWS SNS HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p.accessKeyID != "" {
		req.Header.Set("X-Amz-Access-Key", p.accessKeyID)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed executing AWS SNS HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("AWS SNS API error (%d): %s", resp.StatusCode, string(respBytes))
	}

	return nil
}
