/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/aws_ses.go
 * Tier: Internal Service Package / Email Drivers
 *
 * Description: AWS SES v2 EmailProvider implementation.
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

// AWSSESProvider implements EmailProvider interface for AWS SES v2 API.
type AWSSESProvider struct {
	accessKeyID     string
	secretAccessKey string
	region          string
	fromAddress     string
	httpClient      *http.Client
}

// NewAWSSESProvider constructs a new AWSSESProvider.
func NewAWSSESProvider(accessKeyID string, secretAccessKey string, region string, fromAddress string) *AWSSESProvider {
	if region == "" {
		region = "us-east-1"
	}
	return &AWSSESProvider{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		region:          region,
		fromAddress:     fromAddress,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
	}
}

type sesContentObj struct {
	Data    string `json:"Data"`
	Charset string `json:"Charset,omitempty"`
}

type sesBodyObj struct {
	Html *sesContentObj `json:"Html,omitempty"`
	Text *sesContentObj `json:"Text,omitempty"`
}

type sesMessageObj struct {
	Subject sesContentObj `json:"Subject"`
	Body    sesBodyObj    `json:"Body"`
}

type sesSendRequest struct {
	FromEmailAddress string `json:"FromEmailAddress"`
	Destination      struct {
		ToAddresses []string `json:"ToAddresses"`
	} `json:"Destination"`
	Content struct {
		Simple sesMessageObj `json:"Simple"`
	} `json:"Content"`
}

// Send transmits an email using AWS SES v2 HTTP API.
func (p *AWSSESProvider) Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error {
	endpoint := fmt.Sprintf("https://email.%s.amazonaws.com/v2/email/outbound-emails", p.region)

	payload := sesSendRequest{
		FromEmailAddress: p.fromAddress,
	}
	payload.Destination.ToAddresses = []string{to}

	msg := sesMessageObj{
		Subject: sesContentObj{Data: subject, Charset: "UTF-8"},
		Body:    sesBodyObj{},
	}
	if htmlBody != "" {
		msg.Body.Html = &sesContentObj{Data: htmlBody, Charset: "UTF-8"}
	}
	if textBody != "" {
		msg.Body.Text = &sesContentObj{Data: textBody, Charset: "UTF-8"}
	}
	payload.Content.Simple = msg

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed marshaling AWS SES payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed creating AWS SES HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if p.accessKeyID != "" {
		req.Header.Set("X-Amz-Access-Key", p.accessKeyID)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed executing AWS SES HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("AWS SES API error (%d): %s", resp.StatusCode, string(respBytes))
	}

	return nil
}
