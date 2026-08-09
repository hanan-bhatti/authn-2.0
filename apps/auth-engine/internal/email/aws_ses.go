/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/aws_ses.go
 * Tier: Internal Service Package / Email Drivers
 *
 * Delivery through the AWS SES v2 HTTP API.
 *
 * Authentication is incomplete. SES requires every request to carry a
 * Signature Version 4 Authorization header computed from the secret access key
 * over a canonical form of the request; this driver sends the access key ID in
 * an X-Amz-Access-Key header instead, which is not a header AWS defines, and
 * never uses the secret at all. AWS rejects such requests, so this driver
 * cannot deliver against a real SES endpoint until SigV4 signing is
 * implemented. Deployments needing SES today should route through SMTP, for
 * which SES exposes credentials that work with the smtp driver.
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

// defaultAWSRegion is used when configuration names no region. SES is
// regional and the endpoint hostname embeds the region, so some value is
// required to build a URL at all.
const defaultAWSRegion = "us-east-1"

// AWSSESProvider delivers mail through AWS SES v2.
type AWSSESProvider struct {
	// accessKeyID identifies the AWS credential.
	accessKeyID string
	// secretAccessKey is retained for the SigV4 signing this driver does not
	// yet perform. It is never transmitted.
	secretAccessKey string
	// region selects the regional SES endpoint.
	region string
	// fromAddress is the sender; SES requires the address or its domain to be a
	// verified identity in this region.
	fromAddress string
	// httpClient is reused across sends so connections are pooled.
	httpClient *http.Client
}

// NewAWSSESProvider constructs an SES-backed provider, defaulting the region
// when none is configured.
func NewAWSSESProvider(accessKeyID string, secretAccessKey string, region string, fromAddress string) *AWSSESProvider {
	if region == "" {
		region = defaultAWSRegion
	}
	return &AWSSESProvider{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		region:          region,
		fromAddress:     fromAddress,
		httpClient:      &http.Client{Timeout: providerHTTPTimeout},
	}
}

// sesContentObj is a text value with its character set.
type sesContentObj struct {
	// Data is the text itself.
	Data string `json:"Data"`
	// Charset is the encoding, always UTF-8 here.
	Charset string `json:"Charset,omitempty"`
}

// sesBodyObj holds the message body alternatives. Both are pointers so an
// absent alternative is omitted rather than sent as an empty string, which SES
// rejects.
type sesBodyObj struct {
	// Html is the HTML alternative.
	Html *sesContentObj `json:"Html,omitempty"`
	// Text is the plain-text alternative.
	Text *sesContentObj `json:"Text,omitempty"`
}

// sesMessageObj is a simple (non-raw) SES message.
type sesMessageObj struct {
	// Subject is the message subject.
	Subject sesContentObj `json:"Subject"`
	// Body holds the alternatives.
	Body sesBodyObj `json:"Body"`
}

// sesSendRequest is the outbound-email request body.
type sesSendRequest struct {
	// FromEmailAddress is the verified sender identity.
	FromEmailAddress string `json:"FromEmailAddress"`
	// Destination lists the recipients.
	Destination struct {
		ToAddresses []string `json:"ToAddresses"`
	} `json:"Destination"`
	// Content carries the message; the Simple form lets SES assemble the MIME
	// structure rather than requiring a pre-built raw message.
	Content struct {
		Simple sesMessageObj `json:"Simple"`
	} `json:"Content"`
}

// Send delivers one message through SES.
//
// Returns an error when the request cannot be built or executed, or when SES
// answers 4xx or 5xx. Because requests are not SigV4-signed, SES answers 403
// and this returns an error for every send against a real endpoint.
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
