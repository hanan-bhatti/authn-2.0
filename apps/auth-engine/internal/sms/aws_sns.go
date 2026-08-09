/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sms/aws_sns.go
 * Tier: Internal Service Package / SMS Drivers
 *
 * Delivery through the AWS SNS Publish API.
 *
 * Authentication is incomplete. SNS requires every request to carry a Signature
 * Version 4 Authorization header computed from the secret access key over a
 * canonical form of the request; this driver sends the access key ID in an
 * X-Amz-Access-Key header instead, which is not a header AWS defines, and never
 * uses the secret at all. AWS rejects such requests, so this driver cannot
 * deliver against a real SNS endpoint until SigV4 signing is implemented.
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
)

const (
	// defaultAWSRegion is used when configuration names no region. SNS is
	// regional and the endpoint hostname embeds the region, so some value is
	// required to build a URL at all.
	defaultAWSRegion = "us-east-1"

	// snsAPIVersion pins the SNS Query API revision. The API is versioned by
	// parameter rather than by path, so omitting it leaves the revision to the
	// service's discretion.
	snsAPIVersion = "2010-03-31"
)

// AWSSNSProvider sends messages through AWS SNS.
type AWSSNSProvider struct {
	// accessKeyID identifies the AWS credential.
	accessKeyID string
	// secretAccessKey is retained for the SigV4 signing this driver does not
	// yet perform. It is never transmitted.
	secretAccessKey string
	// region selects the regional SNS endpoint.
	region string
	// httpClient is reused across sends so connections are pooled.
	httpClient *http.Client
}

// NewAWSSNSProvider constructs an SNS-backed provider, defaulting the region
// when none is configured.
func NewAWSSNSProvider(accessKeyID string, secretAccessKey string, region string) *AWSSNSProvider {
	if region == "" {
		region = defaultAWSRegion
	}
	return &AWSSNSProvider{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		region:          region,
		httpClient:      &http.Client{Timeout: providerHTTPTimeout},
	}
}

// SendSMS delivers one message through SNS.
//
// Publishing to a bare phone number rather than to a topic is what makes this a
// direct SMS send; SNS treats the presence of PhoneNumber as selecting that
// mode.
//
// Returns an error when the request cannot be built or executed, or when SNS
// answers 4xx or 5xx. Because requests are not SigV4-signed, SNS answers 403
// and this returns an error for every send against a real endpoint.
func (p *AWSSNSProvider) SendSMS(ctx context.Context, toPhoneNumber string, message string) error {
	endpoint := fmt.Sprintf("https://sns.%s.amazonaws.com/", p.region)

	// The SNS Query API takes form-encoded parameters. url.Values escapes the
	// values, so a message body containing an ampersand cannot add parameters
	// of its own.
	data := url.Values{}
	data.Set("Action", "Publish")
	data.Set("PhoneNumber", toPhoneNumber)
	data.Set("Message", message)
	data.Set("Version", snsAPIVersion)

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
