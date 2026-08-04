/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sms/sms_test.go
 * Tier: Internal Service Package / SMS Unit Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sms_test

import (
	"context"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/sms"
	"github.com/stretchr/testify/assert"
)

func TestNoopSMSProvider_Send(t *testing.T) {
	provider := sms.NewNoopProvider()
	err := provider.SendSMS(context.Background(), "+15551234567", "Your Authn code is 123456")
	assert.NoError(t, err)
}

func TestNewSMSProvider_Factory(t *testing.T) {
	tests := []struct {
		name      string
		driver    string
		expectErr bool
	}{
		{"Noop Driver", "noop", false},
		{"Empty Driver Defaults to Noop", "", false},
		{"Twilio Missing Credentials", "twilio", true},
		{"MessageBird Missing Key", "messagebird", true},
		{"AWS SNS Driver", "aws_sns", false},
		{"Unsupported Driver", "unknown_sms_driver", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.EnvConfig{
				SMSDriver: tt.driver,
			}
			p, err := sms.NewSMSProvider(cfg)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, p)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, p)
			}
		})
	}
}
