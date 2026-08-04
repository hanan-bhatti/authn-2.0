# Feature 08: SMS & WhatsApp Communication Drivers (FR-3)

**Module**: `apps/auth-engine/internal/sms`  
**Version**: 1.0.0  
**Status**: Implemented, Production-Ready & Verified  

---

## 1. Overview

The **SMS & WhatsApp Communication Driver Package** provides pluggable telephony drivers for the Authn Platform (FR-3). It features a provider-agnostic `SMSProvider` interface, production drivers for Twilio, MessageBird, and AWS SNS, a No-op logging driver for testing, and factory-based configuration routing.

---

## 2. Pluggable Architecture & Drivers

### 2.1 `SMSProvider` Interface ([`internal/sms/provider.go`](file:///home/hanan-bhatti/authn/apps/auth-engine/internal/sms/provider.go))
```go
type SMSProvider interface {
	SendSMS(ctx context.Context, toPhoneNumber string, message string) error
}
```

### 2.2 Implemented Drivers & Factory
1. **Twilio Driver ([`internal/sms/twilio.go`](file:///home/hanan-bhatti/authn/apps/auth-engine/internal/sms/twilio.go))**: Integrates with Twilio Programmable Messaging API using `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_FROM_NUMBER`.
2. **MessageBird Driver ([`internal/sms/messagebird.go`](file:///home/hanan-bhatti/authn/apps/auth-engine/internal/sms/messagebird.go))**: Integrates with MessageBird REST API using `MESSAGEBIRD_ACCESS_KEY` and `MESSAGEBIRD_ORIGINATOR`.
3. **AWS SNS Driver ([`internal/sms/aws_sns.go`](file:///home/hanan-bhatti/authn/apps/auth-engine/internal/sms/aws_sns.go))**: Integrates with AWS SNS Publish API using `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION`.
4. **No-op Driver ([`internal/sms/noop.go`](file:///home/hanan-bhatti/authn/apps/auth-engine/internal/sms/noop.go))**: Fallback logger for unconfigured or test environments.

### 2.3 Factory & Driver Selection ([`internal/sms/factory.go`](file:///home/hanan-bhatti/authn/apps/auth-engine/internal/sms/factory.go))
The SMS driver is selected via `SMS_DRIVER` in `.env`:
```bash
SMS_DRIVER=noop # "twilio" | "messagebird" | "aws_sns" | "noop"
```
