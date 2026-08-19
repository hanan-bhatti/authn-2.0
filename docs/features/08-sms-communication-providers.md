# Feature 08: SMS & WhatsApp Communication Drivers (FR-3)

**Module**: `apps/auth-engine/internal/sms`  
**Version**: 1.0.0  
**Status**: Implemented, Production-Ready & Verified  

---

## 1. Overview

The **SMS & WhatsApp Communication Driver Package** provides pluggable telephony drivers for the Authn Platform (FR-3). It features a provider-agnostic `SMSProvider` interface, production drivers for Twilio, MessageBird, and AWS SNS, a No-op logging driver for testing, and factory-based configuration routing.

---

## 2. Pluggable Architecture & Drivers

### 2.1 `SMSProvider` Interface ([`internal/sms/provider.go`](../../apps/auth-engine/internal/sms/provider.go))
```go
type SMSProvider interface {
	SendSMS(ctx context.Context, toPhoneNumber string, message string) error
}
```

### 2.2 Implemented Drivers & Factory
1. **Twilio Driver ([`internal/sms/twilio.go`](../../apps/auth-engine/internal/sms/twilio.go))**: Integrates with Twilio Programmable Messaging API using `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_FROM_NUMBER`.
2. **MessageBird Driver ([`internal/sms/messagebird.go`](../../apps/auth-engine/internal/sms/messagebird.go))**: Integrates with MessageBird REST API using `MESSAGEBIRD_ACCESS_KEY` and `MESSAGEBIRD_ORIGINATOR`.
3. **AWS SNS Driver ([`internal/sms/aws_sns.go`](../../apps/auth-engine/internal/sms/aws_sns.go))**: Integrates with AWS SNS Publish API using `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION`.
4. **No-op Driver ([`internal/sms/noop.go`](../../apps/auth-engine/internal/sms/noop.go))**: Fallback logger for unconfigured or test environments.

### 2.3 Factory & Driver Selection ([`internal/sms/factory.go`](../../apps/auth-engine/internal/sms/factory.go))
The SMS driver is selected via `SMS_DRIVER` in `.env`:
```bash
SMS_DRIVER=noop # "twilio" | "messagebird" | "aws_sns" | "noop"
```

---

## 3. Test-Environment Capture (Sandbox)

In the **test environment the driver is never reached**. `sandbox.WrapSMS` decorates whichever driver section 2.3 selected, and a message sent while acting in `test` is stored for the inbox API instead of dispatched. Live sends are handed to the driver untouched.

Capturing is what makes SMS second-factor enrolment testable at all. The alternative is paying a carrier for every run of the 2FA test, to a handset that has to be in somebody's hand to read the code off — so in practice the flow goes untested.

The one endpoint that deliberately bypasses the wrapper is `POST /v1/tenant/delivery/verify` with `{"channel": "sms"}`, which sends one real message to the signed-in operator's own verified number to prove the credentials above work. See [`18-sandbox-message-inbox.md`](18-sandbox-message-inbox.md).
