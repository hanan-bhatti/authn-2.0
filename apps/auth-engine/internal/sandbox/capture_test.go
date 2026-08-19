package sandbox

import (
	"context"
	"errors"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/sandboxmessage"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/sms"
)

// emailCall is one message that reached the delegate.
type emailCall struct {
	to       string
	subject  string
	htmlBody string
	textBody string
}

// recordingEmailProvider is a delegate that records what reached it, standing in
// for the real provider a live send is expected to arrive at.
type recordingEmailProvider struct {
	calls []emailCall
	err   error
}

func (p *recordingEmailProvider) Send(_ context.Context, to, subject, htmlBody, textBody string) error {
	p.calls = append(p.calls, emailCall{to, subject, htmlBody, textBody})
	return p.err
}

// smsCall is one text message that reached the delegate.
type smsCall struct {
	to      string
	message string
}

// recordingSMSProvider is the SMS counterpart.
type recordingSMSProvider struct {
	calls []smsCall
	err   error
}

func (p *recordingSMSProvider) SendSMS(_ context.Context, to, message string) error {
	p.calls = append(p.calls, smsCall{to, message})
	return p.err
}

// TestCapturingDecision covers every scope a send can arrive on.
//
// The live and unscoped rows are the ones that matter. Capturing a message the
// engine should have delivered means a real person never receives their password
// reset, so anything short of an explicit test scope has to fall through to the
// provider.
func TestCapturingDecision(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{
			name: "test scope captures",
			ctx:  testCtx(tenantA, "test"),
			want: true,
		},
		{
			name: "live scope delivers",
			ctx:  testCtx(tenantA, "live"),
			want: false,
		},
		{
			name: "a bypass delivers, because it carries no environment to judge",
			ctx:  privacy.NewBypassContext(context.Background()),
			want: false,
		},
		{
			name: "no privacy context delivers",
			ctx:  context.Background(),
			want: false,
		},
		{
			name: "test environment without a tenant delivers, having no inbox to file under",
			ctx:  testCtx("", "test"),
			want: false,
		},
		{
			name: "an unrecognised environment delivers",
			ctx:  testCtx(tenantA, "staging"),
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := capturing(tc.ctx); got != tc.want {
				t.Fatalf("capturing() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWrapEmailCapturesTestTraffic confirms a test-environment send lands in the
// inbox, never reaches the provider, and arrives with the code and link already
// lifted out of the body.
func TestWrapEmailCapturesTestTraffic(t *testing.T) {
	store, _ := newTestStore(t)
	delegate := &recordingEmailProvider{}
	provider := WrapEmail(delegate, store)

	const link = "https://app.test/v1/client/auth/verify-email?token=vrf_abc123"
	htmlBody, textBody, err := email.RenderVerificationEmail(email.VerificationEmailData{
		UserName:         "Ada",
		VerificationLink: link,
		AppName:          "Authn Platform",
		ExpiresInHours:   24,
	})
	if err != nil {
		t.Fatalf("rendering verification email: %v", err)
	}

	ctx := testCtx(tenantA, "test")
	if err := provider.Send(ctx, "ada@example.test", email.SubjectEmailVerification, htmlBody, textBody); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if len(delegate.calls) != 0 {
		t.Fatalf("the provider received %d test-environment messages, want 0", len(delegate.calls))
	}

	messages, total, err := store.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 {
		t.Fatalf("captured %d messages, want 1", total)
	}

	captured := messages[0]
	if captured.Channel != sandboxmessage.ChannelEmail {
		t.Errorf("channel = %q, want email", captured.Channel)
	}
	if captured.Recipient != "ada@example.test" {
		t.Errorf("recipient = %q, want ada@example.test", captured.Recipient)
	}
	if captured.Subject != email.SubjectEmailVerification {
		t.Errorf("subject = %q, want the verification subject", captured.Subject)
	}
	if captured.Template != "email_verification" {
		t.Errorf("template = %q, want email_verification", captured.Template)
	}
	if captured.Body != htmlBody {
		t.Error("body is not the rendered html the provider would have received")
	}
	if captured.Metadata["link"] != link {
		t.Errorf("metadata link = %v, want %q", captured.Metadata["link"], link)
	}
	if captured.Metadata["text_body"] != textBody {
		t.Error("the plain-text alternative was not kept alongside the html")
	}
	// A verification email carries a link rather than a code, and reporting one
	// anyway would mean the extractor read a value out of the stylesheet.
	if captured.Code != "" {
		t.Errorf("code = %q, want empty for a link-bearing message", captured.Code)
	}
}

// TestWrapEmailCapturesCode confirms the second-factor code reaches its own
// column, which is the field a harness completes the flow from.
func TestWrapEmailCapturesCode(t *testing.T) {
	store, _ := newTestStore(t)
	provider := WrapEmail(&recordingEmailProvider{}, store)

	ctx := testCtx(tenantA, "test")
	err := provider.Send(ctx, "ada@example.test", email.SubjectTwoFactorCode,
		"<p>Your 2FA verification code is: <strong>445566</strong> (expires in 10 minutes)</p>",
		"Your 2FA verification code is: 445566 (expires in 10 minutes)")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	messages, _, err := store.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("captured %d messages, want 1", len(messages))
	}
	if messages[0].Code != "445566" {
		t.Errorf("code = %q, want 445566", messages[0].Code)
	}
	if messages[0].Template != "two_factor_code" {
		t.Errorf("template = %q, want two_factor_code", messages[0].Template)
	}
}

// TestWrapEmailDeliversOutsideTest confirms a live send reaches the provider
// untouched and is not filed in any inbox.
func TestWrapEmailDeliversOutsideTest(t *testing.T) {
	store, _ := newTestStore(t)
	delegate := &recordingEmailProvider{}
	provider := WrapEmail(delegate, store)

	for _, ctx := range []context.Context{
		testCtx(tenantA, "live"),
		privacy.NewBypassContext(context.Background()),
		context.Background(),
	} {
		if err := provider.Send(ctx, "ada@example.test", "Subject", "<p>html</p>", "text"); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	if len(delegate.calls) != 3 {
		t.Fatalf("the provider received %d messages, want all 3", len(delegate.calls))
	}
	if delegate.calls[0].htmlBody != "<p>html</p>" || delegate.calls[0].textBody != "text" {
		t.Error("the wrapper altered a message it was only meant to pass through")
	}

	if _, total, _ := store.List(testCtx(tenantA, "test"), Filter{}); total != 0 {
		t.Errorf("%d live messages were filed in the test inbox", total)
	}
}

// TestWrapEmailSurfacesProviderError confirms a delegate's rejection still reaches
// the caller, so wrapping does not turn a failed send into a silent success.
func TestWrapEmailSurfacesProviderError(t *testing.T) {
	store, _ := newTestStore(t)
	sentinel := errors.New("provider rejected the message")
	provider := WrapEmail(&recordingEmailProvider{err: sentinel}, store)

	err := provider.Send(testCtx(tenantA, "live"), "ada@example.test", "Subject", "<p>html</p>", "text")
	if !errors.Is(err, sentinel) {
		t.Fatalf("Send error = %v, want the provider's own error", err)
	}
}

// TestWrapEmailSurfacesCaptureError confirms a failed capture is reported rather
// than swallowed. A caller that logs and continues keeps doing so, but the reason
// the message never arrived stays visible.
func TestWrapEmailSurfacesCaptureError(t *testing.T) {
	store, _ := newTestStore(t)
	provider := WrapEmail(&recordingEmailProvider{}, store)

	// A tenant that does not exist fails the row's required tenant edge, which is
	// the realistic way a capture fails.
	err := provider.Send(testCtx("tnt_missing", "test"), "ada@example.test", "Subject", "<p>html</p>", "text")
	if err == nil {
		t.Fatal("Send reported success for a capture that could not be written")
	}
}

// TestWrapSMSCapturesTestTraffic confirms a text message is captured with its code
// and never billed to a carrier.
func TestWrapSMSCapturesTestTraffic(t *testing.T) {
	store, _ := newTestStore(t)
	delegate := &recordingSMSProvider{}
	provider := WrapSMS(delegate, store)

	ctx := testCtx(tenantA, "test")
	if err := provider.SendSMS(ctx, "+15550001111", "Your Authn verification code is: 778899"); err != nil {
		t.Fatalf("SendSMS: %v", err)
	}

	if len(delegate.calls) != 0 {
		t.Fatalf("the carrier received %d test-environment messages, want 0", len(delegate.calls))
	}

	messages, _, err := store.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("captured %d messages, want 1", len(messages))
	}

	captured := messages[0]
	if captured.Channel != sandboxmessage.ChannelSms {
		t.Errorf("channel = %q, want sms", captured.Channel)
	}
	if captured.Recipient != "+15550001111" {
		t.Errorf("recipient = %q, want the E.164 number", captured.Recipient)
	}
	if captured.Code != "778899" {
		t.Errorf("code = %q, want 778899", captured.Code)
	}
	if captured.Template != smsTemplate {
		t.Errorf("template = %q, want %q", captured.Template, smsTemplate)
	}
	if captured.Subject != "" {
		t.Errorf("subject = %q, want empty for sms", captured.Subject)
	}
}

// TestWrapSMSDeliversOutsideTest confirms a live text message reaches the carrier.
func TestWrapSMSDeliversOutsideTest(t *testing.T) {
	store, _ := newTestStore(t)
	delegate := &recordingSMSProvider{}
	provider := WrapSMS(delegate, store)

	if err := provider.SendSMS(testCtx(tenantA, "live"), "+15550001111", "Your Authn verification code is: 778899"); err != nil {
		t.Fatalf("SendSMS: %v", err)
	}

	if len(delegate.calls) != 1 {
		t.Fatalf("the carrier received %d messages, want 1", len(delegate.calls))
	}
	if delegate.calls[0].message != "Your Authn verification code is: 778899" {
		t.Error("the wrapper altered a message it was only meant to pass through")
	}
}

// TestWrapWithoutStoreReturnsDelegate confirms a deployment that failed to build
// the sandbox keeps its ordinary provider, rather than ending up with one that
// discards mail.
func TestWrapWithoutStoreReturnsDelegate(t *testing.T) {
	emailDelegate := &recordingEmailProvider{}
	if got := WrapEmail(emailDelegate, nil); got != email.EmailProvider(emailDelegate) {
		t.Error("WrapEmail with no store did not return the delegate untouched")
	}
	if got := WrapEmail(nil, nil); got != nil {
		t.Error("WrapEmail with no delegate returned something to send through")
	}

	smsDelegate := &recordingSMSProvider{}
	if got := WrapSMS(smsDelegate, nil); got != sms.SMSProvider(smsDelegate) {
		t.Error("WrapSMS with no store did not return the delegate untouched")
	}
	if got := WrapSMS(nil, nil); got != nil {
		t.Error("WrapSMS with no delegate returned something to send through")
	}
}
