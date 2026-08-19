package sandbox

import (
	"strings"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
)

// TestExtractOTP covers the shapes the engine actually sends and the shapes that
// must not be mistaken for a code.
func TestExtractOTP(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "plain text second factor",
			body: "Your 2FA verification code is: 123456 (expires in 10 minutes)",
			want: "123456",
		},
		{
			name: "wrapped in markup",
			body: "<p>Your 2FA verification code is: <strong>654321</strong> (expires in 10 minutes)</p>",
			want: "654321",
		},
		{
			name: "sms body",
			body: "Your Authn verification code is: 098765",
			want: "098765",
		},
		{
			name: "leading zeroes are part of the code",
			body: "Code: 000123",
			want: "000123",
		},
		{
			name: "hex colour is not a code",
			body: "border: 1px solid #334155;",
			want: "",
		},
		{
			name: "digits inside an opaque token are not a code",
			body: "https://app.test/verify?token=ab123456cd",
			want: "",
		},
		{
			name: "five digits is not a code",
			body: "Code: 12345",
			want: "",
		},
		{
			name: "seven digits is not a code",
			body: "Reference 1234567 for support",
			want: "",
		},
		{
			name: "no digits at all",
			body: "Someone signed in to your account.",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractOTP(tc.body); got != tc.want {
				t.Fatalf("extractOTP(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

// TestExtractOTPIgnoresRenderedPalette runs the extractor over a message this
// engine really renders.
//
// The template's inlined stylesheet contains a palette value that is six digits
// with no letters in it, so a naive digit pattern reports a border colour as the
// recipient's verification code. Rendering the real template rather than quoting a
// snippet of it means the guard follows the stylesheet if the palette changes.
func TestExtractOTPIgnoresRenderedPalette(t *testing.T) {
	htmlBody, textBody, err := email.RenderVerificationEmail(email.VerificationEmailData{
		UserName:         "Ada",
		VerificationLink: "https://app.test/v1/client/auth/verify-email?token=abc123",
		AppName:          "Authn Platform",
		ExpiresInHours:   24,
	})
	if err != nil {
		t.Fatalf("rendering verification email: %v", err)
	}

	if !strings.Contains(htmlBody, "#334155") {
		t.Fatal("the rendered template no longer contains the six-digit palette value this test guards against; " +
			"confirm the stylesheet still holds no all-digit hex colour before relaxing otpPattern")
	}

	if got := extractOTP(htmlBody); got != "" {
		t.Fatalf("extractOTP read %q out of a message that carries no code", got)
	}
	if got := extractOTP(textBody); got != "" {
		t.Fatalf("extractOTP read %q out of a plain-text body that carries no code", got)
	}
}

// TestExtractLink covers link recovery from both a rendered document and the
// plain-text alternative.
func TestExtractLink(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "href attribute",
			body: `<a href="https://app.test/verify?token=tok_abc123" class="button">Verify</a>`,
			want: "https://app.test/verify?token=tok_abc123",
		},
		{
			name: "bare url in plain text",
			body: "Click the link to verify your new email: https://app.test/v1/client/user/email/verify?token=emc_xyz",
			want: "https://app.test/v1/client/user/email/verify?token=emc_xyz",
		},
		{
			name: "token as a later parameter",
			body: "https://app.test/verify?redirect=%2Fhome&token=tok_abc",
			want: "https://app.test/verify?redirect=%2Fhome&token=tok_abc",
		},
		{
			name: "a link carrying no credential is not lifted",
			body: `<a href="https://app.test/support">Contact support</a>`,
			want: "",
		},
		{
			name: "no link at all",
			body: "Your code is 123456.",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractLink(tc.body); got != tc.want {
				t.Fatalf("extractLink(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

// TestExtractLinkFromRenderedTemplate confirms the link survives the markup the
// template wraps it in, which is what the character class in linkPattern exists
// for.
func TestExtractLinkFromRenderedTemplate(t *testing.T) {
	const link = "https://app.test/v1/client/auth/verify-email?token=vrf_abc123XYZ"

	htmlBody, textBody, err := email.RenderVerificationEmail(email.VerificationEmailData{
		UserName:         "Ada",
		VerificationLink: link,
		AppName:          "Authn Platform",
		ExpiresInHours:   24,
	})
	if err != nil {
		t.Fatalf("rendering verification email: %v", err)
	}

	if got := extractLink(htmlBody); got != link {
		t.Fatalf("extractLink from html = %q, want %q", got, link)
	}
	if got := extractLink(textBody); got != link {
		t.Fatalf("extractLink from text = %q, want %q", got, link)
	}
}

// TestClassifyEmail confirms every subject the engine sends resolves to a
// template identifier, and that an unknown subject resolves to none.
//
// The table is keyed by the sender's own constants, so this also fails if a
// subject constant is added without a matching template identifier.
func TestClassifyEmail(t *testing.T) {
	subjects := []string{
		email.SubjectEmailVerification,
		email.SubjectMagicLink,
		email.SubjectTwoFactorCode,
		email.SubjectImpersonation,
		email.SubjectEmailChange,
		email.SubjectRecoveryEmail,
	}

	for _, subject := range subjects {
		if got := classifyEmail(subject); got == "" {
			t.Errorf("classifyEmail(%q) returned no template identifier", subject)
		}
	}

	if got := classifyEmail("Your weekly digest"); got != "" {
		t.Errorf("classifyEmail on an unknown subject = %q, want an empty string", got)
	}
}
