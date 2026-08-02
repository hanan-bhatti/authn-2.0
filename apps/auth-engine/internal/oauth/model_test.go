package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerifyPKCE_S256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// S256 mode match
	match := VerifyPKCE(verifier, challenge, "S256")
	if !match {
		t.Fatalf("expected PKCE S256 match for valid verifier")
	}

	// S256 mode mismatch
	mismatch := VerifyPKCE("wrong_verifier", challenge, "S256")
	if mismatch {
		t.Fatalf("expected PKCE S256 mismatch for invalid verifier")
	}
}

func TestVerifyPKCE_Plain(t *testing.T) {
	verifier := "my_plain_verifier_string"

	match := VerifyPKCE(verifier, verifier, "plain")
	if !match {
		t.Fatalf("expected plain PKCE match")
	}

	mismatch := VerifyPKCE(verifier, "different", "plain")
	if mismatch {
		t.Fatalf("expected plain PKCE mismatch")
	}
}
