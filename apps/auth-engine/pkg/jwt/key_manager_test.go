/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/jwt/key_manager_test.go
 * Tier: Unit Testing Layer / JWKS Key Rotation
 *
 * Description: Unit tests verifying JWKS key rotation, multi-key export,
 *              7-day grace period key retention, and kid-based JWT signature verification.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package jwt

import (
	"testing"
	"time"
)

func TestJWKSKeyRotationAndVerification(t *testing.T) {
	km, err := NewKeyManager("key_v1")
	if err != nil {
		t.Fatalf("failed creating KeyManager: %v", err)
	}

	// 1. Check initial JWKS exports 1 active key
	jwks1 := km.GetPublicJWKS()
	if len(jwks1.Keys) != 1 {
		t.Fatalf("expected 1 key in initial JWKS, got %d", len(jwks1.Keys))
	}
	if jwks1.Keys[0].Kid != "key_v1" {
		t.Errorf("expected initial key id 'key_v1', got '%s'", jwks1.Keys[0].Kid)
	}

	// 2. Sign token with key_v1
	claims1 := map[string]interface{}{
		"sub": "usr_test123",
		"iss": "authn-engine",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}
	token1, err := km.SignToken(claims1)
	if err != nil {
		t.Fatalf("failed signing token with key_v1: %v", err)
	}

	// Verify token1 with key_v1
	verifiedClaims1, err := km.VerifyToken(token1)
	if err != nil {
		t.Fatalf("failed verifying token1 with key_v1: %v", err)
	}
	if verifiedClaims1["sub"] != "usr_test123" {
		t.Errorf("expected sub 'usr_test123', got '%v'", verifiedClaims1["sub"])
	}

	// 3. Manually trigger key rotation to key_v2
	rotatedKey, err := km.RotateKey("key_v2")
	if err != nil {
		t.Fatalf("failed rotating key: %v", err)
	}
	if rotatedKey.ID != "key_v2" {
		t.Errorf("expected rotated key ID 'key_v2', got '%s'", rotatedKey.ID)
	}

	// 4. Confirm JWKS now exports 2 keys (Active key_v2 + Grace key_v1)
	jwks2 := km.GetPublicJWKS()
	if len(jwks2.Keys) != 2 {
		t.Fatalf("expected 2 keys in JWKS after rotation, got %d", len(jwks2.Keys))
	}

	// 5. Confirm token signed with OLD key (key_v1) STILL verifies successfully (grace period working!)
	graceClaims, err := km.VerifyToken(token1)
	if err != nil {
		t.Fatalf("grace period failure: old token signed with key_v1 failed verification: %v", err)
	}
	if graceClaims["sub"] != "usr_test123" {
		t.Errorf("expected sub 'usr_test123', got '%v'", graceClaims["sub"])
	}

	// 6. Sign NEW token (token2) -> should be signed with NEW active key (key_v2)
	claims2 := map[string]interface{}{
		"sub": "usr_test456",
		"iss": "authn-engine",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}
	token2, err := km.SignToken(claims2)
	if err != nil {
		t.Fatalf("failed signing token with key_v2: %v", err)
	}

	verifiedClaims2, err := km.VerifyToken(token2)
	if err != nil {
		t.Fatalf("failed verifying token2 with key_v2: %v", err)
	}
	if verifiedClaims2["sub"] != "usr_test456" {
		t.Errorf("expected sub 'usr_test456', got '%v'", verifiedClaims2["sub"])
	}
}
