/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/oauth/discovery_test.go
 * Tier: OIDC Standard Integration Tests
 *
 * Description: Tests RFC 8414 OpenID Connect Discovery metadata endpoint (GET /.well-known/openid-configuration).
 *              Verifies HTTP method enforcement, auth independence, exact issuer alignment, cache headers,
 *              and endpoint resolution.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package oauth_test

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/oauth"
)

func TestOIDCDiscoveryEndpoint(t *testing.T) {
	cfg := &config.EnvConfig{
		Issuer: "http://localhost:8080",
	}

	repo := oauth.NewRepository()
	svc := oauth.NewService(repo, nil, nil, cfg)
	handler := oauth.NewHandler(svc)

	app := fiber.New()
	handler.RegisterRoutes(app, nil)

	// 1. Successful GET Request
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	req.Header.Set("Authorization", "Bearer invalid_garbage_token")
	req.Header.Set("X-Publishable-Key", "pk_invalid_123")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed executing discovery request: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	cacheHeader := resp.Header.Get("Cache-Control")
	if cacheHeader != "public, max-age=3600" {
		t.Errorf("expected Cache-Control 'public, max-age=3600', got '%s'", cacheHeader)
	}

	body, _ := io.ReadAll(resp.Body)
	var doc oauth.OIDCDiscoveryConfig
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("failed unmarshaling discovery json: %v", err)
	}

	if doc.Issuer != "http://localhost:8080" {
		t.Errorf("expected issuer 'http://localhost:8080', got '%s'", doc.Issuer)
	}
	if doc.AuthorizationEndpoint != "http://localhost:8080/v1/oauth/authorize" {
		t.Errorf("unexpected authorization endpoint: %s", doc.AuthorizationEndpoint)
	}
	if doc.TokenEndpoint != "http://localhost:8080/v1/oauth/token" {
		t.Errorf("unexpected token endpoint: %s", doc.TokenEndpoint)
	}
	if doc.JwksURI != "http://localhost:8080/v1/oauth/jwks" {
		t.Errorf("unexpected jwks uri: %s", doc.JwksURI)
	}
	if doc.UserinfoEndpoint != "http://localhost:8080/v1/oauth/userinfo" {
		t.Errorf("unexpected userinfo endpoint: %s", doc.UserinfoEndpoint)
	}

	// 2. Non-GET Method Enforcement Check
	postReq := httptest.NewRequest("POST", "/.well-known/openid-configuration", nil)
	postResp, _ := app.Test(postReq)
	if postResp.StatusCode != 405 {
		t.Errorf("expected status 405 for POST, got %d", postResp.StatusCode)
	}
}

func TestJWKSEndpoint(t *testing.T) {
	cfg := &config.EnvConfig{
		AuthnKeyID: "authn-rsa-test-key",
	}

	repo := oauth.NewRepository()
	svc := oauth.NewService(repo, nil, nil, cfg)
	handler := oauth.NewHandler(svc)

	app := fiber.New()
	handler.RegisterRoutes(app, nil)

	req := httptest.NewRequest("GET", "/v1/oauth/jwks", nil)
	req.Header.Set("Authorization", "Bearer invalid_garbage_token")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed executing jwks request: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	cacheHeader := resp.Header.Get("Cache-Control")
	if cacheHeader != "public, max-age=3600" {
		t.Errorf("expected Cache-Control 'public, max-age=3600', got '%s'", cacheHeader)
	}

	body, _ := io.ReadAll(resp.Body)
	var rawMap map[string]interface{}
	if err := json.Unmarshal(body, &rawMap); err != nil {
		t.Fatalf("failed unmarshaling jwks json: %v", err)
	}

	keysRaw, ok := rawMap["keys"].([]interface{})
	if !ok || len(keysRaw) == 0 {
		t.Fatalf("expected non-empty keys array in JWKS")
	}

	keyObj := keysRaw[0].(map[string]interface{})

	// CRITICAL SECURITY AUDIT: Zero private key parameters allowed
	for _, forbiddenParam := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, exists := keyObj[forbiddenParam]; exists {
			t.Fatalf("CRITICAL SECURITY FAILURE: Private key parameter '%s' found in JWKS response!", forbiddenParam)
		}
	}

	// Schema Validation
	if keyObj["kty"] != "RSA" {
		t.Errorf("expected kty 'RSA', got '%v'", keyObj["kty"])
	}
	if keyObj["use"] != "sig" {
		t.Errorf("expected use 'sig', got '%v'", keyObj["use"])
	}
	if keyObj["alg"] != "RS256" {
		t.Errorf("expected alg 'RS256', got '%v'", keyObj["alg"])
	}
	if keyObj["kid"] != "authn-rsa-test-key" {
		t.Errorf("expected kid 'authn-rsa-test-key', got '%v'", keyObj["kid"])
	}
	if keyObj["n"] == "" || keyObj["e"] == "" {
		t.Errorf("expected non-empty RSA modulus (n) and exponent (e)")
	}

	// Non-GET Method Check
	postReq := httptest.NewRequest("POST", "/v1/oauth/jwks", nil)
	postResp, _ := app.Test(postReq)
	if postResp.StatusCode != 405 {
		t.Errorf("expected status 405 for POST, got %d", postResp.StatusCode)
	}
}
