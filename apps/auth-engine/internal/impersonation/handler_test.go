/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/impersonation/handler_test.go
 * Tier: Internal Feature Package / Impersonation HTTP Handler Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package impersonation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/impersonation"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockStepUpVerifier struct{}

func (m *mockStepUpVerifier) VerifyAdminPassword(ctx context.Context, userID string, password string) error {
	if password == "CorrectAdminPassword123!" {
		return nil
	}
	return fmt.Errorf("invalid password")
}

func (m *mockStepUpVerifier) VerifyAdminTOTP(ctx context.Context, userID string, code string) error {
	if code == "123456" {
		return nil
	}
	return fmt.Errorf("invalid totp code")
}

func TestImpersonationHTTPHandlers(t *testing.T) {
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:impersonation_handler_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	sysCtx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(sysCtx, "", "")

	tnt, err := client.Tenant.Create().SetID("tnt_imph").SetName("Impersonation Handler Tenant").SetSlug("tnt-imph").Save(sysCtx)
	require.NoError(t, err)

	cfg := &config.Config{
		EncryptionKey: "test_encryption_key_32_bytes_12345",
	}

	policyRepo := policy.NewRepository(factory)
	svc := impersonation.NewService(factory, cfg)
	verifier := &mockStepUpVerifier{}
	handler := impersonation.NewHandler(svc, policyRepo, verifier)

	// Create Admin User & Target User & Other Admin User
	adminUser, err := client.User.Create().SetID("usr_admin10").SetTenantID(tnt.ID).SetEmail("admin10@example.com").SetName("Admin 10").SetStatus("active").Save(sysCtx)
	require.NoError(t, err)

	targetUser, err := client.User.Create().SetID("usr_target10").SetTenantID(tnt.ID).SetEmail("target10@example.com").SetName("Target 10").SetStatus("active").Save(sysCtx)
	require.NoError(t, err)

	otherAdmin, err := client.User.Create().SetID("usr_admin11").SetTenantID(tnt.ID).SetEmail("admin11@example.com").SetName("Other Admin 11").SetStatus("active").Save(sysCtx)
	require.NoError(t, err)

	// Assign admin role to otherAdmin
	roleAdmin, err := client.Role.Create().SetID("rol_admin11").SetTenantID(tnt.ID).SetName("Tenant Admin").SetSlug("tenant_admin").Save(sysCtx)
	require.NoError(t, err)
	_, err = client.UserRole.Create().SetID("ur_admin11").SetUserID(otherAdmin.ID).SetRoleID(roleAdmin.ID).Save(sysCtx)
	require.NoError(t, err)

	// Setup Fiber App with middleware mock context
	app := fiber.New()
	adminMwMock := func(c *fiber.Ctx) error {
		c.Locals("tenant_id", tnt.ID)
		c.Locals("environment", "test")
		c.Locals("console_user_id", adminUser.ID)
		return c.Next()
	}
	clientMwMock := func(c *fiber.Ctx) error {
		return c.Next()
	}
	handler.RegisterRoutes(app, adminMwMock, clientMwMock, nil)

	// 1. GET /v1/tenant/impersonation-policy -> 200 OK
	reqGetPol := httptest.NewRequest("GET", "/v1/tenant/impersonation-policy", nil)
	respGetPol, err := app.Test(reqGetPol)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respGetPol.StatusCode)

	// 2. PUT /v1/tenant/impersonation-policy -> 422 Unprocessable Entity (Invalid duration 999)
	badPolBody, _ := json.Marshal(map[string]interface{}{
		"max_duration_minutes": 999,
	})
	reqPutBad := httptest.NewRequest("PUT", "/v1/tenant/impersonation-policy", bytes.NewReader(badPolBody))
	reqPutBad.Header.Set("Content-Type", "application/json")
	respPutBad, err := app.Test(reqPutBad)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnprocessableEntity, respPutBad.StatusCode)

	// 3. Initiate Impersonation WITHOUT Step-Up Verification -> 400 Bad Request (admin_step_up_required)
	noStepUpBody, _ := json.Marshal(map[string]interface{}{
		"reason": "Investigating billing issue #4092",
	})
	reqNoStepUp := httptest.NewRequest("POST", "/v1/admin/users/"+targetUser.ID+"/impersonate", bytes.NewReader(noStepUpBody))
	reqNoStepUp.Header.Set("Content-Type", "application/json")
	respNoStepUp, err := app.Test(reqNoStepUp)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, respNoStepUp.StatusCode)

	// 4. Initiate Impersonation WITH Invalid Password -> 401 Unauthorized
	wrongPassBody, _ := json.Marshal(map[string]interface{}{
		"reason":              "Investigating billing issue #4092",
		"verification_method": "password",
		"admin_password":      "WrongPassword!",
	})
	reqWrongPass := httptest.NewRequest("POST", "/v1/admin/users/"+targetUser.ID+"/impersonate", bytes.NewReader(wrongPassBody))
	reqWrongPass.Header.Set("Content-Type", "application/json")
	respWrongPass, err := app.Test(reqWrongPass)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, respWrongPass.StatusCode)

	// 5. Initiate Impersonation WITH Correct Password -> 200 OK
	validBody, _ := json.Marshal(map[string]interface{}{
		"reason":              "Investigating billing issue #4092",
		"duration_minutes":    12,
		"verification_method": "password",
		"admin_password":      "CorrectAdminPassword123!",
	})
	reqValid := httptest.NewRequest("POST", "/v1/admin/users/"+targetUser.ID+"/impersonate", bytes.NewReader(validBody))
	reqValid.Header.Set("Content-Type", "application/json")
	respValid, err := app.Test(reqValid)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respValid.StatusCode)

	var resObj impersonation.ImpersonationResult
	err = json.NewDecoder(respValid.Body).Decode(&resObj)
	require.NoError(t, err)
	assert.NotEmpty(t, resObj.AccessToken)
	assert.Equal(t, targetUser.ID, resObj.ImpersonatedUser.ID)
	assert.Equal(t, adminUser.ID, resObj.ImpersonatorID)

	// 6. Impersonate Self -> 400 Bad Request (cannot_impersonate_self)
	reqSelf := httptest.NewRequest("POST", "/v1/admin/users/"+adminUser.ID+"/impersonate", bytes.NewReader(validBody))
	reqSelf.Header.Set("Content-Type", "application/json")
	respSelf, err := app.Test(reqSelf)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, respSelf.StatusCode)

	// 7. Impersonate another Admin -> 403 Forbidden (impersonation_hierarchy_violation)
	reqHierarchy := httptest.NewRequest("POST", "/v1/admin/users/"+otherAdmin.ID+"/impersonate", bytes.NewReader(validBody))
	reqHierarchy.Header.Set("Content-Type", "application/json")
	respHierarchy, err := app.Test(reqHierarchy)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, respHierarchy.StatusCode)

	// 8. Exit Impersonation -> 200 OK
	impToken, err := jwtpkg.IssueImpersonationToken(targetUser.ID, tnt.ID, "test", targetUser.Email, targetUser.Name, "", adminUser.ID, 15*time.Minute, cfg.EncryptionKey)
	require.NoError(t, err)

	reqExit := httptest.NewRequest("POST", "/v1/client/auth/impersonate/exit", nil)
	reqExit.Header.Set("Authorization", "Bearer "+impToken)
	respExit, err := app.Test(reqExit)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, respExit.StatusCode)
}
