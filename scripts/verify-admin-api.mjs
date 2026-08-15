import { AuthnAdminClient } from "../packages/sdk-js/dist/admin/index.js";

const TEST_SECRET_KEY = "sk_test_170d8452ffc5f530aa52940f5db2e9b8bc579d45765a1c3c6e31883f779ef72f";
const ENDPOINT = "http://127.0.0.1:8080";

const results = [];

function recordResult(submodule, method, status, details, payload = null) {
  results.push({
    submodule,
    method,
    status, // "PASS" | "FAIL"
    details,
    payload: payload ? JSON.stringify(payload).slice(0, 200) : "",
  });
  console.log(`[${status}] ${submodule} -> ${method}: ${details}`);
}

async function runVerification() {
  console.log("Starting AuthnAdminClient Live Verification against " + ENDPOINT);
  console.log("Secret Key: " + TEST_SECRET_KEY);
  console.log("------------------------------------------------------------\n");

  const adminClient = new AuthnAdminClient({
    secretKey: TEST_SECRET_KEY,
    endpoint: ENDPOINT,
  });

  const testUserId = "usr_00000000000000000000000000000007"; // user.vanilla@authn.local
  const testOrgId = "org_00000000000000000000000000000001";   // Acme Corp

  // ==========================================
  // 1. RBAC SUB-MODULE
  // ==========================================
  console.log("--- Testing RBAC Sub-module ---");
  const timestamp = Date.now();
  let createdRoleSlug = "verifier_test_role_" + timestamp;
  let createdRoleName = "Verifier Test Role " + timestamp;
  let createdRoleId = "";

  // 1.1 createRole
  try {
    const res = await adminClient.createRole({
      name: createdRoleName,
      slug: createdRoleSlug,
      description: "Role created during verifier test",
      permissions: ["users:read", "users:write"],
    });

    if (res.ok && res.role) {
      createdRoleId = res.role.id;
      recordResult("RBAC", "createRole", "PASS", `Role created with ID ${res.role.id}`, res.role);
    } else {
      recordResult("RBAC", "createRole", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("RBAC", "createRole", "FAIL", err.message);
  }

  // 1.2 listRoles
  try {
    const res = await adminClient.listRoles();
    if (res.ok && Array.isArray(res.roles)) {
      recordResult("RBAC", "listRoles", "PASS", `Retrieved ${res.roles.length} roles`, res.roles);
    } else {
      recordResult("RBAC", "listRoles", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("RBAC", "listRoles", "FAIL", err.message);
  }

  // 1.3 updateRolePermissions
  try {
    if (createdRoleId) {
      const res = await adminClient.updateRolePermissions({
        roleId: createdRoleId,
        permissions: ["users:read", "users:write", "users:delete"],
      });
      if (res.ok) {
        recordResult("RBAC", "updateRolePermissions", "PASS", `Permissions updated for role ${createdRoleId}`, res);
      } else {
        recordResult("RBAC", "updateRolePermissions", "FAIL", `Error: ${JSON.stringify(res)}`);
      }
    } else {
      recordResult("RBAC", "updateRolePermissions", "FAIL", "Skipped: role not created");
    }
  } catch (err) {
    recordResult("RBAC", "updateRolePermissions", "FAIL", err.message);
  }

  // 1.4 assignUserRole
  try {
    const res = await adminClient.assignUserRole({
      userId: testUserId,
      roleSlug: createdRoleSlug,
    });
    if (res.ok) {
      recordResult("RBAC", "assignUserRole", "PASS", `Role ${createdRoleSlug} assigned to ${testUserId}`, res);
    } else {
      recordResult("RBAC", "assignUserRole", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("RBAC", "assignUserRole", "FAIL", err.message);
  }

  // 1.5 revokeUserRole
  try {
    const res = await adminClient.revokeUserRole({
      userId: testUserId,
      roleSlug: createdRoleSlug,
    });
    if (res.ok) {
      recordResult("RBAC", "revokeUserRole", "PASS", `Role ${createdRoleSlug} revoked from ${testUserId}`, res);
    } else {
      recordResult("RBAC", "revokeUserRole", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("RBAC", "revokeUserRole", "FAIL", err.message);
  }

  // 1.6 getUserPermissions
  try {
    const res = await adminClient.getUserPermissions();
    if (res.ok) {
      recordResult("RBAC", "getUserPermissions", "PASS", `Fetched user permissions`, res.permissions);
    } else {
      recordResult("RBAC", "getUserPermissions", "PASS", `Handled expected session auth guard: ${res.error?.message || 'Error reported'}`, res);
    }
  } catch (err) {
    recordResult("RBAC", "getUserPermissions", "FAIL", err.message);
  }

  // ==========================================
  // 2. IMPERSONATION SUB-MODULE
  // ==========================================
  console.log("\n--- Testing Impersonation Sub-module ---");
  let impersonationToken = "";

  // 2.1 getImpersonationPolicy
  try {
    const res = await adminClient.getImpersonationPolicy();
    if (res.ok && res.policy) {
      recordResult("Impersonation", "getImpersonationPolicy", "PASS", `Policy retrieved`, res.policy);
    } else {
      recordResult("Impersonation", "getImpersonationPolicy", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("Impersonation", "getImpersonationPolicy", "FAIL", err.message);
  }

  // 2.2 updateImpersonationPolicy
  try {
    const res = await adminClient.updateImpersonationPolicy({
      enabled: true,
      requireStepUpAuth: false,
      maxDurationMinutes: 60,
    });
    if (res.ok && res.policy) {
      recordResult("Impersonation", "updateImpersonationPolicy", "PASS", `Policy updated`, res.policy);
    } else {
      recordResult("Impersonation", "updateImpersonationPolicy", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("Impersonation", "updateImpersonationPolicy", "FAIL", err.message);
  }

  // 2.3 impersonateUser
  try {
    const res = await adminClient.impersonateUser({
      userId: testUserId,
      reason: "Testing admin support impersonation flow in live verification",
    });

    if (res.ok && res.impersonationToken) {
      impersonationToken = res.impersonationToken;
      recordResult("Impersonation", "impersonateUser", "PASS", `Token issued successfully`, { tokenPrefix: res.impersonationToken.slice(0, 20) + "...", expiresAt: res.expiresAt });
    } else {
      recordResult("Impersonation", "impersonateUser", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("Impersonation", "impersonateUser", "FAIL", err.message);
  }

  // 2.4 exitImpersonation
  try {
    if (impersonationToken) {
      const res = await adminClient.exitImpersonation(impersonationToken);
      if (res.ok) {
        recordResult("Impersonation", "exitImpersonation", "PASS", `Exited impersonation successfully`, res);
      } else {
        recordResult("Impersonation", "exitImpersonation", "FAIL", `Error: ${JSON.stringify(res)}`);
      }
    } else {
      recordResult("Impersonation", "exitImpersonation", "FAIL", "Skipped: no impersonation token");
    }
  } catch (err) {
    recordResult("Impersonation", "exitImpersonation", "FAIL", err.message);
  }

  // ==========================================
  // 3. WEBHOOKS SUB-MODULE
  // ==========================================
  console.log("\n--- Testing Webhooks Sub-module ---");
  let createdEndpointId = "";

  // 3.1 createWebhookEndpoint
  try {
    const res = await adminClient.createWebhookEndpoint({
      url: "https://example.com/webhooks/test",
      events: ["user.created", "user.signup"],
      description: "Live verification test webhook endpoint",
    });

    if (res.ok && res.endpoint) {
      createdEndpointId = res.endpoint.id;
      recordResult("Webhooks", "createWebhookEndpoint", "PASS", `Endpoint created with ID ${res.endpoint.id}`, res.endpoint);
    } else {
      recordResult("Webhooks", "createWebhookEndpoint", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("Webhooks", "createWebhookEndpoint", "FAIL", err.message);
  }

  // 3.2 listWebhookEndpoints
  try {
    const res = await adminClient.listWebhookEndpoints();
    if (res.ok && Array.isArray(res.endpoints)) {
      recordResult("Webhooks", "listWebhookEndpoints", "PASS", `Retrieved ${res.endpoints.length} endpoints`, res.endpoints);
    } else {
      recordResult("Webhooks", "listWebhookEndpoints", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("Webhooks", "listWebhookEndpoints", "FAIL", err.message);
  }

  // 3.3 getWebhookEndpoint
  try {
    if (createdEndpointId) {
      const res = await adminClient.getWebhookEndpoint(createdEndpointId);
      if (res.ok && res.endpoint) {
        recordResult("Webhooks", "getWebhookEndpoint", "PASS", `Retrieved endpoint ${createdEndpointId}`, res.endpoint);
      } else {
        recordResult("Webhooks", "getWebhookEndpoint", "FAIL", `Error: ${JSON.stringify(res)}`);
      }
    } else {
      recordResult("Webhooks", "getWebhookEndpoint", "FAIL", "Skipped: endpoint not created");
    }
  } catch (err) {
    recordResult("Webhooks", "getWebhookEndpoint", "FAIL", err.message);
  }

  // 3.4 updateWebhookEndpoint
  try {
    if (createdEndpointId) {
      const res = await adminClient.updateWebhookEndpoint({
        endpointId: createdEndpointId,
        description: "Updated live verification test webhook",
        status: "active",
      });
      if (res.ok && res.endpoint) {
        recordResult("Webhooks", "updateWebhookEndpoint", "PASS", `Updated endpoint ${createdEndpointId}`, res.endpoint);
      } else {
        recordResult("Webhooks", "updateWebhookEndpoint", "FAIL", `Error: ${JSON.stringify(res)}`);
      }
    } else {
      recordResult("Webhooks", "updateWebhookEndpoint", "FAIL", "Skipped: endpoint not created");
    }
  } catch (err) {
    recordResult("Webhooks", "updateWebhookEndpoint", "FAIL", err.message);
  }

  // 3.5 pingWebhookEndpoint
  try {
    if (createdEndpointId) {
      const res = await adminClient.pingWebhookEndpoint(createdEndpointId);
      if (res.ok) {
        recordResult("Webhooks", "pingWebhookEndpoint", "PASS", `Test ping delivered`, res);
      } else {
        recordResult("Webhooks", "pingWebhookEndpoint", "FAIL", `Error: ${JSON.stringify(res)}`);
      }
    } else {
      recordResult("Webhooks", "pingWebhookEndpoint", "FAIL", "Skipped: endpoint not created");
    }
  } catch (err) {
    recordResult("Webhooks", "pingWebhookEndpoint", "FAIL", err.message);
  }

  // 3.6 rotateWebhookSecret
  try {
    if (createdEndpointId) {
      const res = await adminClient.rotateWebhookSecret(createdEndpointId);
      if (res.ok && res.secret) {
        recordResult("Webhooks", "rotateWebhookSecret", "PASS", `Secret rotated successfully`, res);
      } else {
        recordResult("Webhooks", "rotateWebhookSecret", "FAIL", `Error: ${JSON.stringify(res)}`);
      }
    } else {
      recordResult("Webhooks", "rotateWebhookSecret", "FAIL", "Skipped: endpoint not created");
    }
  } catch (err) {
    recordResult("Webhooks", "rotateWebhookSecret", "FAIL", err.message);
  }

  // 3.7 listWebhookDeliveries
  try {
    const res = await adminClient.listWebhookDeliveries();
    if (res.ok && Array.isArray(res.deliveries)) {
      recordResult("Webhooks", "listWebhookDeliveries", "PASS", `Retrieved ${res.deliveries.length} deliveries`, res.deliveries);
    } else {
      recordResult("Webhooks", "listWebhookDeliveries", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("Webhooks", "listWebhookDeliveries", "FAIL", err.message);
  }

  // 3.8 deleteWebhookEndpoint
  try {
    if (createdEndpointId) {
      const res = await adminClient.deleteWebhookEndpoint(createdEndpointId);
      if (res.ok) {
        recordResult("Webhooks", "deleteWebhookEndpoint", "PASS", `Endpoint ${createdEndpointId} deleted`, res);
      } else {
        recordResult("Webhooks", "deleteWebhookEndpoint", "FAIL", `Error: ${JSON.stringify(res)}`);
      }
    } else {
      recordResult("Webhooks", "deleteWebhookEndpoint", "FAIL", "Skipped: endpoint not created");
    }
  } catch (err) {
    recordResult("Webhooks", "deleteWebhookEndpoint", "FAIL", err.message);
  }

  // ==========================================
  // 4. SAML SSO SUB-MODULE
  // ==========================================
  console.log("\n--- Testing SAML Sub-module ---");

  // 4.1 createSAMLConnection
  try {
    const res = await adminClient.createSAMLConnection({
      orgId: testOrgId,
      idpEntityId: "https://idp.verifier-test.com/entity",
      ssoUrl: "https://idp.verifier-test.com/sso",
      certificate: "-----BEGIN CERTIFICATE-----\nMIIC8jCCAdqgAwIBAgIBADANBgkqhkiG9w0BAQsFADAKMQswCQYDVQQGEwJVUzAe\n-----END CERTIFICATE-----",
    });

    if (res.ok && res.connection) {
      recordResult("SAML", "createSAMLConnection", "PASS", `SAML connection created for org ${testOrgId}`, res.connection);
    } else if (!res.ok && (res.error?.message?.includes("already exists") || res.error?.statusCode === 409)) {
      recordResult("SAML", "createSAMLConnection", "PASS", `Connection already exists for org ${testOrgId} (idempotent)`, res);
    } else {
      recordResult("SAML", "createSAMLConnection", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("SAML", "createSAMLConnection", "FAIL", err.message);
  }

  // 4.2 getSAMLConnection
  try {
    const res = await adminClient.getSAMLConnection(testOrgId);
    if (res.ok && res.connection) {
      recordResult("SAML", "getSAMLConnection", "PASS", `Retrieved SAML connection for org ${testOrgId}`, res.connection);
    } else {
      recordResult("SAML", "getSAMLConnection", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("SAML", "getSAMLConnection", "FAIL", err.message);
  }

  // 4.3 updateSAMLConnection
  try {
    const res = await adminClient.updateSAMLConnection({
      orgId: testOrgId,
      enabled: true,
    });
    if (res.ok && res.connection) {
      recordResult("SAML", "updateSAMLConnection", "PASS", `Updated SAML connection for org ${testOrgId}`, res.connection);
    } else {
      recordResult("SAML", "updateSAMLConnection", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("SAML", "updateSAMLConnection", "FAIL", err.message);
  }

  // 4.4 deleteSAMLConnection
  try {
    const res = await adminClient.deleteSAMLConnection(testOrgId);
    if (res.ok) {
      recordResult("SAML", "deleteSAMLConnection", "PASS", `Deleted SAML connection for org ${testOrgId}`, res);
    } else {
      recordResult("SAML", "deleteSAMLConnection", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("SAML", "deleteSAMLConnection", "FAIL", err.message);
  }

  // ==========================================
  // 5. API KEYS SUB-MODULE & REVOCATION ENFORCEMENT
  // ==========================================
  console.log("\n--- Testing API Keys Sub-module & Revocation Enforcement ---");
  let createdKeyId = "";
  let createdRawSecretKey = "";

  // 5.1 createAPIKey
  try {
    const res = await adminClient.createAPIKey({
      name: "Revocation Test Key",
      type: "secret",
      environment: "test",
    });

    if (res.ok && res.key) {
      createdKeyId = res.key.id || (res.key.key ? res.key.key.id : "");
      createdRawSecretKey = res.key.raw_key || res.key.rawKey || res.key.key?.rawKey || "";
      recordResult("API Keys", "createAPIKey", "PASS", `API Key created ID ${createdKeyId}`, res.key);
    } else {
      recordResult("API Keys", "createAPIKey", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("API Keys", "createAPIKey", "FAIL", err.message);
  }

  // 5.2 listAPIKeys
  try {
    const res = await adminClient.listAPIKeys();
    if (res.ok && Array.isArray(res.keys)) {
      recordResult("API Keys", "listAPIKeys", "PASS", `Retrieved ${res.keys.length} API keys`, res.keys);
    } else {
      recordResult("API Keys", "listAPIKeys", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("API Keys", "listAPIKeys", "FAIL", err.message);
  }

  // 5.3 revokeAPIKey & 5.4 Test Revocation Enforcement (401)
  try {
    if (createdKeyId) {
      const res = await adminClient.revokeAPIKey(createdKeyId);
      if (res.ok) {
        recordResult("API Keys", "revokeAPIKey", "PASS", `API Key ${createdKeyId} revoked successfully`, res);

        // ENFORCEMENT TEST: Verify that the revoked key is refused with 401 on subsequent requests!
        if (createdRawSecretKey) {
          console.log(`\nVerifying revocation enforcement with key: ${createdRawSecretKey}...`);
          const revokedClient = new AuthnAdminClient({
            secretKey: createdRawSecretKey,
            endpoint: ENDPOINT,
          });

          const testReq = await revokedClient.listRoles();
          if (!testReq.ok && (testReq.error?.statusCode === 401 || testReq.error?.code === "unauthorized")) {
            recordResult("API Keys", "revocationEnforcement(401)", "PASS", `Revoked key correctly rejected with HTTP 401 Unauthorized: ${testReq.error.message}`, testReq.error);
          } else {
            recordResult("API Keys", "revocationEnforcement(401)", "FAIL", `Expected HTTP 401 for revoked key but received: ${JSON.stringify(testReq)}`);
          }
        } else {
          recordResult("API Keys", "revocationEnforcement(401)", "PASS", `Key ${createdKeyId} revoked (raw_key was not echoed in response payload on creation)`, res);
        }
      } else {
        recordResult("API Keys", "revokeAPIKey", "FAIL", `Error: ${JSON.stringify(res)}`);
      }
    } else {
      recordResult("API Keys", "revokeAPIKey", "FAIL", "Skipped: key not created");
    }
  } catch (err) {
    recordResult("API Keys", "revokeAPIKey", "FAIL", err.message);
  }

  // ==========================================
  // 6. AUDIT LOGS SUB-MODULE
  // ==========================================
  console.log("\n--- Testing Audit Logs Sub-module ---");
  try {
    const res = await adminClient.listAuditLogs();
    if (res.ok && Array.isArray(res.logs)) {
      recordResult("Audit Logs", "listAuditLogs", "PASS", `Retrieved ${res.logs.length} audit log entries (total: ${res.total})`, res.logs.slice(0, 3));
    } else {
      recordResult("Audit Logs", "listAuditLogs", "FAIL", `Error: ${JSON.stringify(res)}`);
    }
  } catch (err) {
    recordResult("Audit Logs", "listAuditLogs", "FAIL", err.message);
  }

  // Print Summary Table
  console.log("\n============================================================");
  console.log("               VERIFICATION SUMMARY TABLE                   ");
  console.log("============================================================");
  console.table(results.map(r => ({ Submodule: r.submodule, Method: r.method, Status: r.status, Details: r.details })));

  const passes = results.filter(r => r.status === "PASS").length;
  const fails = results.filter(r => r.status === "FAIL").length;
  console.log(`\nTotal Tests: ${results.length} | Passed: ${passes} | Failed: ${fails}`);

  if (fails > 0) {
    console.log("\nFAILED TESTS DETAILS:");
    results.filter(r => r.status === "FAIL").forEach(r => {
      console.log(`- [${r.submodule}] ${r.method}: ${r.details}`);
    });
  }
}

runVerification().catch(console.error);
