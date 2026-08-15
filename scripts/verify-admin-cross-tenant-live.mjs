import { AuthnAdminClient } from "../packages/sdk-js/dist/admin/index.js";

const TENANT_A_KEY = "sk_test_170d8452ffc5f530aa52940f5db2e9b8bc579d45765a1c3c6e31883f779ef72f";
const TENANT_B_KEY = "sk_test_tenant_b_secret_key_12345678901234567890";
const TENANT_B_ORG_ID = "org_tenant_b_org_12345678901234567890";
const TENANT_B_USER_ID = "usr_tenant_b_user_12345678901234567890";

const adminA = new AuthnAdminClient({ secretKey: TENANT_A_KEY, endpoint: "http://127.0.0.1:8080" });
const adminB = new AuthnAdminClient({ secretKey: TENANT_B_KEY, endpoint: "http://127.0.0.1:8080" });

const VALID_PEM_CERT = `-----BEGIN CERTIFICATE-----
MIICXjCCAcegAwIBAgIJAK9y80wN7b3RMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCVRlc3QgSWRQQTAeFw0yNjA4MTIwMDAwMDBaFw0yNzA4MTIwMDAwMDBaMBQx
EjAQBgNVBAMMCVRlc3QgSWRQQjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
0Z1Z5mY6qW2g8...
-----END CERTIFICATE-----`;

async function runCrossTenantTests() {
  console.log("=== CROSS-TENANT ADMIN SECURITY ATTACK SUITE ===");
  console.log(`Tenant A Key: ${TENANT_A_KEY.substring(0, 20)}...`);
  console.log(`Tenant B Key: ${TENANT_B_KEY.substring(0, 20)}...`);
  console.log(`Tenant B Org Target: ${TENANT_B_ORG_ID}`);
  console.log(`Tenant B User Target: ${TENANT_B_USER_ID}\n`);

  // Step 0: Setup valid SAML Connection in Tenant B using Tenant B's Admin Key
  console.log("0. Setting up SAML Connection in Tenant B using Tenant B's Admin Key...");
  const setupSamlRes = await adminB.createSAMLConnection({
    orgId: TENANT_B_ORG_ID,
    idpMetadataUrl: "https://idp.tenantb.com/metadata.xml",
    idpEntityId: "https://idp.tenantb.com",
    idpSsoUrl: "https://idp.tenantb.com/sso",
    idpCertificate: VALID_PEM_CERT,
    allowedDomains: ["tenantb.com"],
  });
  console.log("Tenant B SAML Setup Result:", setupSamlRes.ok ? "SUCCESS (Connection created)" : JSON.stringify(setupSamlRes));


  // --- Attack Test 1: SAML Connection Cross-Tenant Access ---
  console.log("\n--- Attack Test 1: SAML Connection Cross-Tenant Access ---");

  // 1a. Attempt to CREATE SAML Connection for Tenant B's Org using Tenant A's Admin Key
  console.log("1a. Tenant A Admin attempting to CREATE SAML Connection for Tenant B's Org...");
  const attackCreateSaml = await adminA.createSAMLConnection({
    orgId: TENANT_B_ORG_ID,
    idpMetadataUrl: "https://attacker.com/metadata.xml",
    idpEntityId: "https://attacker.com",
    idpSsoUrl: "https://attacker.com/sso",
    idpCertificate: VALID_PEM_CERT,
    allowedDomains: ["attacker.com"],
  });
  console.log("Response:", JSON.stringify(attackCreateSaml, null, 2));

  // 1b. Attempt to UPDATE SAML Connection for Tenant B's Org using Tenant A's Admin Key
  console.log("\n1b. Tenant A Admin attempting to UPDATE SAML Connection for Tenant B's Org...");
  const attackUpdateSaml = await adminA.updateSAMLConnection({
    orgId: TENANT_B_ORG_ID,
    idpSsoUrl: "https://attacker.com/hacked-sso",
    enabled: true,
  });
  console.log("Response:", JSON.stringify(attackUpdateSaml, null, 2));

  // 1c. Attempt to DELETE SAML Connection for Tenant B's Org using Tenant A's Admin Key
  console.log("\n1c. Tenant A Admin attempting to DELETE SAML Connection for Tenant B's Org...");
  const attackDeleteSaml = await adminA.deleteSAMLConnection(TENANT_B_ORG_ID);
  console.log("Response:", JSON.stringify(attackDeleteSaml, null, 2));


  // --- Attack Test 2: User Role Assignment / Revocation Cross-Tenant Access ---
  console.log("\n--- Attack Test 2: User Role Assignment / Revocation Cross-Tenant Access ---");

  // 2a. Assign Role to Tenant B's User using Tenant A's Admin Key
  console.log("2a. Tenant A Admin attempting to ASSIGN ROLE to Tenant B's User...");
  const attackAssignRole = await adminA.assignUserRole({
    userId: TENANT_B_USER_ID,
    roleSlug: "admin",
  });
  console.log("Response:", JSON.stringify(attackAssignRole, null, 2));

  // 2b. Revoke Role from Tenant B's User using Tenant A's Admin Key
  console.log("\n2b. Tenant A Admin attempting to REVOKE ROLE from Tenant B's User...");
  const attackRevokeRole = await adminA.revokeUserRole({
    userId: TENANT_B_USER_ID,
    roleSlug: "admin",
  });
  console.log("Response:", JSON.stringify(attackRevokeRole, null, 2));


  // --- Attack Test 3: Audit Log Cross-Tenant Isolation ---
  console.log("\n--- Attack Test 3: Audit Log Cross-Tenant Isolation ---");

  console.log("3a. Tenant A Admin querying audit logs...");
  const logsARes = await adminA.listAuditLogs({ limit: 100 });
  console.log("Tenant A Log Count:", logsARes.ok ? logsARes.logs.length : 0);

  const tenantBLeaksInA = logsARes.ok
    ? logsARes.logs.filter((l) => JSON.stringify(l).includes("tenant_b_private_log") || l.tenantId === "tnt_tenant_b_cross_tenant_test")
    : [];
  console.log(`Tenant B Leaked Records in Tenant A's Audit Query: ${tenantBLeaksInA.length}`);

  console.log("\n3b. Tenant B Admin querying audit logs...");
  const logsBRes = await adminB.listAuditLogs({ limit: 100 });
  console.log("Tenant B Log Count:", logsBRes.ok ? logsBRes.logs.length : 0);
  if (logsBRes.ok && logsBRes.logs.length > 0) {
    console.log("Tenant B Log Entry Event Types:", logsBRes.logs.map(l => l.eventType));
  }

  console.log("\n=== CROSS-TENANT ATTACK SUITE COMPLETED ===");
}

runCrossTenantTests().catch(console.error);
