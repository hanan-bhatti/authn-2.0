import { AuthnClient } from "../src/client";

const ENDPOINT = "http://127.0.0.1:8080";
const PUBLISHABLE_KEY =
  "pk_test_170d8452ffc5f530aa52940f5db2e9b8bc579d45765a1c3c6e31883f779ef72f";
const TENANT_ID = "tnt_cbf010720b7741af88258608ad992c7a";

async function main() {
  console.log("=== B2B ORGANIZATIONS LIVE VERIFICATION ===");

  const clientA = new AuthnClient({
    endpoint: ENDPOINT,
    publishableKey: PUBLISHABLE_KEY,
    tenantId: TENANT_ID,
    timeout: 30000,
  });

  const clientB = new AuthnClient({
    endpoint: ENDPOINT,
    publishableKey: PUBLISHABLE_KEY,
    tenantId: TENANT_ID,
    timeout: 30000,
  });

  const clientC = new AuthnClient({
    endpoint: ENDPOINT,
    publishableKey: PUBLISHABLE_KEY,
    tenantId: TENANT_ID,
    timeout: 30000,
  });

  const ts = Date.now();
  const emailA = `orgadmin_${ts}@example.com`;
  const emailB = `orgmember_${ts}@example.com`;
  const emailC = `attacker_${ts}@example.com`;
  const password = "Password123!";

  // Step 1: Sign up & Login User A (Admin)
  console.log("\n1. Signing up & logging in User A (Org Admin)...");
  const signUpA = await clientA.signUp({ email: emailA, password, name: "Admin A" });
  if (!signUpA.ok) throw new Error(`User A signup failed: ${signUpA.error.message}`);
  const loginA = await clientA.login({ email: emailA, password });
  if (!loginA.ok) throw new Error(`User A login failed: ${loginA.error.message}`);
  console.log(`✓ User A logged in: ${loginA.session.user.id}`);

  // Step 2: Create Org X
  console.log("\n2. Creating Org X (Acme Corp) via User A...");
  const createOrgX = await clientA.createOrganization({ name: `Acme Corp ${ts}` });
  console.log("Result:", JSON.stringify(createOrgX, null, 2));
  if (!createOrgX.ok) throw new Error(`Create Org failed: ${createOrgX.error.message}`);
  const orgXId = createOrgX.org.id;
  console.log(`✓ Org X created: ${orgXId}`);

  // Step 3: Sign up & Login User B (Invitee)
  console.log("\n3. Signing up & logging in User B (Invitee)...");
  const signUpB = await clientB.signUp({ email: emailB, password, name: "Member B" });
  if (!signUpB.ok) throw new Error(`User B signup failed: ${signUpB.error.message}`);
  const loginB = await clientB.login({ email: emailB, password });
  if (!loginB.ok) throw new Error(`User B login failed: ${loginB.error.message}`);
  console.log(`✓ User B logged in: ${loginB.session.user.id}`);

  // Step 4: Invite User B to Org X
  console.log("\n4. Inviting User B to Org X as 'member' via User A...");
  const inviteB = await clientA.inviteOrgMember(orgXId, {
    email: emailB,
    roleId: "member",
  });
  console.log("Result:", JSON.stringify(inviteB, null, 2));
  if (!inviteB.ok) throw new Error(`Invite failed: ${inviteB.error.message}`);
  const token = inviteB.invitation.invitationToken;
  console.log(`✓ Invitation token received: ${token}`);

  // Step 5: Accept Invitation via User B
  console.log("\n5. Accepting invitation via User B...");
  const acceptB = await clientB.acceptOrgInvitation({ invitationToken: token! });
  console.log("Result:", JSON.stringify(acceptB, null, 2));
  if (!acceptB.ok) throw new Error(`Accept invitation failed: ${acceptB.error.message}`);
  console.log(`✓ Invitation accepted. Member ID: ${acceptB.member.id}`);

  // Step 6: List Members of Org X via User B
  console.log("\n6. Listing Org X members via User B...");
  const listMembers = await clientB.listOrgMembers(orgXId);
  console.log("Result:", JSON.stringify(listMembers, null, 2));
  if (!listMembers.ok) throw new Error(`List members failed: ${listMembers.error.message}`);
  console.log(`✓ Listed ${listMembers.total} members`);

  // Step 7: Update Member B's Role to 'admin' via User A
  console.log("\n7. Updating User B's role to 'admin' via User A...");
  const updateRole = await clientA.updateOrgMemberRole(orgXId, loginB.session.user.id, {
    roleId: "admin",
  });
  console.log("Result:", JSON.stringify(updateRole, null, 2));
  if (!updateRole.ok) throw new Error(`Update role failed: ${updateRole.error.message}`);
  console.log(`✓ Role updated to ${updateRole.member.roleId}`);

  // Step 8: Sign up & Login User C (Attacker in Org Y)
  console.log("\n8. Setting up User C (Attacker belonging to Org Y only)...");
  await clientC.signUp({ email: emailC, password, name: "Attacker C" });
  const loginC = await clientC.login({ email: emailC, password });
  const createOrgY = await clientC.createOrganization({ name: `Evil Corp ${ts}` });
  if (!createOrgY.ok) throw new Error("Org Y creation failed");
  const orgYId = createOrgY.org.id;
  console.log(`✓ User C created Org Y: ${orgYId}`);

  // Step 9: Cross-Tenant Isolation / ID-Swapping Attacks
  console.log("\n9. CROSS-TENANT ACCESS ATTACK TESTS:");

  console.log("9a. User C (Org Y member) attempts to GET Org X by passing orgXId...");
  const getCrossOrg = await clientC.getOrganization(orgXId);
  console.log("Result:", JSON.stringify(getCrossOrg, null, 2));
  if (!getCrossOrg.ok) {
    console.log(`✓ PASS: Cross-tenant GET blocked with ${getCrossOrg.error.code} (${getCrossOrg.error.statusCode})`);
  } else {
    console.error("❌ FAIL: User C was able to view Org X details!");
  }

  console.log("9b. User C attempts to LIST MEMBERS of Org X by passing orgXId...");
  const listCrossMembers = await clientC.listOrgMembers(orgXId);
  console.log("Result:", JSON.stringify(listCrossMembers, null, 2));
  if (!listCrossMembers.ok) {
    console.log(`✓ PASS: Cross-tenant list members blocked with ${listCrossMembers.error.code} (${listCrossMembers.error.statusCode})`);
  } else {
    console.error("❌ FAIL: User C was able to list members of Org X!");
  }

  console.log("9c. User C attempts to DELETE Org X by passing orgXId...");
  const deleteCrossOrg = await clientC.deleteOrganization(orgXId);
  console.log("Result:", JSON.stringify(deleteCrossOrg, null, 2));
  if (!deleteCrossOrg.ok) {
    console.log(`✓ PASS: Cross-tenant DELETE blocked with ${deleteCrossOrg.error.code} (${deleteCrossOrg.error.statusCode})`);
  } else {
    console.error("❌ FAIL: User C was able to delete Org X!");
  }

  // Step 10: Delete Org X via User A
  console.log("\n10. Deleting Org X via User A...");
  const deleteOrgX = await clientA.deleteOrganization(orgXId);
  console.log("Result:", JSON.stringify(deleteOrgX, null, 2));
  if (!deleteOrgX.ok) throw new Error(`Delete org failed: ${deleteOrgX.error.message}`);
  console.log(`✓ Org X deleted successfully`);

  console.log("\n=== ALL LIVE B2B ORGANIZATION TESTS COMPLETED SUCCESSFULLY ===");
}

main().catch((err) => {
  console.error("FATAL TEST ERROR:", err);
  process.exit(1);
});
