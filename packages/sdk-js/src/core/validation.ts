/**
 * @authn/js — Input Validation
 *
 * @internal
 */

import { AuthnError } from "../types";
import { checkUsernameFormat } from "./username";

export interface ValidationResult {
  valid: boolean;
  field?: string;
  message?: string;
}

const ok: ValidationResult = { valid: true };

function fail(field: string, message: string): ValidationResult {
  return { valid: false, field, message };
}

/** Throw an AuthnError if validation failed. */
export function assertValid(result: ValidationResult): void {
  if (!result.valid) {
    throw AuthnError.validation(result.field!, result.message!);
  }
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validateEmail(value: unknown): ValidationResult {
  if (value === undefined || value === null || value === "") {
    return fail("email", "Email is required.");
  }
  if (typeof value !== "string") {
    return fail("email", "Email must be a string.");
  }
  if (!EMAIL_RE.test(value)) {
    return fail("email", "Email format is invalid. Expected: user@example.com");
  }
  return ok;
}

export function validateUsername(value: unknown): ValidationResult {
  if (typeof value !== "string" && value !== undefined && value !== null) {
    return fail("username", "Username must be a string.");
  }
  const format = checkUsernameFormat(value);
  if (!format.valid) {
    return fail("username", format.message!);
  }
  return ok;
}

/**
 * The RFC 5321 maximum address length, which is also the engine's ceiling on the
 * login identifier. Counted in UTF-8 bytes, because that is what the engine
 * counts: a value that passes here and fails there would produce a 400 the caller
 * cannot explain.
 */
const MAX_IDENTIFIER_BYTES = 320;

/**
 * Check the identifier a login names an account by.
 *
 * Presence and a length ceiling, and nothing else. The value may be an address or
 * a handle, and refusing one that is neither would answer a malformed value
 * differently from a wrong one — sending a user who mistyped their handle a
 * message about email format, and telling anyone probing which shapes can exist.
 * The engine answers anything that resolves to no account as bad credentials, and
 * this call must not undo that by refusing it earlier.
 */
export function validateLoginIdentifier(value: unknown): ValidationResult {
  if (value === undefined || value === null || value === "") {
    return fail("identifier", "Email or username is required.");
  }
  if (typeof value !== "string") {
    return fail("identifier", "Email or username must be a string.");
  }
  if (value.trim() === "") {
    return fail("identifier", "Email or username is required.");
  }
  if (new TextEncoder().encode(value.trim()).length > MAX_IDENTIFIER_BYTES) {
    // Bytes, not characters, because that is the unit measured. A 200-character
    // address in an accented script passes 320 characters and fails 320 bytes, and
    // naming the wrong unit describes input the sender never typed.
    return fail(
      "identifier",
      `Email or username cannot exceed ${MAX_IDENTIFIER_BYTES} bytes.`,
    );
  }
  return ok;
}

/**
 * The engine's own floor, below which no tenant policy can go.
 *
 * Counted in characters after NFKC, which is how the engine counts. Two things
 * are wrong with the obvious alternatives. `String.length` counts UTF-16 units,
 * so "AA1" plus two emoji reads as 7 when it is 5 characters. Counting UTF-8
 * bytes reads the same input as 11, which is how a five-character password used
 * to satisfy a minimum of eight. And measuring before normalizing measures a
 * string the engine discards, since "e" plus a combining acute composes to a
 * single "é".
 *
 * Only the floor is checked here. A tenant's own minimum, and every character
 * class it requires, stay with the server: it is the only authority on them, and
 * a second copy in the client is a second policy to disagree with.
 */
const MIN_PASSWORD_CHARACTERS = 8;

export function validatePassword(value: unknown): ValidationResult {
  if (value === undefined || value === null || value === "") {
    return fail("password", "Password is required.");
  }
  if (typeof value !== "string") {
    return fail("password", "Password must be a string.");
  }
  if ([...value.normalize("NFKC")].length < MIN_PASSWORD_CHARACTERS) {
    return fail("password", `Password must be at least ${MIN_PASSWORD_CHARACTERS} characters.`);
  }
  return ok;
}

const PK_RE = /^pk_(test|live)_[a-zA-Z0-9]{32,}$/;

export function validatePublishableKey(key: unknown): ValidationResult {
  if (key === undefined || key === null || key === "") {
    return fail("publishableKey", "Publishable key is required.");
  }
  if (typeof key !== "string") {
    return fail("publishableKey", "Publishable key must be a string.");
  }
  if (key.startsWith("sk_")) {
    return fail(
      "publishableKey",
      'You passed a SECRET key (sk_...) instead of a PUBLISHABLE key (pk_...). ' +
        "Secret keys must never be used in client-side code — they grant full admin access.",
    );
  }
  if (!PK_RE.test(key)) {
    return fail(
      "publishableKey",
      "Invalid format. Expected: pk_test_<32+ chars> or pk_live_<32+ chars>. " +
        "Get your keys from the Authn Console → Settings → API Keys.",
    );
  }
  return ok;
}

export function validateToken(
  value: unknown,
  fieldName: string,
): ValidationResult {
  if (value === undefined || value === null || value === "") {
    return fail(fieldName, `${fieldName} is required.`);
  }
  if (typeof value !== "string") {
    return fail(fieldName, `${fieldName} must be a string.`);
  }
  return ok;
}

export function validateTenantId(value: unknown): ValidationResult {
  if (value === undefined || value === null) return ok;
  if (typeof value !== "string") {
    return fail("tenantId", "Tenant ID must be a string.");
  }
  if (value.length > 0 && !value.startsWith("tnt_")) {
    return fail(
      "tenantId",
      'Tenant ID must start with "tnt_". Example: tnt_demo123',
    );
  }
  return ok;
}

export function validateEnvironment(value: unknown): ValidationResult {
  if (value === undefined || value === null) return ok;
  if (value !== "test" && value !== "live") {
    return fail(
      "environment",
      'Environment must be "test" or "live".',
    );
  }
  return ok;
}

const E164_RE = /^\+[1-9]\d{1,14}$/;

export function validatePhoneNumber(value: unknown): ValidationResult {
  if (value === undefined || value === null || value === "") {
    return fail("phoneNumber", "Phone number is required.");
  }
  if (typeof value !== "string") {
    return fail("phoneNumber", "Phone number must be a string.");
  }
  if (!E164_RE.test(value)) {
    return fail(
      "phoneNumber",
      "Phone number must be in E.164 format (e.g. +12025550199).",
    );
  }
  return ok;
}

const TOTP_CODE_RE = /^\d{6}$/;

export function validateTOTPCode(value: unknown): ValidationResult {
  if (value === undefined || value === null || value === "") {
    return fail("code", "Verification code is required.");
  }
  if (typeof value !== "string") {
    return fail("code", "Verification code must be a string.");
  }
  if (!TOTP_CODE_RE.test(value)) {
    return fail("code", "Verification code must be exactly 6 digits.");
  }
  return ok;
}

/** Eight alphanumerics once the grouping dash is stripped, matching what the engine hashes. */
const RECOVERY_CODE_RE = /^[A-Z0-9]{8}$/;

/**
 * A backup recovery code, in either the printed `XXXX-XXXX` form or without the dash.
 *
 * Separate from validateTOTPCode because a recovery code is not six digits, and the shared
 * validator refused every one of them before it could be sent — which made the codes the engine
 * hands out at enrollment unusable from this SDK.
 */
export function validateRecoveryCode(value: unknown): ValidationResult {
  if (value === undefined || value === null || value === "") {
    return fail("code", "Recovery code is required.");
  }
  if (typeof value !== "string") {
    return fail("code", "Recovery code must be a string.");
  }
  // Normalised the way the engine normalises before hashing, so a reader who types the dash, omits
  // it, or uses lower case is not refused for a difference the server would not have seen.
  const normalized = value.trim().replace(/-/g, "").toUpperCase();
  if (!RECOVERY_CODE_RE.test(normalized)) {
    return fail(
      "code",
      "Recovery code must be 8 letters and digits, like ABCD-1234.",
    );
  }
  return ok;
}

export function validateWebAuthnCredential(value: unknown): ValidationResult {
  if (value === undefined || value === null || typeof value !== "object") {
    return fail("credential", "WebAuthn credential object is required.");
  }
  const cred = value as Record<string, unknown>;
  if (!cred["id"] || typeof cred["id"] !== "string") {
    return fail("credential", "WebAuthn credential missing required string 'id'.");
  }
  return ok;
}
