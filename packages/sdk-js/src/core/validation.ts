/**
 * @authn/js — Input Validation
 *
 * @internal
 */

import { AuthnError } from "../types";

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
