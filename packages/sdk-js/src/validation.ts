/**
 * @authn/js — Input Validation
 *
 * Every public method validates its parameters *before* making any network
 * call. This catches developer mistakes at call-site rather than producing
 * confusing server errors.
 *
 * @internal
 */

import { AuthnError } from "./types";

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

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

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

export function validatePassword(value: unknown): ValidationResult {
  if (value === undefined || value === null || value === "") {
    return fail("password", "Password is required.");
  }
  if (typeof value !== "string") {
    return fail("password", "Password must be a string.");
  }
  if (value.length < 8) {
    return fail("password", "Password must be at least 8 characters.");
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
