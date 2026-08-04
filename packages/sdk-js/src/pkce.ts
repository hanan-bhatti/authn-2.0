/**
 * @authn/js — PKCE Utilities
 *
 * Proof Key for Code Exchange (RFC 7636) helpers for OIDC authorization flows.
 * Isomorphic — works in browsers (Web Crypto API) and Node.js 18+ (node:crypto).
 *
 * @example
 * ```ts
 * import { generatePKCEPair } from "@authn/js/pkce";
 *
 * const { codeVerifier, codeChallenge, codeChallengeMethod } = await generatePKCEPair();
 * // Use codeChallenge in /v1/oauth/authorize
 * // Use codeVerifier in /v1/oauth/token exchange
 * ```
 *
 * @packageDocumentation
 */

/**
 * Generate a cryptographically random code verifier string.
 *
 * Per RFC 7636 §4.1, the verifier is 43–128 characters from the
 * unreserved character set [A-Z / a-z / 0-9 / "-" / "." / "_" / "~"].
 *
 * @param length - Verifier length in bytes before base64url encoding. Default: 32 (produces 43 chars).
 * @returns A base64url-encoded random string.
 */
export function generateCodeVerifier(length = 32): string {
  const buffer = getRandomBytes(length);
  return base64UrlEncode(buffer);
}

/**
 * Derive a SHA-256 code challenge from a code verifier.
 *
 * @param verifier - The code verifier string.
 * @returns Base64url-encoded SHA-256 digest.
 * @throws {Error} If SHA-256 hashing is not available in the runtime.
 */
export async function generateCodeChallenge(
  verifier: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);

  // Browser: Web Crypto API
  if (
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.subtle !== "undefined"
  ) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
    return base64UrlEncode(new Uint8Array(digest));
  }

  // Node.js 18+: node:crypto
  try {
    const nodeCrypto = await import("crypto");
    const hash = nodeCrypto.createHash("sha256").update(data).digest();
    return base64UrlEncode(new Uint8Array(hash));
  } catch {
    throw new Error(
      "[authn] PKCE requires Web Crypto API (browsers) or Node.js 18+ crypto module. " +
        "Neither is available in this environment.",
    );
  }
}

/**
 * Generate a complete PKCE pair for use in OAuth 2.0 authorization code flows.
 *
 * @returns Object containing `codeVerifier`, `codeChallenge`, and `codeChallengeMethod` ("S256").
 *
 * @example
 * ```ts
 * const pkce = await generatePKCEPair();
 * // Store pkce.codeVerifier securely (e.g. sessionStorage)
 * // Send pkce.codeChallenge + pkce.codeChallengeMethod to /v1/oauth/authorize
 * ```
 */
export async function generatePKCEPair(): Promise<{
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
}> {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  return { codeVerifier, codeChallenge, codeChallengeMethod: "S256" };
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

function getRandomBytes(length: number): Uint8Array {
  const buffer = new Uint8Array(length);

  // Browser / Cloudflare Workers / Deno
  if (
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.getRandomValues === "function"
  ) {
    globalThis.crypto.getRandomValues(buffer);
    return buffer;
  }

  // Node.js fallback
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const nodeCrypto = require("crypto") as typeof import("crypto");
    const nodeBuffer = nodeCrypto.randomBytes(length);
    buffer.set(new Uint8Array(nodeBuffer.buffer, nodeBuffer.byteOffset, nodeBuffer.byteLength));
    return buffer;
  } catch {
    throw new Error(
      "[authn] Secure random number generation is not available. " +
        "PKCE requires crypto.getRandomValues (browsers) or crypto.randomBytes (Node.js).",
    );
  }
}

/**
 * Base64url encoding without padding, per RFC 4648 §5.
 */
function base64UrlEncode(buffer: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i]!);
  }

  // Use btoa if available (browsers, Node 16+)
  if (typeof globalThis.btoa === "function") {
    return globalThis
      .btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  // Node.js Buffer fallback
  return Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
