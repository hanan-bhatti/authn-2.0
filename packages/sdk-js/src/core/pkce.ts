/**
 * @authn/js — PKCE Utilities
 *
 * Proof Key for Code Exchange (RFC 7636) helpers for OIDC authorization flows.
 *
 * @packageDocumentation
 */

export function generateCodeVerifier(length = 32): string {
  const buffer = getRandomBytes(length);
  return base64UrlEncode(buffer);
}

export async function generateCodeChallenge(
  verifier: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);

  if (
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.subtle !== "undefined"
  ) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
    return base64UrlEncode(new Uint8Array(digest));
  }

  try {
    const nodeCrypto = await import("crypto");
    const hash = nodeCrypto.createHash("sha256").update(data).digest();
    return base64UrlEncode(new Uint8Array(hash));
  } catch {
    throw new Error(
      "[authn] PKCE requires Web Crypto API (browsers) or Node.js 18+ crypto module.",
    );
  }
}

export async function generatePKCEPair(): Promise<{
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
}> {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  return { codeVerifier, codeChallenge, codeChallengeMethod: "S256" };
}

function getRandomBytes(length: number): Uint8Array {
  const buffer = new Uint8Array(length);

  if (
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.getRandomValues === "function"
  ) {
    globalThis.crypto.getRandomValues(buffer);
    return buffer;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const nodeCrypto = require("crypto") as typeof import("crypto");
    const nodeBuffer = nodeCrypto.randomBytes(length);
    buffer.set(new Uint8Array(nodeBuffer.buffer, nodeBuffer.byteOffset, nodeBuffer.byteLength));
    return buffer;
  } catch {
    throw new Error(
      "[authn] Secure random number generation is not available.",
    );
  }
}

function base64UrlEncode(buffer: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i]!);
  }

  if (typeof globalThis.btoa === "function") {
    return globalThis
      .btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  return Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
