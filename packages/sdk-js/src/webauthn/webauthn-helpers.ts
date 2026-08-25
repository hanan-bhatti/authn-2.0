/**
 * @authn/js — WebAuthn Base64URL Conversion Helpers
 *
 * Utility functions to convert between WebAuthn browser binary fields (ArrayBuffer)
 * and server JSON representations (base64url strings).
 *
 * @packageDocumentation
 */

export function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    const b = bytes[i];
    if (b !== undefined) {
      binary += String.fromCharCode(b);
    }
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function base64UrlToBuffer(base64url: string): ArrayBuffer {
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Transform server creation options (from POST /2fa/webauthn/register/begin)
 * into PublicKeyCredentialCreationOptions suitable for navigator.credentials.create().
 */
export function prepareCreationOptions(
  rawOptions: Record<string, unknown>,
): PublicKeyCredentialCreationOptions {
  const optionsObj =
    (rawOptions["publicKey"] as Record<string, unknown>) ?? rawOptions;

  const challenge =
    typeof optionsObj["challenge"] === "string"
      ? base64UrlToBuffer(optionsObj["challenge"] as string)
      : (optionsObj["challenge"] as ArrayBuffer);

  const userRaw = optionsObj["user"] as Record<string, unknown> | undefined;
  const user = userRaw
    ? {
        ...userRaw,
        id:
          typeof userRaw["id"] === "string"
            ? base64UrlToBuffer(userRaw["id"] as string)
            : (userRaw["id"] as ArrayBuffer),
        name: (userRaw["name"] as string) || "user",
        displayName: (userRaw["displayName"] as string) || "User",
      }
    : {
        id: new Uint8Array(16).buffer,
        name: "user",
        displayName: "User",
      };

  const excludeCredentialsRaw = optionsObj["excludeCredentials"] as
    | Array<Record<string, unknown>>
    | undefined;
  const excludeCredentials = excludeCredentialsRaw?.map((cred) => ({
    type: (cred["type"] as PublicKeyCredentialType) || "public-key",
    id:
      typeof cred["id"] === "string"
        ? base64UrlToBuffer(cred["id"] as string)
        : (cred["id"] as ArrayBuffer),
    transports: cred["transports"] as AuthenticatorTransport[] | undefined,
  }));

  return {
    ...(optionsObj as unknown as PublicKeyCredentialCreationOptions),
    challenge,
    user,
    ...(excludeCredentials ? { excludeCredentials } : {}),
  };
}

/**
 * Transform PublicKeyCredential returned by navigator.credentials.create()
 * into JSON payload for POST /2fa/webauthn/register/finish.
 */
export function formatCreationCredential(
  credential: PublicKeyCredential,
): Record<string, unknown> {
  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      attestationObject: bufferToBase64Url(response.attestationObject),
      ...(response.getTransports
        ? { transports: response.getTransports() }
        : {}),
      ...(response.getPublicKey
        ? { publicKey: bufferToBase64Url(response.getPublicKey()!) }
        : {}),
      ...(response.getAuthenticatorData
        ? { authenticatorData: bufferToBase64Url(response.getAuthenticatorData()!) }
        : {}),
    },
    ...(credential.authenticatorAttachment
      ? { authenticatorAttachment: credential.authenticatorAttachment }
      : {}),
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

/**
 * Transform server request options (from POST /2fa/webauthn/login/begin)
 * into PublicKeyCredentialRequestOptions suitable for navigator.credentials.get().
 */
export function prepareRequestOptions(
  rawOptions: Record<string, unknown>,
): PublicKeyCredentialRequestOptions {
  const optionsObj =
    (rawOptions["publicKey"] as Record<string, unknown>) ?? rawOptions;

  const challenge =
    typeof optionsObj["challenge"] === "string"
      ? base64UrlToBuffer(optionsObj["challenge"] as string)
      : (optionsObj["challenge"] as ArrayBuffer);

  const allowCredentialsRaw = optionsObj["allowCredentials"] as
    | Array<Record<string, unknown>>
    | undefined;
  const allowCredentials = allowCredentialsRaw?.map((cred) => ({
    type: (cred["type"] as PublicKeyCredentialType) || "public-key",
    id:
      typeof cred["id"] === "string"
        ? base64UrlToBuffer(cred["id"] as string)
        : (cred["id"] as ArrayBuffer),
    transports: cred["transports"] as AuthenticatorTransport[] | undefined,
  }));

  return {
    ...(optionsObj as unknown as PublicKeyCredentialRequestOptions),
    challenge,
    ...(allowCredentials ? { allowCredentials } : {}),
  };
}

/**
 * Transform PublicKeyCredential returned by navigator.credentials.get()
 * into JSON payload for POST /2fa/webauthn/login/finish.
 */
export function formatRequestCredential(
  credential: PublicKeyCredential,
): Record<string, unknown> {
  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      authenticatorData: bufferToBase64Url(response.authenticatorData),
      signature: bufferToBase64Url(response.signature),
      ...(response.userHandle
        ? { userHandle: bufferToBase64Url(response.userHandle) }
        : {}),
    },
    ...(credential.authenticatorAttachment
      ? { authenticatorAttachment: credential.authenticatorAttachment }
      : {}),
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

/** The ceremony outcomes worth telling apart from a generic failure. */
export type PasskeyCeremonyOutcome = "cancelled" | "already-registered" | "unsupported";

/**
 * Whether this browser can run a passkey ceremony at all.
 *
 * A sign-in screen has to know before it offers the option: the engine lists
 * `passkey` among an account's methods because the account has a credential
 * enrolled, which says nothing about the browser now in front of it. Offered
 * anyway, the button reaches `navigator.credentials` and throws a TypeError,
 * which reads as a fault rather than as an unsupported browser.
 *
 * Requires a secure context, because WebAuthn is unavailable over plain HTTP
 * except on localhost — where `isSecureContext` is already true.
 */
export function isPasskeySupported(): boolean {
  return (
    typeof window !== "undefined" &&
    window.isSecureContext &&
    typeof window.PublicKeyCredential === "function" &&
    typeof navigator !== "undefined" &&
    typeof navigator.credentials?.get === "function"
  );
}

/**
 * Translates what the authenticator threw into the SDK's own error vocabulary.
 *
 * The browser reports every outcome of a ceremony as a `DOMException`, and the
 * one that matters most is not a failure: dismissing the system prompt and
 * letting it time out both arrive as `NotAllowedError`. Left unmapped it reaches
 * the caller as `UNKNOWN` carrying the browser's own sentence — "The operation
 * either timed out or was not allowed" — so a person who changed their mind is
 * shown an error they cannot act on.
 *
 * Returns null for anything that is not a recognised ceremony outcome, leaving
 * the caller's generic handling in place.
 */
export function mapCeremonyError(
  err: unknown,
): { outcome: PasskeyCeremonyOutcome; message: string } | null {
  const name = err instanceof Error ? err.name : "";

  switch (name) {
    case "NotAllowedError":
    case "AbortError":
      return {
        outcome: "cancelled",
        message: "The passkey prompt was dismissed or timed out.",
      };
    case "InvalidStateError":
      return {
        outcome: "already-registered",
        message: "This device already has a passkey for this account.",
      };
    case "NotSupportedError":
      return {
        outcome: "unsupported",
        message: "This device cannot create a passkey of the kind this account requires.",
      };
    case "SecurityError":
      return {
        outcome: "unsupported",
        message: "Passkeys need a secure connection to this exact domain.",
      };
    case "ConstraintError":
      return {
        outcome: "unsupported",
        message:
          "This device cannot satisfy the passkey requirements — a screen lock may be missing.",
      };
    default:
      return null;
  }
}
