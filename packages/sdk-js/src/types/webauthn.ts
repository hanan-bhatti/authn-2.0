/**
 * @authn/js — WebAuthn & Passkey Types
 *
 * @packageDocumentation
 */

import type { AuthnError } from "./errors";

export interface WebAuthnPasskey {
  id: string;
  name: string;
  /**
   * The authenticator model's identifier, as hex. Read from the registration
   * metadata; all zeroes when the authenticator declined to identify itself,
   * which platform authenticators in privacy-preserving modes routinely do.
   */
  aaguid?: string;
  /**
   * How the authenticator can be reached: `internal` for one built into the
   * device, `usb`, `nfc` or `ble` for a key carried between devices, `hybrid` for
   * a phone answering for a desktop.
   *
   * Worth surfacing because it is the difference between "the fingerprint reader
   * on this laptop" and "the key on your keyring", and a list of passkeys that
   * cannot tell those apart is a list nobody can safely prune.
   */
  transports?: string[];
  createdAt: string;
  lastUsedAt?: string;
}

export type ListWebAuthnCredentialsResult =
  | { ok: true; credentials: WebAuthnPasskey[] }
  | { ok: false; error: AuthnError };

export interface RevokeWebAuthnCredentialParams {
  id: string;
  password?: string;
}

export type BeginPasskeyRegistrationResult =
  | {
      ok: true;
      options: Record<string, unknown>;
      sessionId: string;
    }
  | { ok: false; error: AuthnError };

export interface FinishPasskeyRegistrationParams {
  sessionId: string;
  name?: string;
  credential: Record<string, unknown>;
}

export interface BeginPasskeyLoginParams {
  mfaToken?: string;
}

export type BeginPasskeyLoginResult =
  | {
      ok: true;
      options: Record<string, unknown>;
      sessionId: string;
      userId?: string;
    }
  | { ok: false; error: AuthnError };

export interface FinishPasskeyLoginParams {
  sessionId: string;
  mfaToken?: string;
  credential: Record<string, unknown>;
}

export type FinishPasskeyLoginResult =
  | { ok: true; session: import("./common").AuthnSession }
  | { ok: false; error: AuthnError };

export interface PublicKeyCredentialCreationOptionsJSON {
  rp: { name: string; id?: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: Array<{ type: string; alg: number }>;
  timeout?: number;
  excludeCredentials?: Array<{ id: string; type: string; transports?: string[] }>;
  authenticatorSelection?: {
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  };
  attestation?: string;
}

export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: Array<{ id: string; type: string; transports?: string[] }>;
  userVerification?: string;
}

export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: string[];
  };
  clientExtensionResults?: Record<string, unknown>;
  authenticatorAttachment?: string;
}

export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  clientExtensionResults?: Record<string, unknown>;
  authenticatorAttachment?: string;
}
