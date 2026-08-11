import type { AuthnError } from "./errors";

export interface AuthnGuardian {
  id: string;
  guardianEmail: string;
  guardianName: string;
  shareIndex: number;
  status: string;
  createdAt: string;
}

export interface InviteGuardianInput {
  email: string;
  name: string;
}

export interface InviteGuardiansParams {
  guardians: InviteGuardianInput[];
}

export type InviteGuardiansResult =
  | {
      ok: true;
      enrolledCount: number;
      thresholdK: number;
      guardians: AuthnGuardian[];
      inviteUrls?: string[];
    }
  | { ok: false; error: AuthnError };

export interface AcceptGuardianInviteParams {
  contactId: string;
  token: string;
}

export type AcceptGuardianInviteResult =
  | { ok: true; message: string }
  | { ok: false; error: AuthnError };

export type ListGuardiansResult =
  | { ok: true; guardians: AuthnGuardian[] }
  | { ok: false; error: AuthnError };

export type RevokeGuardianResult =
  | { ok: true; message: string }
  | { ok: false; error: AuthnError };
