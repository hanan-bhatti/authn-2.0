/**
 * @authn/js — Device Sessions Types
 *
 * @packageDocumentation
 */

import type { AuthnError } from "./errors";

export interface AuthnDeviceInfo {
  ipAddress?: string;
  userAgent?: string;
  deviceType?: string;
  os?: string;
  browser?: string;
  device?: string;
  label?: string;
}

export interface AuthnDeviceSession {
  id: string;
  userId?: string;
  isCurrent: boolean;
  device: AuthnDeviceInfo;
  ipAddress?: string;
  location?: string;
  createdAt: string;
  lastActiveAt?: string;
  expiresAt?: string;
}

export type SessionListResult =
  | { ok: true; sessions: AuthnDeviceSession[] }
  | { ok: false; error: AuthnError };

export type RevokeSessionsResult =
  | { ok: true; revokedCount?: number; count?: number; message?: string }
  | { ok: false; error: AuthnError };
