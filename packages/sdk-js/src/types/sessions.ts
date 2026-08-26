/**
 * @authn/js — Device Sessions Types
 *
 * @packageDocumentation
 */

import type { AuthnError } from "./errors";

/**
 * How a session's device is described in the session list.
 *
 * Every field is derived from the `User-Agent` header the session was created
 * with, which is client-supplied and trivially spoofed. It is for recognition —
 * "that is my phone" — and nothing may branch on it for a security decision.
 * Unrecognised values come back as `"Unknown"` rather than absent.
 */
export interface AuthnDeviceInfo {
  /** Browser family, e.g. `"Chrome"`, `"Safari"`. */
  browser?: string;
  /** Operating system, e.g. `"macOS"`, `"iOS"`, `"Windows"`. */
  os?: string;
  /** Form factor: `"Desktop"`, `"Mobile"` or `"Tablet"`. */
  device?: string;
  /** Alias of {@link AuthnDeviceInfo.device}. */
  deviceType?: string;
  /** Browser and OS combined for display, e.g. `"Chrome on macOS"`. */
  label?: string;
}

/** One signed-in device, as returned by {@link AuthnClient.listSessions}. */
export interface AuthnDeviceSession {
  /** Session identifier, and what {@link AuthnClient.revokeSession} takes. */
  id: string;
  /** True for the session this client is authenticated with. */
  isCurrent: boolean;
  device: AuthnDeviceInfo;
  /** Address the session was created from. Empty string when not recorded. */
  ipAddress?: string;
  /**
   * Coarse place label for that address. Empty string on a deployment with no
   * geolocation configured, which is why it must be checked before it is shown.
   */
  location?: string;
  /** RFC 3339 timestamp of the sign-in. */
  createdAt: string;
  /**
   * RFC 3339 timestamp of the session's last credential use. Its resolution is
   * the refresh cadence — one access-token lifetime — not the request, because a
   * refresh advances it by replacing the session.
   */
  lastActiveAt?: string;
  /** RFC 3339 timestamp after which the session expires on its own. */
  expiresAt?: string;
}

export type SessionListResult =
  | { ok: true; sessions: AuthnDeviceSession[] }
  | { ok: false; error: AuthnError };

/**
 * The outcome of a revocation.
 *
 * `count` is a number of devices signed out, not of database rows: each refresh
 * leaves a superseded row behind, and those are revoked too but never counted.
 * {@link AuthnClient.revokeSession} reports `1`, since it ends the one session it
 * was given.
 */
export type RevokeSessionsResult =
  | { ok: true; count?: number; message?: string }
  | { ok: false; error: AuthnError };
