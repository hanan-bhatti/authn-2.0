"use client";

import { useMemo, type ReactNode } from "react";
import { encode } from "uqr";

/**
 * Authn Platform — QR code
 * File: apps/web-account/src/components/QrCode.tsx
 *
 * Renders a string as a scannable QR code, for the one place the account needs one:
 * handing an authenticator secret from this screen to a phone.
 *
 * The alternative to a QR code is asking someone to read a 32-character base32
 * secret off a laptop and type it into a phone without a typo, which is the step
 * where two-factor setup gets abandoned.
 *
 * SVG rather than a canvas. A canvas has to be drawn in an effect after mount, is
 * blurry until it is scaled by the device pixel ratio by hand, and prints as a
 * bitmap; the SVG is correct at any size, has no mount-order problem, and one path
 * of rectangles is smaller than the PNG would be.
 */

export interface QrCodeProps {
  /** The string to encode. For TOTP this is the engine's `otpauth://` URI. */
  value: string;
  /** Rendered width and height in pixels. */
  size?: number;
  /**
   * Description for a screen reader. The encoded value is useless read aloud, so
   * the label says what the code is *for*, and every caller pairs it with the same
   * secret in text.
   */
  label: string;
  className?: string;
}

/**
 * Four modules of light margin, which the specification requires and scanners
 * genuinely rely on: a code butted against a border is read as a code with a
 * damaged edge. Baked into the matrix rather than left to CSS padding so it stays
 * proportional to the module size at every rendered width.
 */
const QUIET_ZONE_MODULES = 4;

export function QrCode({ value, size = 208, label, className }: QrCodeProps): ReactNode {
  /**
   * Error correction level M — 15% recoverable — rather than the L default. This
   * code is scanned off a screen at an angle, frequently a screen with a
   * fingerprint on it, and the version it costs is one step up.
   */
  const matrix = useMemo(() => encode(value, { ecc: "M", border: QUIET_ZONE_MODULES }), [value]);

  /**
   * One path for the whole code instead of a rect element per module.
   *
   * A version 5 code is 37 modules square, so ~700 dark modules; as elements that
   * is 700 nodes for React to diff and the browser to lay out, and as a single path
   * it is one. The subpaths are closed rectangles, which the default nonzero fill
   * rule renders solid.
   */
  const path = useMemo(() => {
    const parts: string[] = [];
    matrix.data.forEach((row, y) => {
      row.forEach((isDark, x) => {
        if (isDark) parts.push(`M${x} ${y}h1v1h-1z`);
      });
    });
    return parts.join("");
  }, [matrix]);

  return (
    /* Always dark-on-white, never themed. An inverted QR code is a valid image that
       most scanners refuse to read, because they look for a dark finder pattern on a
       light field; a code that looks correct in dark mode and cannot be scanned is
       worse than one that looks out of place. The white plate is therefore part of
       the code, not decoration. */
    <div
      className={`inline-flex items-center justify-center rounded-md bg-white p-xs ${className ?? ""}`}
    >
      <svg
        viewBox={`0 0 ${matrix.size} ${matrix.size}`}
        width={size}
        height={size}
        role="img"
        aria-label={label}
        /* No antialiasing between modules. At a fractional module size the edges
           blend into grey, and a scanner thresholding the image loses the boundary
           between a dark module and its light neighbour. */
        shapeRendering="crispEdges"
      >
        <path d={path} fill="#000000" />
      </svg>
    </div>
  );
}
