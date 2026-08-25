"use client";

import React, { useId, useState } from "react";
import { cn } from "../../utils/cn.js";

/**
 * Authn Platform — Tooltip
 * File: packages/ui/src/components/display/Tooltip.tsx
 *
 * A label that appears on hover or keyboard focus. Two things make it usable for
 * help text rather than only for one-word labels: it can wrap, and it is attached
 * to its trigger by `aria-describedby`, so a screen reader reads the explanation
 * along with the control it explains.
 */

export interface TooltipProps {
  content: React.ReactNode;
  children: React.ReactNode;
  position?: "top" | "bottom" | "left" | "right";
  /**
   * Lets the label wrap, capped at a readable measure.
   *
   * Off by default because a short label — a shortcut, a full timestamp, an
   * exact count — reads better unbroken. Anything sentence-length needs this, or
   * it grows past the edge of the viewport and the end of the sentence is
   * unreachable.
   */
  multiline?: boolean;
  className?: string;
}

export const Tooltip: React.FC<TooltipProps> = ({
  content,
  children,
  position = "top",
  multiline = false,
  className,
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const id = useId();

  const posMap = {
    top: "bottom-full left-1/2 -translate-x-1/2 mb-2",
    bottom: "top-full left-1/2 -translate-x-1/2 mt-2",
    left: "right-full top-1/2 -translate-y-1/2 mr-2",
    right: "left-full top-1/2 -translate-y-1/2 ml-2",
  };

  // The trigger is told which node describes it. Without this the bubble is
  // decoration: `role="tooltip"` alone is not announced, so a keyboard user
  // reaches a control whose only explanation is one they cannot hear.
  const trigger = React.isValidElement(children)
    ? React.cloneElement(children as React.ReactElement<{ "aria-describedby"?: string }>, {
        "aria-describedby": id,
      })
    : children;

  return (
    <div
      className="relative inline-flex"
      onMouseEnter={() => setIsVisible(true)}
      onMouseLeave={() => setIsVisible(false)}
      onFocus={() => setIsVisible(true)}
      onBlur={() => setIsVisible(false)}
      // A tooltip that can only be closed by moving the pointer covers whatever
      // it overlaps for as long as the pointer stays put. Escape gives it back.
      onKeyDown={(event) => {
        if (event.key === "Escape") setIsVisible(false);
      }}
    >
      {trigger}
      {/*
        Always rendered, hidden with opacity rather than unmounted, for two
        reasons: `aria-describedby` above must resolve to a node that exists even
        while the bubble is invisible, and a node that only appears mid-animation
        cannot fade in.
      */}
      <div
        role="tooltip"
        id={id}
        className={cn(
          "pointer-events-none absolute z-50 rounded-md border border-hairline-strong bg-canvas px-2.5 py-1 text-caption text-ink transition-opacity duration-fast",
          multiline ? "w-max max-w-[16rem] whitespace-normal text-left" : "whitespace-nowrap",
          isVisible ? "opacity-100" : "opacity-0",
          posMap[position],
          className,
        )}
      >
        {content}
      </div>
    </div>
  );
};
