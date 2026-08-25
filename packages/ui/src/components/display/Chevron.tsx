import React from "react";
import { cn } from "../../utils/cn.js";

export interface ChevronProps extends React.SVGProps<SVGSVGElement> {
  direction?: "up" | "down" | "left" | "right";
  size?: "sm" | "md" | "lg";
}

/**
 * The set's disclosure and separator arrow.
 *
 * Drawn on the same 24-unit grid at the same 1.5 weight as every icon, because
 * this is the one glyph that routinely sits directly beside one — a tree row's
 * chevron next to the row's own icon — and a quarter-unit of extra weight there
 * reads as two different icon sets sharing a row.
 *
 * A lighter stroke needs more length to hold the same optical presence, so the
 * arms run 4.75 to 19.25 rather than the 6 to 18 a 2-unit stroke can get away
 * with. Rotation rather than four paths keeps the four directions identical, and
 * makes the open/closed transition on a tree row a transform the compositor can
 * animate.
 */
export const Chevron: React.FC<ChevronProps> = ({
  direction = "right",
  size = "md",
  className,
  ...props
}) => {
  const sizeMap = {
    sm: "w-3 h-3",
    md: "w-4 h-4",
    lg: "w-5 h-5",
  };

  const rotationMap = {
    up: "-rotate-90",
    down: "rotate-90",
    left: "rotate-180",
    right: "rotate-0",
  };

  return (
    <svg
      className={cn(
        "stroke-current transition-transform duration-150 ease-out flex-shrink-0",
        sizeMap[size],
        rotationMap[direction],
        className
      )}
      fill="none"
      viewBox="0 0 24 24"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      <path d="M8.75 4.75 16 12l-7.25 7.25" />
    </svg>
  );
};
