import React from "react";
import { cn } from "../../utils/cn.js";

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  children?: React.ReactNode;
  variant?: "orange" | "green" | "red" | "yellow" | "gray" | "blue";
  size?: "sm" | "md";
  dot?: boolean;
}

/**
 * Monospaced Badge
 *
 * An inline mark, not a control: it takes the sm radius so it does not read as
 * a button sitting in the same row as one, and it fills from
 * surface-elevated rather than the canvas so a neutral badge is still legible
 * as a distinct object against a card.
 */
export const Badge: React.FC<BadgeProps> = ({
  children,
  className,
  variant = "gray",
  size = "md",
  dot = false,
  ...props
}) => {
  const variantMap = {
    orange: "border-accent-orange/40 text-accent-orange bg-accent-orange/[0.06]",
    green: "border-accent-green/40 text-accent-green bg-accent-green/[0.06]",
    red: "border-accent-red/40 text-accent-red bg-accent-red/[0.06]",
    yellow: "border-accent-yellow/40 text-accent-yellow bg-accent-yellow/[0.06]",
    blue: "border-accent-blue/40 text-link bg-accent-blue/[0.06]",
    gray: "border-hairline text-body bg-surface-elevated",
  };

  const sizeMap = {
    sm: "px-1.5 py-0.5 text-[11px] gap-1.5",
    md: "px-2 py-1 text-xs gap-1.5",
  };

  const dotColorMap = {
    orange: "bg-accent-orange",
    green: "bg-accent-green",
    red: "bg-accent-red",
    yellow: "bg-accent-yellow",
    blue: "bg-accent-blue",
    gray: "bg-mute",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center font-mono border rounded-sm transition-colors select-none",
        variantMap[variant],
        sizeMap[size],
        className
      )}
      {...props}
    >
      {dot && <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", dotColorMap[variant])} />}
      <span>{children}</span>
    </span>
  );
};
