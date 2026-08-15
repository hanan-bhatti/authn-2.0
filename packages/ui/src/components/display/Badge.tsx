import React from "react";
import { cn } from "../../utils/cn.js";

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  children?: React.ReactNode;
  variant?: "violet" | "green" | "red" | "amber" | "gray" | "blue";
  size?: "sm" | "md";
  dot?: boolean;
}

/**
 * Monospaced Badge
 *
 * Rules:
 * - 6px border radius
 * - Commit Mono / JetBrains Mono font
 * - 1px hairline border against black canvas
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
    violet: "border-[#9281f7]/40 text-[#9281f7] bg-[#9281f7]/[0.06]",
    green: "border-[#3ad389]/40 text-[#3ad389] bg-[#3ad389]/[0.06]",
    red: "border-[#ff9592]/40 text-[#ff9592] bg-[#ff9592]/[0.06]",
    amber: "border-[#ffca16]/40 text-[#ffca16] bg-[#ffca16]/[0.06]",
    blue: "border-[#3b9eff]/40 text-[#3b9eff] bg-[#3b9eff]/[0.06]",
    gray: "border-[#292d30] text-[#a1a4a5] bg-[#000000]",
  };

  const sizeMap = {
    sm: "px-1.5 py-0.5 text-[11px] gap-1.5",
    md: "px-2 py-1 text-xs gap-1.5",
  };

  const dotColorMap = {
    violet: "bg-[#9281f7]",
    green: "bg-[#3ad389]",
    red: "bg-[#ff9592]",
    amber: "bg-[#ffca16]",
    blue: "bg-[#3b9eff]",
    gray: "bg-[#a1a4a5]",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center font-mono border rounded-[6px] transition-colors select-none",
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
