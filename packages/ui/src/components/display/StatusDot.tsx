import React from "react";
import { cn } from "../../utils/cn.js";

export interface StatusDotProps {
  status?: "delivered" | "opened" | "clicked" | "bounced" | "complained" | "active" | "error" | "warning";
  pulse?: boolean;
  label?: React.ReactNode;
  className?: string;
}

export const StatusDot: React.FC<StatusDotProps> = ({
  status = "active",
  pulse = false,
  label,
  className,
}) => {
  const colorMap = {
    delivered: "bg-[#3ad389]",
    active: "bg-[#3ad389]",
    opened: "bg-[#70b8ff]",
    clicked: "bg-[#9281f7]",
    bounced: "bg-[#ff9592]",
    error: "bg-[#ff9592]",
    complained: "bg-[#ffca16]",
    warning: "bg-[#ffca16]",
  };

  const selectedColor = colorMap[status];

  return (
    <span className={cn("inline-flex items-center gap-2 font-mono text-xs text-[#a1a4a5]", className)}>
      <span className="relative flex h-2 w-2 items-center justify-center">
        {pulse && (
          <span className={cn("absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping", selectedColor)} />
        )}
        <span className={cn("relative inline-flex rounded-full h-2 w-2", selectedColor)} />
      </span>
      {label && <span>{label}</span>}
    </span>
  );
};
