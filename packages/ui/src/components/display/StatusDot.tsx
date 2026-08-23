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
    delivered: "bg-accent-green",
    active: "bg-accent-green",
    opened: "bg-accent-blue",
    clicked: "bg-accent-orange",
    bounced: "bg-accent-red",
    error: "bg-accent-red",
    complained: "bg-accent-yellow",
    warning: "bg-accent-yellow",
  };

  const selectedColor = colorMap[status];

  return (
    <span className={cn("inline-flex items-center gap-2 font-mono text-xs text-mute", className)}>
      <span className="relative flex h-2 w-2 items-center justify-center">
        {pulse && (
          <span className={cn("absolute inline-flex h-full w-full rounded-full opacity-75 animate-status-ping", selectedColor)} />
        )}
        <span className={cn("relative inline-flex rounded-full h-2 w-2", selectedColor)} />
      </span>
      {label && <span>{label}</span>}
    </span>
  );
};
