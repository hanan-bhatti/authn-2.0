import React from "react";
import { StatusDot } from "../display/StatusDot.js";
import { cn } from "../../utils/cn.js";

export interface ToastProps {
  type?: "success" | "error" | "warning" | "info";
  title: string;
  description?: string;
  onClose?: () => void;
  className?: string;
}

export const Toast: React.FC<ToastProps> = ({
  type = "info",
  title,
  description,
  onClose,
  className,
}) => {
  const statusMap = {
    success: "active",
    error: "error",
    warning: "warning",
    info: "opened",
  } as const;

  return (
    <div
      className={cn(
        "flex items-start gap-3 p-3.5 bg-canvas border border-hairline-strong rounded-md shadow-2xl backdrop-scrim max-w-sm select-none animate-in fade-in slide-in-from-bottom-2",
        className
      )}
    >
      <StatusDot status={statusMap[type]} pulse className="mt-0.5" />
      <div className="flex-1 flex flex-col gap-0.5">
        <span className="text-xs font-semibold text-ink font-sans">{title}</span>
        {description && <span className="text-[11px] text-mute font-sans">{description}</span>}
      </div>
      {onClose && (
        <button
          type="button"
          onClick={onClose}
          className="text-mute hover:text-ink transition-colors cursor-pointer p-0.5"
        >
          <svg className="w-3.5 h-3.5 stroke-current" fill="none" viewBox="0 0 24 24" strokeWidth="2">
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
          </svg>
        </button>
      )}
    </div>
  );
};
