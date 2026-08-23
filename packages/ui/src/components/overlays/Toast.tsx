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

/**
 * Toast
 *
 * The colour carries the whole meaning of a toast for a sighted user, so the
 * role has to carry it for everyone else. An error or warning is announced with
 * `alert`, which interrupts whatever the screen reader is reading; a success or
 * an informational note uses `status`, which waits its turn. Getting that the
 * wrong way round either buries a failed sign-in or talks over the user for a
 * message that said "saved".
 */
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

  const isUrgent = type === "error" || type === "warning";

  return (
    <div
      role={isUrgent ? "alert" : "status"}
      aria-live={isUrgent ? "assertive" : "polite"}
      className={cn(
        "flex items-start gap-3 p-3.5 bg-canvas border border-hairline-strong rounded-md backdrop-scrim max-w-sm select-none animate-enter-rise",
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
          aria-label="Dismiss notification"
          className="text-mute hover:text-ink transition-colors cursor-pointer p-0.5"
        >
          <svg
            aria-hidden="true"
            className="w-3.5 h-3.5 stroke-current"
            fill="none"
            viewBox="0 0 24 24"
            strokeWidth="2"
          >
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
          </svg>
        </button>
      )}
    </div>
  );
};
