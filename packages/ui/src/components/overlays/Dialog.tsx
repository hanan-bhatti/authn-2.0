"use client";

import React, { useEffect } from "react";
import { IconButton } from "../actions/IconButton.js";
import { cn } from "../../utils/cn.js";

export interface DialogProps {
  isOpen: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  description?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  maxWidth?: "sm" | "md" | "lg" | "xl";
  className?: string;
}

export const Dialog: React.FC<DialogProps> = ({
  isOpen,
  onClose,
  title,
  description,
  children,
  footer,
  maxWidth = "md",
  className,
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const widthMap = {
    sm: "max-w-compact",
    md: "max-w-panel",
    lg: "max-w-wide",
    xl: "max-w-broad",
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop Scrim. `select-none` belongs here and not on the wrapper: a
          dialog often carries the one string a reader needs to copy — an address
          a confirmation was sent to, a recovery code — and an unselectable card
          means the only way to get it out is to retype it. */}
      <div
        className="fixed inset-0 bg-canvas/80 backdrop-blur-[25px] transition-opacity duration-150 select-none"
        onClick={onClose}
      />

      {/* Dialog Card — 16px radius, hairline border */}
      <div
        role="dialog"
        aria-modal="true"
        className={cn(
          "relative z-10 w-full bg-canvas border border-hairline-strong rounded-lg p-6 flex flex-col gap-4 animate-enter-scale",
          widthMap[maxWidth],
          className
        )}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            {title && <h2 className="text-base font-semibold text-ink font-sans tracking-tight">{title}</h2>}
            {description && <p className="text-xs text-mute font-sans mt-0.5">{description}</p>}
          </div>
          <IconButton
            size="sm"
            label="Close modal"
            onClick={onClose}
            icon={
              <svg className="w-4 h-4 stroke-current" fill="none" viewBox="0 0 24 24" strokeWidth="2">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            }
          />
        </div>

        <div className="py-2">{children}</div>

        {footer && <div className="flex items-center justify-end gap-3 pt-3 border-t border-hairline-strong">{footer}</div>}
      </div>
    </div>
  );
};
