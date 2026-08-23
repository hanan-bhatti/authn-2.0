"use client";

import React, { useEffect } from "react";
import { IconButton } from "../actions/IconButton.js";
import { cn } from "../../utils/cn.js";

export interface SheetProps {
  isOpen: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  description?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  position?: "right" | "left";
  className?: string;
}

export const Sheet: React.FC<SheetProps> = ({
  isOpen,
  onClose,
  title,
  description,
  children,
  footer,
  position = "right",
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

  return (
    <div className="fixed inset-0 z-50 flex select-none">
      {/* Backdrop Scrim */}
      <div
        className="fixed inset-0 bg-canvas/80 backdrop-blur-[25px] transition-opacity duration-150"
        onClick={onClose}
      />

      {/* Sheet Slide-Over Drawer */}
      <div
        role="dialog"
        aria-modal="true"
        className={cn(
          "relative z-10 w-full max-w-md h-full bg-canvas border-l border-hairline-strong p-6 transition-transform duration-200 flex flex-col justify-between ml-auto",
          position === "left" && "mr-auto ml-0 border-r border-l-0",
          className
        )}
      >
        <div className="flex flex-col gap-4 overflow-y-auto">
          <div className="flex items-start justify-between gap-4 pb-4 border-b border-hairline-strong">
            <div>
              {title && <h2 className="text-base font-semibold text-ink font-sans tracking-tight">{title}</h2>}
              {description && <p className="text-xs text-mute font-sans mt-0.5">{description}</p>}
            </div>
            <IconButton
              size="sm"
              label="Close sheet"
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
        </div>

        {footer && <div className="pt-4 border-t border-hairline-strong flex items-center justify-end gap-3">{footer}</div>}
      </div>
    </div>
  );
};
