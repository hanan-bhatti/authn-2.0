"use client";

import React from "react";
import { cn } from "../../utils/cn.js";

export interface CheckboxProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "type"> {
  label?: React.ReactNode;
}

export const Checkbox = React.forwardRef<HTMLInputElement, CheckboxProps>(
  ({ className, label, disabled, checked, style, ...props }, ref) => {
    return (
      <label className={cn("inline-flex items-center gap-2.5 cursor-pointer select-none", disabled && "opacity-40 cursor-not-allowed")}>
        <div className="relative flex items-center justify-center">
          <input
            ref={ref}
            type="checkbox"
            checked={checked}
            disabled={disabled}
            className={cn(
              "peer w-4 h-4 appearance-none bg-[#000000] border border-[#292d30] transition-all duration-150 ease-out outline-none focus-visible:ring-1 focus-visible:ring-white checked:bg-white checked:border-white cursor-pointer",
              className
            )}
            style={{ borderRadius: "4px", ...style }}
            {...props}
          />
          <svg
            className="absolute w-3 h-3 text-[#000000] opacity-0 peer-checked:opacity-100 pointer-events-none transition-opacity duration-150"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth="3"
          >
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
        </div>
        {label && <span className="text-xs text-[#f0f0f0] font-sans">{label}</span>}
      </label>
    );
  }
);

Checkbox.displayName = "Checkbox";
