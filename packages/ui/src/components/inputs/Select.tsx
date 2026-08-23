"use client";

import React from "react";
import { cn } from "../../utils/cn.js";

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  options: SelectOption[];
  isMonospace?: boolean;
}

export const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  ({ className, options, isMonospace = false, disabled, style, ...props }, ref) => {
    return (
      <div className="relative w-full">
        <select
          ref={ref}
          disabled={disabled}
          className={cn(
            "w-full h-10 rounded-md bg-surface-card border border-hairline-strong text-sm text-ink px-3.5 pr-9 appearance-none transition-all duration-150 ease-out outline-none focus:border-ink disabled:opacity-40 cursor-pointer",
            isMonospace ? "font-mono" : "font-sans",
            className
          )}
          style={style}
          {...props}
        >
          {options.map((opt) => (
            <option key={opt.value} value={opt.value} disabled={opt.disabled} className="bg-surface-card text-ink">
              {opt.label}
            </option>
          ))}
        </select>
        <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-mute">
          <svg className="w-4 h-4 stroke-current" fill="none" viewBox="0 0 24 24" strokeWidth="2">
            <polyline points="6 9 12 15 18 9"></polyline>
          </svg>
        </div>
      </div>
    );
  }
);

Select.displayName = "Select";
