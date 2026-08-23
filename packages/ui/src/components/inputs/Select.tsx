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
            "w-full h-10 bg-[#000000] border border-[#292d30] text-sm text-[#ffffff] px-3.5 pr-9 appearance-none transition-all duration-150 ease-out outline-none focus:border-white disabled:opacity-40 cursor-pointer",
            isMonospace ? "font-mono" : "font-sans",
            className
          )}
          style={{ borderRadius: "6px", ...style }}
          {...props}
        >
          {options.map((opt) => (
            <option key={opt.value} value={opt.value} disabled={opt.disabled} className="bg-[#000000] text-white">
              {opt.label}
            </option>
          ))}
        </select>
        <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-[#a1a4a5]">
          <svg className="w-4 h-4 stroke-current" fill="none" viewBox="0 0 24 24" strokeWidth="2">
            <polyline points="6 9 12 15 18 9"></polyline>
          </svg>
        </div>
      </div>
    );
  }
);

Select.displayName = "Select";
