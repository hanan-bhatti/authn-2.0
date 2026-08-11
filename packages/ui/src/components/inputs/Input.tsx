import React from "react";
import { cn } from "../../utils/cn.js";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  isMonospace?: boolean;
  isInvalid?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

/**
 * Resend-style Form Input
 *
 * Rules:
 * - 6px border radius
 * - Pure #000000 background
 * - 1px #292d30 hairline border
 * - Focus border #ffffff
 */
export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  (
    {
      className,
      isMonospace = false,
      isInvalid = false,
      leftIcon,
      rightIcon,
      style,
      disabled,
      ...props
    },
    ref
  ) => {
    return (
      <div className="relative flex items-center w-full">
        {leftIcon && (
          <div className="absolute left-3 text-[#a1a4a5] pointer-events-none flex items-center justify-center">
            {leftIcon}
          </div>
        )}

        <input
          ref={ref}
          disabled={disabled}
          className={cn(
            "w-full h-10 bg-[#000000] border border-[#292d30] text-sm text-[#ffffff] placeholder-[#464a4d] transition-all duration-150 ease-out outline-none focus:border-white disabled:opacity-40 disabled:cursor-not-allowed",
            isMonospace ? "font-mono" : "font-sans",
            leftIcon ? "pl-9" : "px-3.5",
            rightIcon ? "pr-9" : "pr-3.5",
            isInvalid && "border-[#ff9592] focus:border-[#ff9592]",
            className
          )}
          style={{ borderRadius: "6px", ...style }}
          {...props}
        />

        {rightIcon && (
          <div className="absolute right-3 text-[#a1a4a5] flex items-center justify-center">
            {rightIcon}
          </div>
        )}
      </div>
    );
  }
);

Input.displayName = "Input";
