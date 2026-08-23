"use client";

import React from "react";
import { cn } from "../../utils/cn.js";

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  isMonospace?: boolean;
  isInvalid?: boolean;
}

export const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, isMonospace = false, isInvalid = false, disabled, style, ...props }, ref) => {
    return (
      <textarea
        ref={ref}
        disabled={disabled}
        className={cn(
          "w-full min-h-[100px] bg-[#000000] border border-[#292d30] text-sm text-[#ffffff] placeholder-[#464a4d] p-3.5 transition-all duration-150 ease-out outline-none focus:border-white disabled:opacity-40 disabled:cursor-not-allowed resize-y",
          isMonospace ? "font-mono text-xs leading-relaxed" : "font-sans",
          isInvalid && "border-[#ff9592] focus:border-[#ff9592]",
          className
        )}
        style={{ borderRadius: "6px", ...style }}
        {...props}
      />
    );
  }
);

Textarea.displayName = "Textarea";
