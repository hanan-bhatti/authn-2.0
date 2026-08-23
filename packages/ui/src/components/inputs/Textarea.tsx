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
        aria-invalid={isInvalid || undefined}
        className={cn(
          "w-full min-h-[100px] rounded-md bg-surface-card border border-hairline-strong text-sm text-ink placeholder-stone p-3.5 transition-all duration-150 ease-out outline-none focus:border-ink disabled:opacity-40 disabled:cursor-not-allowed resize-y",
          isMonospace ? "font-mono text-xs leading-relaxed" : "font-sans",
          isInvalid && "border-accent-red focus:border-accent-red",
          className
        )}
        style={style}
        {...props}
      />
    );
  }
);

Textarea.displayName = "Textarea";
