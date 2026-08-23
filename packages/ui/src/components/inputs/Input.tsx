"use client";

import React from "react";
import { cn } from "../../utils/cn.js";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  isMonospace?: boolean;
  isInvalid?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

/**
 * Form Input
 *
 * Fills from the card surface rather than the canvas so the field reads as an
 * inset well even before it is focused — on a true-black page an unfocused
 * canvas-filled input is just a rectangle of border. Focus swaps the hairline
 * for ink instead of adding a ring, keeping the control the same size in both
 * states so a focused field never nudges the layout.
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
          <div className="absolute left-3 text-mute pointer-events-none flex items-center justify-center">
            {leftIcon}
          </div>
        )}

        <input
          ref={ref}
          disabled={disabled}
          aria-invalid={isInvalid || undefined}
          className={cn(
            "w-full h-10 rounded-md bg-surface-card border border-hairline-strong text-sm text-ink placeholder-stone transition-all duration-150 ease-out outline-none focus:border-ink disabled:opacity-40 disabled:cursor-not-allowed",
            isMonospace ? "font-mono" : "font-sans",
            leftIcon ? "pl-9" : "px-3.5",
            rightIcon ? "pr-9" : "pr-3.5",
            isInvalid && "border-accent-red focus:border-accent-red",
            className
          )}
          style={style}
          {...props}
        />

        {rightIcon && (
          <div className="absolute right-3 text-mute flex items-center justify-center">
            {rightIcon}
          </div>
        )}
      </div>
    );
  }
);

Input.displayName = "Input";
