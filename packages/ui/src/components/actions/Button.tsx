"use client";

import React from "react";
import { cn } from "../../utils/cn.js";

export type ButtonProps = React.PropsWithChildren<
  React.ButtonHTMLAttributes<HTMLButtonElement> & {
    variant?: "ghost" | "primary" | "secondary" | "destructive" | "outline";
    size?: "sm" | "md" | "lg";
    isLoading?: boolean;
    leftIcon?: React.ReactNode;
    rightIcon?: React.ReactNode;
  }
>;

/**
 * Ghost & Action Button
 *
 * Ghost is the default because the design system allows at most one solid
 * bright surface per viewport: `primary` is a white rectangle on a black
 * canvas, the brightest pixel on the page, so it has to stay scarce enough to
 * read as the single anchor. Every other variant builds its edge from a
 * translucent hairline instead — the system has no drop-shadow elevation
 * language at all, so borders carry the whole weight of separating a control
 * from its surface.
 */
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      children,
      className,
      variant = "ghost",
      size = "md",
      isLoading = false,
      disabled,
      leftIcon,
      rightIcon,
      style,
      ...props
    },
    ref
  ) => {
    const baseStyles =
      "inline-flex items-center justify-center font-medium transition-all duration-150 ease-out select-none outline-none focus-visible:ring-1 focus-visible:ring-ink disabled:opacity-50 disabled:pointer-events-none cursor-pointer";

    const variantStyles = {
      ghost:
        "bg-transparent border border-hairline-strong text-ink hover:border-ink hover:bg-ink/[0.04] active:opacity-80",
      primary:
        "bg-primary border border-primary text-primary-on hover:bg-surface-light hover:border-surface-light active:opacity-90",
      secondary:
        "bg-transparent border border-hairline-strong text-ink hover:border-mute hover:text-ink active:opacity-80",
      destructive:
        "bg-transparent border border-accent-red/40 text-accent-red hover:border-accent-red hover:bg-accent-red/10 active:opacity-80",
      outline:
        "bg-transparent border border-hairline-strong text-mute hover:border-ink hover:text-ink active:opacity-80",
    };

    const sizeStyles = {
      sm: "h-8 px-3 text-xs rounded-md gap-1.5",
      md: "h-10 px-4 text-sm rounded-md gap-2",
      lg: "h-12 px-6 text-base rounded-md gap-2.5",
    };

    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        className={cn(baseStyles, variantStyles[variant], sizeStyles[size], className)}
        style={style}
        {...props}
      >
        {isLoading ? (
          <svg
            className="animate-spin h-4 w-4 text-current"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            ></path>
          </svg>
        ) : (
          leftIcon
        )}
        <span>{children}</span>
        {!isLoading && rightIcon}
      </button>
    );
  }
);

Button.displayName = "Button";
