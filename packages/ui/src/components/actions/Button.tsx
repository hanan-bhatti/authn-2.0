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
 * Rules:
 * - 6px border-radius
 * - Ghost on Black default: transparent bg, 1px #292d30 border, #ffffff text
 * - Hover shifts border opacity to white
 * - Zero drop shadows
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
      "inline-flex items-center justify-center font-medium transition-all duration-150 ease-out select-none outline-none focus-visible:ring-1 focus-visible:ring-white disabled:opacity-50 disabled:pointer-events-none cursor-pointer";

    const variantStyles = {
      ghost:
        "bg-transparent border border-[#292d30] text-[#ffffff] hover:border-white hover:bg-white/[0.04] active:opacity-80",
      primary:
        "bg-[#3b9eff] border border-[#3b9eff] text-[#000000] font-semibold hover:bg-[#70b8ff] hover:border-[#70b8ff] active:opacity-90",
      secondary:
        "bg-transparent border border-[#292d30] text-[#f0f0f0] hover:border-[#a1a4a5] hover:text-white active:opacity-80",
      destructive:
        "bg-transparent border border-[#ff9592]/40 text-[#ff9592] hover:border-[#ff9592] hover:bg-[#ff9592]/10 active:opacity-80",
      outline:
        "bg-transparent border border-[#292d30] text-[#a1a4a5] hover:border-white hover:text-white active:opacity-80",
    };

    const sizeStyles = {
      sm: "h-8 px-3 text-xs rounded-[6px] gap-1.5",
      md: "h-10 px-4 text-sm rounded-[6px] gap-2",
      lg: "h-12 px-6 text-base rounded-[6px] gap-2.5",
    };

    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        className={cn(baseStyles, variantStyles[variant], sizeStyles[size], className)}
        style={{ borderRadius: "6px", ...style }}
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
