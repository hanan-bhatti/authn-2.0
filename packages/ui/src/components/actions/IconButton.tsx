"use client";

import React from "react";
import { cn } from "../../utils/cn.js";

export interface IconButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  icon: React.ReactNode;
  label: string;
  variant?: "ghost" | "secondary" | "outline";
  size?: "sm" | "md" | "lg";
}

export const IconButton = React.forwardRef<HTMLButtonElement, IconButtonProps>(
  ({ icon, label, className, variant = "ghost", size = "md", style, ...props }, ref) => {
    // Mirrors Button's variant vocabulary so an icon-only action sitting in the
    // same row as a labelled one shares its resting and hover treatment.
    const variantMap = {
      ghost: "text-ink hover:border-ink hover:bg-ink/[0.04]",
      secondary: "text-ink hover:border-mute",
      outline: "text-mute hover:border-ink hover:text-ink",
    };

    const sizeMap = {
      sm: "w-7 h-7 rounded-md p-1 text-xs",
      md: "w-9 h-9 rounded-md p-2 text-sm",
      lg: "w-11 h-11 rounded-md p-2.5 text-base",
    };

    return (
      <button
        ref={ref}
        aria-label={label}
        title={label}
        className={cn(
          "inline-flex items-center justify-center bg-transparent border border-hairline-strong transition-all duration-150 ease-out outline-none focus-visible:ring-1 focus-visible:ring-ink disabled:opacity-40 cursor-pointer",
          variantMap[variant],
          sizeMap[size],
          className
        )}
        style={style}
        {...props}
      >
        {icon}
      </button>
    );
  }
);

IconButton.displayName = "IconButton";
