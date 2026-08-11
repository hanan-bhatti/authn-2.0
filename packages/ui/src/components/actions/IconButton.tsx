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
    const sizeMap = {
      sm: "w-7 h-7 rounded-[6px] p-1 text-xs",
      md: "w-9 h-9 rounded-[6px] p-2 text-sm",
      lg: "w-11 h-11 rounded-[6px] p-2.5 text-base",
    };

    return (
      <button
        ref={ref}
        aria-label={label}
        title={label}
        className={cn(
          "inline-flex items-center justify-center bg-transparent border border-[#292d30] text-[#a1a4a5] hover:text-white hover:border-white transition-all duration-150 ease-out outline-none focus-visible:ring-1 focus-visible:ring-white disabled:opacity-40 cursor-pointer",
          sizeMap[size],
          className
        )}
        style={{ borderRadius: "6px", ...style }}
        {...props}
      >
        {icon}
      </button>
    );
  }
);

IconButton.displayName = "IconButton";
