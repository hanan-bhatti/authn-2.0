import React from "react";
import { cn } from "../../utils/cn.js";

export interface KbdProps extends React.HTMLAttributes<HTMLElement> {
  children: React.ReactNode;
}

export const Kbd: React.FC<KbdProps> = ({ children, className, ...props }) => {
  return (
    <kbd
      className={cn(
        "inline-flex items-center gap-0.5 px-1.5 py-0.5 font-mono text-[11px] font-medium text-[#a1a4a5] bg-[#000000] border border-[#292d30] rounded-[4px] select-none",
        className
      )}
      {...props}
    >
      {children}
    </kbd>
  );
};
