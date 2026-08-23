import React from "react";
import { cn } from "../../utils/cn.js";

export interface KbdProps extends React.HTMLAttributes<HTMLElement> {
  children: React.ReactNode;
}

export const Kbd: React.FC<KbdProps> = ({ children, className, ...props }) => {
  return (
    <kbd
      className={cn(
        "inline-flex items-center gap-0.5 px-1.5 py-0.5 font-mono text-[11px] font-medium text-mute bg-canvas border border-hairline-strong rounded-xs select-none",
        className
      )}
      {...props}
    >
      {children}
    </kbd>
  );
};
