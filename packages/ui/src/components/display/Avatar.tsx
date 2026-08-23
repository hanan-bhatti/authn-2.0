import React from "react";
import { cn } from "../../utils/cn.js";

export interface AvatarProps {
  src?: string;
  name?: string;
  size?: "sm" | "md" | "lg";
  className?: string;
}

export const Avatar: React.FC<AvatarProps> = ({ src, name = "", size = "md", className }) => {
  const sizeMap = {
    sm: "w-6 h-6 text-[10px]",
    md: "w-8 h-8 text-xs",
    lg: "w-10 h-10 text-sm",
  };

  const initials = name
    .split(" ")
    .map((part) => part[0])
    .filter(Boolean)
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <div
      className={cn(
        "relative inline-flex items-center justify-center rounded-full bg-canvas border border-hairline-strong font-mono text-ink overflow-hidden select-none flex-shrink-0",
        sizeMap[size],
        className
      )}
    >
      {src ? (
        <img src={src} alt={name || "User Avatar"} className="w-full h-full object-cover" />
      ) : (
        <span>{initials || "U"}</span>
      )}
    </div>
  );
};
