import React from "react";
import { cn } from "../../utils/cn.js";

export interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "control" | "card" | "text" | "avatar";
}

export const Skeleton: React.FC<SkeletonProps> = ({
  className,
  variant = "text",
  style,
  ...props
}) => {
  const variantStyles = {
    control: "h-10 w-full rounded-[6px]",
    card: "h-32 w-full rounded-[16px]",
    text: "h-4 w-3/4 rounded-[4px]",
    avatar: "h-8 w-8 rounded-full flex-shrink-0",
  };

  return (
    <div
      className={cn(
        "bg-[#292d30]/50 animate-pulse transition-opacity",
        variantStyles[variant],
        className
      )}
      style={style}
      {...props}
    />
  );
};
