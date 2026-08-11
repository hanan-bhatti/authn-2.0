import React from "react";
import { cn } from "../../utils/cn.js";

export interface ChevronProps extends React.SVGProps<SVGSVGElement> {
  direction?: "up" | "down" | "left" | "right";
  size?: "sm" | "md" | "lg";
}

export const Chevron: React.FC<ChevronProps> = ({
  direction = "right",
  size = "md",
  className,
  ...props
}) => {
  const sizeMap = {
    sm: "w-3 h-3",
    md: "w-4 h-4",
    lg: "w-5 h-5",
  };

  const rotationMap = {
    up: "-rotate-90",
    down: "rotate-90",
    left: "rotate-180",
    right: "rotate-0",
  };

  return (
    <svg
      className={cn(
        "stroke-current transition-transform duration-150 ease-out flex-shrink-0",
        sizeMap[size],
        rotationMap[direction],
        className
      )}
      fill="none"
      viewBox="0 0 24 24"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <polyline points="9 18 15 12 9 6"></polyline>
    </svg>
  );
};
