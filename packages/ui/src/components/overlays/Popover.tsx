"use client";

import React, { useState, useRef, useEffect } from "react";
import { cn } from "../../utils/cn.js";

export interface PopoverProps {
  trigger: React.ReactNode;
  content: React.ReactNode;
  align?: "left" | "right";
  className?: string;
}

export const Popover: React.FC<PopoverProps> = ({
  trigger,
  content,
  align = "left",
  className,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <div ref={containerRef} className="relative inline-block select-none">
      <div onClick={() => setIsOpen(!isOpen)} className="cursor-pointer">
        {trigger}
      </div>

      {isOpen && (
        <div
          className={cn(
            "absolute z-50 mt-2 w-64 bg-canvas border border-hairline-strong rounded-lg p-4 backdrop-scrim animate-enter-scale",
            align === "right" ? "right-0" : "left-0",
            className
          )}
        >
          {content}
        </div>
      )}
    </div>
  );
};
