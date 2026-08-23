"use client";

import React, { useState } from "react";
import { cn } from "../../utils/cn.js";

export interface CopyButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  value: string;
  label?: string;
  copiedDuration?: number;
}

export const CopyButton: React.FC<CopyButtonProps> = ({
  value,
  label = "Copy",
  copiedDuration = 2000,
  className,
  ...props
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), copiedDuration);
    } catch {
      // Fallback if clipboard API is restricted
    }
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={copied ? "Copied to clipboard" : label}
      className={cn(
        "inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono text-mute bg-canvas border border-hairline-strong rounded-md hover:text-ink hover:border-ink transition-all duration-150 ease-out outline-none focus-visible:ring-1 focus-visible:ring-ink cursor-pointer",
        copied && "border-accent-green text-accent-green hover:border-accent-green hover:text-accent-green",
        className
      )}
      {...props}
    >
      {copied ? (
        <>
          <svg className="w-3.5 h-3.5 stroke-current" fill="none" viewBox="0 0 24 24" strokeWidth="2">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
          <span>Copied</span>
        </>
      ) : (
        <>
          <svg className="w-3.5 h-3.5 stroke-current" fill="none" viewBox="0 0 24 24" strokeWidth="1.75">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
          <span>{label}</span>
        </>
      )}
    </button>
  );
};
