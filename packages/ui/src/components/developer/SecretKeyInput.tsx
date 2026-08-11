import React, { useState } from "react";
import { CopyButton } from "../actions/CopyButton.js";
import { cn } from "../../utils/cn.js";

export interface SecretKeyInputProps {
  value: string;
  label?: string;
  className?: string;
}

export const SecretKeyInput: React.FC<SecretKeyInputProps> = ({
  value,
  label = "API Secret Key",
  className,
}) => {
  const [isRevealed, setIsRevealed] = useState(false);

  const maskedValue = value ? `${value.slice(0, 7)}${"•".repeat(Math.max(0, value.length - 7))}` : "";

  return (
    <div className={cn("flex flex-col gap-1.5 w-full", className)}>
      {label && <span className="text-xs font-medium text-[#f0f0f0] font-sans">{label}</span>}
      <div className="flex items-center gap-2 p-1.5 bg-[#000000] border border-[#292d30] rounded-[6px]">
        <input
          type="text"
          readOnly
          value={isRevealed ? value : maskedValue}
          className="flex-1 bg-transparent font-mono text-xs text-[#9281f7] outline-none px-2 select-all"
        />
        <button
          type="button"
          onClick={() => setIsRevealed(!isRevealed)}
          className="px-2 py-1 text-xs font-mono text-[#a1a4a5] hover:text-white transition-colors cursor-pointer"
        >
          {isRevealed ? "Hide" : "Reveal"}
        </button>
        <CopyButton value={value} label="Copy" />
      </div>
    </div>
  );
};
