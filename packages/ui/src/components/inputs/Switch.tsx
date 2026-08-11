import React from "react";
import { cn } from "../../utils/cn.js";

export interface SwitchProps {
  checked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
  disabled?: boolean;
  label?: React.ReactNode;
  className?: string;
}

export const Switch: React.FC<SwitchProps> = ({
  checked = false,
  onCheckedChange,
  disabled = false,
  label,
  className,
}) => {
  return (
    <label className={cn("inline-flex items-center gap-3 cursor-pointer select-none", disabled && "opacity-40 cursor-not-allowed", className)}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => !disabled && onCheckedChange?.(!checked)}
        className={cn(
          "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border border-[#292d30] transition-colors duration-150 ease-out focus-visible:ring-1 focus-visible:ring-white outline-none",
          checked ? "bg-white border-white" : "bg-[#000000]"
        )}
      >
        <span
          className={cn(
            "pointer-events-none inline-block h-3.5 w-3.5 rounded-full transition-transform duration-150 ease-out shadow-sm",
            checked ? "translate-x-4 bg-[#000000]" : "translate-x-0.5 bg-[#a1a4a5]"
          )}
        />
      </button>
      {label && <span className="text-xs font-medium text-[#f0f0f0] font-sans">{label}</span>}
    </label>
  );
};
