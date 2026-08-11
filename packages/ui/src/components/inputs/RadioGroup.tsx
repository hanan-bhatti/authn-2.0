import React from "react";
import { cn } from "../../utils/cn.js";

export interface RadioOption {
  value: string;
  label: React.ReactNode;
  description?: string;
  disabled?: boolean;
}

export interface RadioGroupProps {
  name: string;
  options: RadioOption[];
  value?: string;
  onChange?: (value: string) => void;
  className?: string;
}

export const RadioGroup: React.FC<RadioGroupProps> = ({
  name,
  options,
  value,
  onChange,
  className,
}) => {
  return (
    <div className={cn("flex flex-col gap-2", className)}>
      {options.map((opt) => {
        const isSelected = value === opt.value;
        return (
          <label
            key={opt.value}
            className={cn(
              "flex items-start gap-3 p-3 bg-[#000000] border border-[#292d30] rounded-[6px] cursor-pointer transition-all duration-150 ease-out hover:border-white/[0.4]",
              isSelected && "border-white bg-white/[0.02]",
              opt.disabled && "opacity-40 cursor-not-allowed"
            )}
          >
            <input
              type="radio"
              name={name}
              value={opt.value}
              checked={isSelected}
              disabled={opt.disabled}
              onChange={() => !opt.disabled && onChange?.(opt.value)}
              className="sr-only"
            />
            <div
              className={cn(
                "mt-0.5 w-4 h-4 rounded-full border border-[#292d30] flex items-center justify-center transition-colors",
                isSelected && "border-white bg-white"
              )}
            >
              {isSelected && <div className="w-1.5 h-1.5 rounded-full bg-[#000000]" />}
            </div>
            <div className="flex flex-col">
              <span className="text-xs font-medium text-[#f0f0f0] font-sans">{opt.label}</span>
              {opt.description && <span className="text-[11px] text-[#a1a4a5] font-sans">{opt.description}</span>}
            </div>
          </label>
        );
      })}
    </div>
  );
};
