import React, { useRef, useState } from "react";
import { cn } from "../../utils/cn.js";

export interface InputOTPProps {
  length?: number;
  value?: string;
  onChange?: (value: string) => void;
  onComplete?: (value: string) => void;
  isDisabled?: boolean;
  className?: string;
}

export const InputOTP: React.FC<InputOTPProps> = ({
  length = 6,
  value = "",
  onChange,
  onComplete,
  isDisabled = false,
  className,
}) => {
  const [internalValue, setInternalValue] = useState<string[]>(
    Array.from({ length }, (_, i) => value[i] || "")
  );

  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  const handleChange = (index: number, val: string) => {
    if (isDisabled) return;
    const sanitized = val.replace(/[^0-9]/g, "");
    if (!sanitized) {
      const next = [...internalValue];
      next[index] = "";
      setInternalValue(next);
      onChange?.(next.join(""));
      return;
    }

    const char = sanitized[sanitized.length - 1];
    const next = [...internalValue];
    next[index] = char;
    setInternalValue(next);

    const fullVal = next.join("");
    onChange?.(fullVal);

    if (index < length - 1 && char) {
      inputRefs.current[index + 1]?.focus();
    }

    if (fullVal.length === length && !fullVal.includes("")) {
      onComplete?.(fullVal);
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !internalValue[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData("text").replace(/[^0-9]/g, "").slice(0, length);
    if (!pasted) return;

    const next = Array.from({ length }, (_, i) => pasted[i] || "");
    setInternalValue(next);
    const fullVal = next.join("");
    onChange?.(fullVal);
    if (fullVal.length === length) {
      onComplete?.(fullVal);
    }
  };

  return (
    <div className={cn("inline-flex items-center gap-2", className)}>
      {Array.from({ length }).map((_, i) => (
        <input
          key={i}
          ref={(el) => { inputRefs.current[i] = el; }}
          type="text"
          inputMode="numeric"
          maxLength={1}
          disabled={isDisabled}
          value={internalValue[i]}
          onChange={(e) => handleChange(i, e.target.value)}
          onKeyDown={(e) => handleKeyDown(i, e)}
          onPaste={handlePaste}
          className="w-10 h-12 bg-[#000000] border border-[#292d30] rounded-[6px] text-center font-mono text-lg text-[#ffffff] outline-none transition-all duration-150 focus:border-white disabled:opacity-40"
        />
      ))}
    </div>
  );
};
