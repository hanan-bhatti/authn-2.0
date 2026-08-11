import React from "react";
import { Label } from "./Label.js";
import { cn } from "../../utils/cn.js";

export interface FormFieldProps {
  label?: React.ReactNode;
  isRequired?: boolean;
  monospaceTag?: string;
  error?: string;
  hint?: string;
  children: React.ReactNode;
  className?: string;
}

export const FormField: React.FC<FormFieldProps> = ({
  label,
  isRequired = false,
  monospaceTag,
  error,
  hint,
  children,
  className,
}) => {
  return (
    <div className={cn("flex flex-col w-full gap-1", className)}>
      {label && (
        <Label isRequired={isRequired} monospaceTag={monospaceTag}>
          {label}
        </Label>
      )}
      {children}
      {error && <span className="text-[11px] font-sans text-[#ff9592] mt-1">{error}</span>}
      {!error && hint && <span className="text-[11px] font-sans text-[#a1a4a5] mt-1">{hint}</span>}
    </div>
  );
};
