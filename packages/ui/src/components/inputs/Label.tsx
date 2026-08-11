import React from "react";
import { cn } from "../../utils/cn.js";

export interface LabelProps extends React.LabelHTMLAttributes<HTMLLabelElement> {
  isRequired?: boolean;
  monospaceTag?: string;
}

export const Label: React.FC<LabelProps> = ({
  children,
  className,
  isRequired = false,
  monospaceTag,
  ...props
}) => {
  return (
    <label
      className={cn(
        "inline-flex items-center justify-between w-full text-xs font-medium text-[#f0f0f0] font-sans select-none mb-1.5",
        className
      )}
      {...props}
    >
      <span>
        {children}
        {isRequired && <span className="text-[#ff9592] ml-0.5">*</span>}
      </span>
      {monospaceTag && <span className="font-mono text-[11px] text-[#9281f7]">{monospaceTag}</span>}
    </label>
  );
};
