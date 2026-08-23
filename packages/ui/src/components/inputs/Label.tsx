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
        "inline-flex items-center justify-between w-full text-xs font-medium text-ink font-sans select-none mb-1.5",
        className
      )}
      {...props}
    >
      <span>
        {children}
        {isRequired && <span className="text-accent-red ml-0.5">*</span>}
      </span>
      {monospaceTag && <span className="font-mono text-[11px] text-mute">{monospaceTag}</span>}
    </label>
  );
};
