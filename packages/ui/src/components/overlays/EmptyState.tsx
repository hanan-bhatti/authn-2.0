import React from "react";
import { cn } from "../../utils/cn.js";

export interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
  className,
}) => {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center p-12 text-center bg-[#000000] border border-[#292d30] rounded-[16px] w-full select-none",
        className
      )}
    >
      <div className="w-12 h-12 rounded-[12px] bg-[#000000] border border-[#292d30] flex items-center justify-center text-[#a1a4a5] mb-4">
        {icon || (
          <svg className="w-6 h-6 stroke-current" fill="none" viewBox="0 0 24 24" strokeWidth="1.5">
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
            <line x1="9" y1="9" x2="15" y2="15"></line>
            <line x1="15" y1="9" x2="9" y2="15"></line>
          </svg>
        )}
      </div>

      <h3 className="text-base font-semibold text-white font-sans tracking-tight mb-1">{title}</h3>
      {description && <p className="text-xs text-[#a1a4a5] font-sans max-w-sm mb-6">{description}</p>}
      {action}
    </div>
  );
};
