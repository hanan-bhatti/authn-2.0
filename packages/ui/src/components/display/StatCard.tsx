import React from "react";
import { cn } from "../../utils/cn.js";

export interface StatCardProps {
  title: string;
  value: string | number;
  trend?: string;
  trendType?: "positive" | "negative" | "neutral";
  subtitle?: string;
  icon?: React.ReactNode;
  className?: string;
}

/**
 * Resend-style Dashboard Metric Card
 *
 * Rules:
 * - 16px border radius
 * - 1px #292d30 hairline border
 * - #000000 canvas background
 * - No drop shadow
 */
export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  trend,
  trendType = "neutral",
  subtitle,
  icon,
  className,
}) => {
  const trendColorMap = {
    positive: "text-[#3ad389]",
    negative: "text-[#ff9592]",
    neutral: "text-[#a1a4a5]",
  };

  return (
    <div
      className={cn(
        "flex flex-col justify-between p-6 bg-[#000000] border border-[#292d30] rounded-[16px] transition-all duration-150 ease-out hover:border-white/[0.2]",
        className
      )}
    >
      <div className="flex items-center justify-between gap-2 mb-3">
        <span className="text-xs font-medium text-[#a1a4a5] font-sans uppercase tracking-wider">{title}</span>
        {icon && <div className="text-[#a1a4a5] flex-shrink-0">{icon}</div>}
      </div>

      <div className="flex items-baseline justify-between gap-3">
        <span className="text-3xl font-semibold text-[#ffffff] font-sans tracking-tight">{value}</span>
        {trend && (
          <span className={cn("text-xs font-mono font-medium", trendColorMap[trendType])}>
            {trend}
          </span>
        )}
      </div>

      {subtitle && <span className="text-[11px] text-[#6e727a] font-sans mt-2">{subtitle}</span>}
    </div>
  );
};
