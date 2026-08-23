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
 * Dashboard Metric Card
 *
 * Sits on the canvas rather than an elevated surface: a wall of these is the
 * usual layout, and giving each one a lighter fill turns the grid into stripes.
 * The hairline alone carries the separation, which is also why there is no
 * shadow — the system builds elevation from translucent borders only.
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
    positive: "text-accent-green",
    negative: "text-accent-red",
    neutral: "text-mute",
  };

  return (
    <div
      className={cn(
        "flex flex-col justify-between p-6 bg-canvas border border-hairline-strong rounded-lg transition-all duration-150 ease-out hover:border-ink/[0.2]",
        className
      )}
    >
      <div className="flex items-center justify-between gap-2 mb-3">
        <span className="text-xs font-medium text-mute font-sans uppercase tracking-wider">{title}</span>
        {icon && <div className="text-mute flex-shrink-0">{icon}</div>}
      </div>

      <div className="flex items-baseline justify-between gap-3">
        <span className="text-3xl font-semibold text-ink font-sans tracking-tight">{value}</span>
        {trend && (
          <span className={cn("text-xs font-mono font-medium", trendColorMap[trendType])}>
            {trend}
          </span>
        )}
      </div>

      {subtitle && <span className="text-[11px] text-ash font-sans mt-2">{subtitle}</span>}
    </div>
  );
};
