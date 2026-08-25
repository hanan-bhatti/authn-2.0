import React from "react";
import { cn } from "../../utils/cn.js";

export interface EmptyStateProps {
  /**
   * A 24px glyph, set on a plaque. Right for a compact empty state inside a
   * panel, a tab or a table, where a drawing would be larger than the space the
   * missing content would have occupied.
   */
  icon?: React.ReactNode;
  /**
   * A scene, rendered bare. Right for a full-card empty state, which is where the
   * illustration set does its second job: a card saying only "no applications"
   * reads as a card that failed, and the drawing is what makes it read as "nothing
   * here yet".
   *
   * Separate from `icon` rather than sharing it, because the plaque is the whole
   * difference. A 180-unit scene inside a fixed 48px bordered box overflows it and
   * the layout goes on reserving 48px, so the drawing collides with the heading
   * underneath and the plaque's border cuts across the middle of it.
   */
  illustration?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  illustration,
  title,
  description,
  action,
  className,
}) => {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center p-12 text-center bg-canvas border border-hairline-strong rounded-lg w-full select-none",
        className
      )}
    >
      {illustration ? (
        <div className="mb-4">{illustration}</div>
      ) : (
        <div className="w-12 h-12 rounded-lg bg-canvas border border-hairline-strong flex items-center justify-center text-mute mb-4">
          {icon || (
            <svg className="w-6 h-6 stroke-current" fill="none" viewBox="0 0 24 24" strokeWidth="1.5">
              <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
              <line x1="9" y1="9" x2="15" y2="15"></line>
              <line x1="15" y1="9" x2="9" y2="15"></line>
            </svg>
          )}
        </div>
      )}

      <h3 className="text-base font-semibold text-ink font-sans tracking-tight mb-1">{title}</h3>
      {description && <p className="text-xs text-mute font-sans max-w-compact mb-6">{description}</p>}
      {action}
    </div>
  );
};
