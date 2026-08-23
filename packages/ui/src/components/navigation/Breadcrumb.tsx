import React from "react";
import { Chevron } from "../display/Chevron.js";
import { cn } from "../../utils/cn.js";

export interface BreadcrumbItem {
  label: React.ReactNode;
  href?: string;
  isCurrent?: boolean;
}

export interface BreadcrumbProps {
  items: BreadcrumbItem[];
  className?: string;
}

export const Breadcrumb: React.FC<BreadcrumbProps> = ({ items, className }) => {
  return (
    <nav aria-label="Breadcrumb" className={cn("inline-flex items-center gap-1.5 text-xs font-sans select-none", className)}>
      {items.map((item, index) => {
        const isLast = index === items.length - 1;
        return (
          <React.Fragment key={index}>
            {index > 0 && <Chevron direction="right" size="sm" className="text-ash" />}
            {isLast || item.isCurrent ? (
              <span className="font-medium text-ink font-mono">{item.label}</span>
            ) : (
              <a href={item.href || "#"} className="text-mute hover:text-ink transition-colors">
                {item.label}
              </a>
            )}
          </React.Fragment>
        );
      })}
    </nav>
  );
};
