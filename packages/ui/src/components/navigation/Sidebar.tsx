import React from "react";
import { cn } from "../../utils/cn.js";

export interface SidebarItem {
  id: string;
  label: string;
  href?: string;
  icon?: React.ReactNode;
  badge?: React.ReactNode;
  isActive?: boolean;
}

export interface SidebarGroup {
  title?: string;
  items: SidebarItem[];
}

export interface SidebarProps {
  groups: SidebarGroup[];
  onItemClick?: (id: string) => void;
  footer?: React.ReactNode;
  className?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({
  groups,
  onItemClick,
  footer,
  className,
}) => {
  return (
    <aside
      className={cn(
        "flex flex-col justify-between w-60 h-full bg-canvas border-r border-hairline-strong p-4 select-none flex-shrink-0",
        className
      )}
    >
      <div className="flex flex-col gap-6 overflow-y-auto">
        {groups.map((group, idx) => (
          <div key={idx} className="flex flex-col gap-1">
            {group.title && (
              <span className="px-2 text-[10px] font-mono font-medium text-ash uppercase tracking-wider mb-1">
                {group.title}
              </span>
            )}
            {group.items.map((item) => (
              <a
                key={item.id}
                href={item.href || "#"}
                onClick={(e) => {
                  if (onItemClick) {
                    e.preventDefault();
                    onItemClick(item.id);
                  }
                }}
                className={cn(
                  "flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium font-sans text-mute transition-all duration-150 ease-out hover:text-ink hover:bg-ink/[0.04]",
                  item.isActive && "text-ink bg-ink/[0.06] border border-hairline-strong"
                )}
              >
                <div className="flex items-center gap-2.5">
                  {item.icon && <span className="w-4 h-4 flex-shrink-0 text-current">{item.icon}</span>}
                  <span>{item.label}</span>
                </div>
                {item.badge}
              </a>
            ))}
          </div>
        ))}
      </div>

      {footer && <div className="pt-4 border-t border-hairline-strong">{footer}</div>}
    </aside>
  );
};
