import React from "react";
import { cn } from "../../utils/cn.js";

export interface TabItem {
  id: string;
  label: React.ReactNode;
  badge?: React.ReactNode;
  disabled?: boolean;
}

export interface TabsProps {
  tabs: TabItem[];
  activeId: string;
  onChange: (id: string) => void;
  className?: string;
}

export const Tabs: React.FC<TabsProps> = ({ tabs, activeId, onChange, className }) => {
  return (
    <div className={cn("flex items-center gap-6 border-b border-hairline-strong w-full select-none", className)}>
      {tabs.map((tab) => {
        const isActive = activeId === tab.id;
        return (
          <button
            key={tab.id}
            type="button"
            disabled={tab.disabled}
            onClick={() => !tab.disabled && onChange(tab.id)}
            className={cn(
              "relative pb-3 text-xs font-medium font-sans transition-colors duration-150 outline-none cursor-pointer flex items-center gap-2",
              isActive ? "text-ink" : "text-mute hover:text-ink",
              tab.disabled && "opacity-40 cursor-not-allowed"
            )}
          >
            <span>{tab.label}</span>
            {tab.badge}
            {isActive && <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-primary rounded-full" />}
          </button>
        );
      })}
    </div>
  );
};
