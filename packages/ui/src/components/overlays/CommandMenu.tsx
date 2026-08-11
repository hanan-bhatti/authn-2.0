import React, { useState, useEffect } from "react";
import { Kbd } from "../display/Kbd.js";
import { cn } from "../../utils/cn.js";

export interface CommandItem {
  id: string;
  label: string;
  category?: string;
  shortcut?: string;
  icon?: React.ReactNode;
  onSelect?: () => void;
}

export interface CommandMenuProps {
  isOpen: boolean;
  onClose: () => void;
  items: CommandItem[];
  placeholder?: string;
  className?: string;
}

export const CommandMenu: React.FC<CommandMenuProps> = ({
  isOpen,
  onClose,
  items,
  placeholder = "Type a command or search...",
  className,
}) => {
  const [query, setQuery] = useState("");

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        if (isOpen) onClose();
        else setQuery("");
      }
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const filteredItems = items.filter((item) =>
    item.label.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 p-4 select-none">
      <div className="fixed inset-0 bg-[#000000]/80 backdrop-blur-[25px]" onClick={onClose} />

      <div
        className={cn(
          "relative z-10 w-full max-w-lg bg-[#000000] border border-[#292d30] rounded-[16px] overflow-hidden shadow-2xl flex flex-col animate-in fade-in zoom-in-95",
          className
        )}
      >
        <div className="flex items-center px-4 py-3 border-b border-[#292d30] gap-3">
          <svg className="w-4 h-4 text-[#a1a4a5] stroke-current" fill="none" viewBox="0 0 24 24" strokeWidth="2">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={placeholder}
            className="w-full bg-transparent text-sm text-white font-sans outline-none placeholder-[#464a4d]"
          />
          <Kbd>ESC</Kbd>
        </div>

        <div className="max-h-72 overflow-y-auto p-2 flex flex-col gap-1">
          {filteredItems.length === 0 ? (
            <div className="py-8 text-center text-xs font-mono text-[#a1a4a5]">No commands found.</div>
          ) : (
            filteredItems.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  item.onSelect?.();
                  onClose();
                }}
                className="flex items-center justify-between px-3 py-2 rounded-[6px] text-xs font-sans text-[#f0f0f0] hover:text-white hover:bg-white/[0.04] transition-colors outline-none cursor-pointer"
              >
                <div className="flex items-center gap-2.5">
                  {item.icon && <span className="w-4 h-4 text-[#a1a4a5]">{item.icon}</span>}
                  <span>{item.label}</span>
                </div>
                {item.shortcut && <Kbd>{item.shortcut}</Kbd>}
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
