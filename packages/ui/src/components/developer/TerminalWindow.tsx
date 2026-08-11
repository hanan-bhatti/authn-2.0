import React from "react";
import { SyntaxHighlighter } from "./SyntaxHighlighter.js";
import { cn } from "../../utils/cn.js";

export interface TerminalWindowProps {
  title?: string;
  output: string;
  language?: "json" | "bash" | "javascript";
  className?: string;
}

export const TerminalWindow: React.FC<TerminalWindowProps> = ({
  title = "authn-terminal",
  output,
  language = "bash",
  className,
}) => {
  return (
    <div
      className={cn(
        "flex flex-col bg-[#000000] border border-[#292d30] rounded-[16px] overflow-hidden font-mono text-xs",
        className
      )}
    >
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#292d30] bg-[#000000]">
        <div className="flex items-center gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-[#292d30]" />
          <div className="w-2.5 h-2.5 rounded-full bg-[#292d30]" />
          <div className="w-2.5 h-2.5 rounded-full bg-[#292d30]" />
        </div>
        <span className="text-[11px] text-[#a1a4a5] font-medium">{title}</span>
        <div className="w-12" /> {/* Spacer */}
      </div>

      <div className="p-4 overflow-x-auto">
        <SyntaxHighlighter code={output} language={language} />
      </div>
    </div>
  );
};
