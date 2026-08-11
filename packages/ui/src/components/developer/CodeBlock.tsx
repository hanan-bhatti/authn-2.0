import React from "react";
import { SyntaxHighlighter } from "./SyntaxHighlighter.js";
import { CopyButton } from "../actions/CopyButton.js";
import { cn } from "../../utils/cn.js";

export interface CodeBlockProps {
  code: string;
  language?: "json" | "javascript" | "bash" | "go" | "html";
  title?: string;
  className?: string;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({
  code,
  language = "json",
  title,
  className,
}) => {
  return (
    <div
      className={cn(
        "flex flex-col bg-[#000000] border border-[#292d30] rounded-[16px] overflow-hidden",
        className
      )}
    >
      {(title || code) && (
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#292d30] bg-[#000000]">
          <span className="font-mono text-xs font-medium text-[#a1a4a5]">{title || language}</span>
          <CopyButton value={code} label="Copy" />
        </div>
      )}
      <div className="p-4 overflow-x-auto">
        <SyntaxHighlighter code={code} language={language} />
      </div>
    </div>
  );
};
