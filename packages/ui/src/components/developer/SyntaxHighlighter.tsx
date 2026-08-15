import React from "react";
import { cn } from "../../utils/cn.js";

export interface SyntaxHighlighterProps {
  code: string;
  language?: "json" | "javascript" | "bash" | "go" | "html";
  className?: string;
}

/**
 * Monospaced Syntax Highlighter
 *
 * Rules:
 * - Iris Violet #9281f7 for strings & developer tokens
 * - Green #3ad389 for success values & booleans
 * - Red #ff9592 for numbers/errors
 * - White #ffffff for keys/keywords
 */
export const SyntaxHighlighter: React.FC<SyntaxHighlighterProps> = ({
  code,
  language = "json",
  className,
}) => {
  const formatJSON = (jsonStr: string) => {
    try {
      const parsed = typeof jsonStr === "string" ? JSON.parse(jsonStr) : jsonStr;
      const formatted = JSON.stringify(parsed, null, 2);

      const lines = formatted.split("\n");
      return lines.map((line, i) => {
        // Regex to tokenize JSON keys, strings, numbers, booleans
        const tokenized = line.replace(
          /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
          (match) => {
            let cls = "text-[#f0f0f0]"; // default text
            if (/^"/.test(match)) {
              if (/:$/.test(match)) {
                cls = "text-[#a1a4a5]"; // Key
              } else {
                cls = "text-[#9281f7]"; // String (Iris Violet)
              }
            } else if (/true|false/.test(match)) {
              cls = "text-[#3ad389]"; // Boolean (Pulse Green)
            } else if (/null/.test(match)) {
              cls = "text-[#ffca16]"; // Null (Amber)
            } else if (/-?\d+/.test(match)) {
              cls = "text-[#ff9592]"; // Number (Alarm Red)
            }
            return `<span class="${cls}">${match}</span>`;
          }
        );

        return (
          <div key={i} className="table-row">
            <span className="table-cell pr-4 text-right select-none text-[#464a4d] text-[11px] font-mono w-8">
              {i + 1}
            </span>
            <span
              className="table-cell font-mono text-xs text-[#f0f0f0] whitespace-pre"
              dangerouslySetInnerHTML={{ __html: tokenized }}
            />
          </div>
        );
      });
    } catch {
      // Fallback plain lines
      return code.split("\n").map((line, i) => (
        <div key={i} className="table-row">
          <span className="table-cell pr-4 text-right select-none text-[#464a4d] text-[11px] font-mono w-8">
            {i + 1}
          </span>
          <span className="table-cell font-mono text-xs text-[#f0f0f0] whitespace-pre">{line}</span>
        </div>
      ));
    }
  };

  return (
    <div className={cn("font-mono overflow-x-auto text-xs leading-relaxed", className)}>
      <div className="table w-full border-collapse">
        {language === "json" ? formatJSON(code) : code.split("\n").map((line, i) => (
          <div key={i} className="table-row">
            <span className="table-cell pr-4 text-right select-none text-[#464a4d] text-[11px] font-mono w-8">
              {i + 1}
            </span>
            <span className="table-cell font-mono text-xs text-[#f0f0f0] whitespace-pre">{line}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
