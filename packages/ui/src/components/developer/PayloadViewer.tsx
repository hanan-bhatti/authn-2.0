import React from "react";
import { SyntaxHighlighter } from "./SyntaxHighlighter.js";
import { CopyButton } from "../actions/CopyButton.js";
import { cn } from "../../utils/cn.js";

export interface PayloadViewerProps {
  payload: Record<string, any> | string;
  title?: string;
  className?: string;
}

export const PayloadViewer: React.FC<PayloadViewerProps> = ({
  payload,
  title = "Payload Inspection",
  className,
}) => {
  const jsonStr = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);

  return (
    <div className={cn("flex flex-col bg-canvas border border-hairline-strong rounded-lg overflow-hidden", className)}>
      <div className="flex items-center justify-between px-4 py-2 border-b border-hairline-strong bg-canvas">
        <span className="font-mono text-xs text-mute">{title}</span>
        <CopyButton value={jsonStr} label="Copy JSON" />
      </div>
      <div className="p-3 overflow-x-auto">
        <SyntaxHighlighter code={jsonStr} language="json" />
      </div>
    </div>
  );
};
