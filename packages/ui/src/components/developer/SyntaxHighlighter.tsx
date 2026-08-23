import React from "react";
import { cn } from "../../utils/cn.js";

export interface SyntaxHighlighterProps {
  code: string;
  language?: "json" | "javascript" | "bash" | "go" | "html";
  className?: string;
}

interface Token {
  text: string;
  className: string;
}

/**
 * JSON keys, string values, literals and numbers, in one pass.
 *
 * The alternation order matters: a quoted run has to be consumed before the
 * number branch can see the digits inside it, or `"port: 8080"` would be
 * tokenized as a string, a number and a string again.
 */
const JSON_TOKEN =
  /"(?:\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"\s*:?|\b(?:true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?/g;

/**
 * Accent roles are assigned by meaning, not by convenience: red stays reserved
 * for genuine failure so an error surface rendered next to a payload still
 * reads as the alarming one, which leaves orange for numbers.
 */
function classFor(match: string): string {
  if (match.startsWith('"')) {
    return match.trimEnd().endsWith(":") ? "text-mute" : "text-accent-green";
  }
  if (match === "true" || match === "false") return "text-accent-blue";
  if (match === "null") return "text-accent-yellow";
  return "text-accent-orange";
}

/**
 * Splits one line into coloured spans.
 *
 * This returns data rather than an HTML string because the code being
 * highlighted is usually an API response, and a response field is allowed to
 * contain angle brackets. Assembling markup here and handing it to
 * `dangerouslySetInnerHTML` would let a stored value like `<img onerror=…>`
 * execute; React escapes text nodes for us.
 */
function tokenize(line: string): Token[] {
  const tokens: Token[] = [];
  let cursor = 0;

  for (const match of line.matchAll(JSON_TOKEN)) {
    const at = match.index ?? cursor;
    if (at > cursor) {
      tokens.push({ text: line.slice(cursor, at), className: "text-ink" });
    }
    tokens.push({ text: match[0], className: classFor(match[0]) });
    cursor = at + match[0].length;
  }

  if (cursor < line.length) {
    tokens.push({ text: line.slice(cursor), className: "text-ink" });
  }

  return tokens;
}

interface CodeLineProps {
  number: number;
  tokens: Token[];
}

const CodeLine: React.FC<CodeLineProps> = ({ number, tokens }) => (
  <div className="table-row">
    <span className="table-cell w-8 pr-4 text-right font-mono text-[11px] text-stone select-none">
      {number}
    </span>
    <span className="table-cell font-mono text-xs text-ink whitespace-pre">
      {tokens.map((token, i) => (
        <span key={i} className={token.className}>
          {token.text}
        </span>
      ))}
    </span>
  </div>
);

function highlight(code: string, language: SyntaxHighlighterProps["language"]): Token[][] {
  if (language === "json") {
    try {
      const parsed = typeof code === "string" ? JSON.parse(code) : code;
      return JSON.stringify(parsed, null, 2).split("\n").map(tokenize);
    } catch {
      // Unparseable input is still worth showing: a half-typed payload in a
      // live editor would otherwise blank the panel on every keystroke.
    }
  }
  return code.split("\n").map((line) => [{ text: line, className: "text-ink" }]);
}

/**
 * Monospaced Syntax Highlighter
 *
 * Only JSON is tokenized. Any other language is still numbered and set in the
 * mono family, so a bash or Go snippet keeps the same gutter and rhythm as the
 * payload it sits beside instead of falling back to unstyled text.
 *
 * Deliberately hook-free: highlighting a payload is something a docs page wants
 * to do on the server, and a `useMemo` here would force every importing page
 * into a client boundary to save a parse of a snippet.
 */
export const SyntaxHighlighter: React.FC<SyntaxHighlighterProps> = ({
  code,
  language = "json",
  className,
}) => {
  const lines = highlight(code, language);

  return (
    <div className={cn("overflow-x-auto font-mono text-xs leading-relaxed", className)}>
      <div className="table w-full border-collapse">
        {lines.map((tokens, i) => (
          <CodeLine key={i} number={i + 1} tokens={tokens} />
        ))}
      </div>
    </div>
  );
};
