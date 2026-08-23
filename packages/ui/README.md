# `@authn/ui` — Authn Design System Component Package

Production-grade, accessible React component library for the **Authn Platform** adhering strictly to the **Authn Product Design** specification (`DESIGN.md`).

## Design Tokens Summary (`DESIGN.md`)

- **Canvas Surface:** true black `#000000` — never near-black.
- **Layer Separation:** 1px borders made from translucent white (`hairline` 6%, `hairline-strong` 14%). Cards and code wells carry no drop shadow.
- **Typography:** `Domaine Display` for oversized serif headlines, `Inter` for prose and UI, `ABC Favorit Mono` for code, keys, IDs, and badges.
- **Brand Accent:** white. `primary` (`#fcfdff`) is the only solid bright surface in the system; the six `accent-*` tokens are inline highlights and atmospheric glows, never fills.
- **Buttons:** ghost on black by default (transparent fill, hairline border, ink text, 8px radius). `primary` is a white rectangle with black text — at most one per viewport.
- **Radii Scale:** `4px` xs, `6px` sm, `8px` md for controls, `12px` lg for containers, `16px` xl, plus `full`.

## Component Categories

1. **`actions/`**: `Button`, `ButtonGroup`, `IconButton`, `CopyButton`
2. **`inputs/`**: `Input`, `InputOTP`, `Textarea`, `Select`, `Checkbox`, `Switch`, `RadioGroup`, `Label`, `FormField`
3. **`display/`**: `Chevron`, `Badge`, `StatusDot`, `Avatar`, `Kbd`, `Tooltip`, `StatCard`, `Table`, `DataTable`
4. **`developer/`**: `SyntaxHighlighter`, `CodeBlock`, `TerminalWindow`, `PayloadViewer`, `SecretKeyInput`
5. **`navigation/`**: `Navbar`, `Sidebar`, `Breadcrumb`, `Tabs`, `Pagination`, `DropdownMenu`
6. **`overlays/`**: `Dialog`, `Sheet`, `CommandMenu`, `Popover`, `Toast`, `Skeleton`, `EmptyState`

## Quick Start

```tsx
import { Button, Input, Card, Badge, StatusDot } from "@authn/ui";
import "@authn/ui/styles/globals.css";

export function App() {
  return (
    <Card className="p-6">
      <StatusDot status="active" pulse label="System Online" />
      <Badge variant="blue">v1.0.0</Badge>
      <Input placeholder="Enter work email" />
      <Button variant="ghost">Continue &rarr;</Button>
    </Card>
  );
}
```
