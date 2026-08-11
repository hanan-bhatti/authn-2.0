# `@authn/ui` — Resend Design System UI Component Package

Production-grade, accessible React component library for the **Authn Platform** adhering strictly to the Resend **Black Velvet & Iris Violet Neon** design specification (`DESIGN.md`).

## Design Tokens Summary (`DESIGN.md`)

- **Canvas Surface:** Void Black `#000000`
- **Layer Separation:** 1px Graphite Hairline borders (`#292d30`). Zero drop shadows.
- **Typography:** `Inter` for prose/UI, `JetBrains Mono` / `Commit Mono` for code, keys, IDs, and badges.
- **Brand Accent:** Iris Violet (`#9281f7`) exclusively for strings, developer tokens, tags, and syntax highlighting.
- **Buttons:** Ghost on Black (transparent fill, 1px `#292d30` border, `#ffffff` text, 6px radius, hover glow).
- **Radii Scale:** Strict two-tier — `6px` for controls (buttons, inputs, badges), `16px` for containers (cards, modals, terminal windows).

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
      <Badge variant="violet">v1.0.0</Badge>
      <Input placeholder="Enter work email" />
      <Button variant="ghost">Continue &rarr;</Button>
    </Card>
  );
}
```
