# Authn Platform — UI Component Architecture & Design System Guide

> **Theme:** Black Velvet with Iris Violet Neon (Resend Specification)  
> **Package:** `@authn/ui` (`packages/ui`)  
> **Styling Engine:** Tailwind CSS v4 (`packages/ui/src/styles/globals.css`)

---

## 1. Executive Summary & Design System Foundations

The `@authn/ui` package is the core design system for all web interfaces in the **Authn Platform** ecosystem (`apps/web-console`, `apps/web-demo`, `apps/web-landing`). 

### Core Design Rules (`DESIGN.md`)

| Token Category | Rule & Value | Architectural Rationale |
|---|---|---|
| **Canvas Surface** | `#000000` (Void Black) | Pure black canvas full-bleed. Never off-black or dark gray tint for background. |
| **Layer Elevation** | `1px solid #292d30` (Graphite Hairline) | All layer separation is achieved via hairline borders against black. Drop shadows are strictly banned. |
| **Primary CTA** | Ghost on Black (`transparent`, 1px `#292d30`, `#ffffff` text) | Anti-decorative buttons. Hover shifts border to white with 150ms ease-out. |
| **Brand Accent** | `#9281f7` (Iris Violet) | Exclusively used for developer identifiers, code strings (`<WebAuthn>`), and syntax highlighting. Never on action buttons. |
| **Control Radii** | `6px` (`--radius-control`) | Buttons, inputs, badges, switches, copy buttons, dropdowns. |
| **Container Radii** | `16px` (`--radius-card`) | Cards, modals, side-drawers, code terminal windows, stat panels. |

---

## 2. Master Component Catalog

```
packages/ui/src/components/
├── actions/
│   ├── Button.tsx           (Ghost, Primary, Secondary, Destructive, Loading)
│   ├── ButtonGroup.tsx      (Segmented joined buttons)
│   ├── IconButton.tsx       (Compact vector action button)
│   └── CopyButton.tsx       (One-click clipboard copy with green checkmark feedback)
├── inputs/
│   ├── Input.tsx            (Text, Email, Password, Search, Monospaced API key)
│   ├── InputOTP.tsx         (6-digit segmented 2FA / TOTP verification)
│   ├── Textarea.tsx         (Monospaced multi-line input for payloads/XML)
│   ├── Select.tsx           (Custom hairline dropdown with SVG arrow)
│   ├── Checkbox.tsx         (Custom checkbox with SVG checkmark)
│   ├── Switch.tsx           (Accessible toggle switch)
│   ├── RadioGroup.tsx       (Radio option selector with hairline borders)
│   ├── Label.tsx            (Form label with monospaced tag support)
│   └── FormField.tsx        (Field wrapper with validation error text)
├── display/
│   ├── Chevron.tsx          (Directional SVG chevron: up, down, left, right)
│   ├── Badge.tsx            (Monospaced status badge: violet, green, red, amber, gray)
│   ├── StatusDot.tsx        (Live pulse indicator dot)
│   ├── Avatar.tsx           (User avatar with initials fallback)
│   ├── Kbd.tsx              (Keyboard shortcut indicator e.g. ⌘K)
│   ├── Tooltip.tsx          (Hover metadata tooltip)
│   ├── StatCard.tsx         (Dashboard counter card with trend indicators)
│   ├── Table.tsx            (Raw table primitives: Header, Body, Row, Head, Cell)
│   └── DataTable.tsx        (High-density table with selection & sorting)
├── developer/
│   ├── SyntaxHighlighter.tsx (JSON & code formatter with Iris Violet tokens)
│   ├── CodeBlock.tsx        (Code window with line numbers & copy action)
│   ├── TerminalWindow.tsx   (Dark terminal frame with traffic-light dots)
│   ├── PayloadViewer.tsx    (Collapsible JSON tree inspector)
│   └── SecretKeyInput.tsx   (Masked sk_live_... with reveal toggle & copy)
├── navigation/
│   ├── Navbar.tsx           (Top header shell with tenant & user slots)
│   ├── Sidebar.tsx          (Dashboard side menu with active route indicator)
│   ├── Breadcrumb.tsx       (Path hierarchy trail with SVG chevrons)
│   ├── Tabs.tsx             (Text tabs with active bottom hairline border)
│   ├── Pagination.tsx       (Table page navigator with SVG prev/next controls)
│   └── DropdownMenu.tsx     (Context menu for table row actions & user profile)
└── overlays/
    ├── Dialog.tsx           (Modal dialog with backdrop blur & 16px radius)
    ├── Sheet.tsx            (Slide-over side drawer for audit events)
    ├── CommandMenu.tsx      (Global ⌘K command palette modal)
    ├── Popover.tsx          (Floating popover panel)
    ├── Toast.tsx            (System notification alert toast)
    ├── Skeleton.tsx         (Shimmer loading placeholder)
    └── EmptyState.tsx       (Clean empty state graphic with action CTA)
```

---

## 3. Integration Code Examples

### Building a Production Admin Dashboard View
```tsx
import React, { useState } from "react";
import {
  Navbar,
  Sidebar,
  StatCard,
  DataTable,
  Badge,
  StatusDot,
  Button,
  SecretKeyInput,
} from "@authn/ui";

export function AdminDashboardView() {
  const [selectedUsers, setSelectedUsers] = useState<string[]>([]);

  return (
    <div className="flex flex-col h-screen bg-[#000000] text-white">
      <Navbar
        brandName="Authn Platform"
        statusBadge={<StatusDot status="active" pulse label="Engine Online" />}
      />

      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          groups={[
            {
              title: "Management",
              items: [
                { id: "overview", label: "Overview" },
                { id: "users", label: "Users & RBAC", isActive: true },
                { id: "webhooks", label: "Webhooks" },
              ],
            },
          ]}
        />

        <main className="flex-1 p-8 overflow-y-auto flex flex-col gap-6">
          <div className="grid grid-cols-3 gap-4">
            <StatCard title="Total Users" value="12,482" trend="+8.2%" trendType="positive" />
            <StatCard title="WebAuthn Passkeys" value="4,102" trend="+24.1%" trendType="positive" />
            <StatCard title="API Traffic" value="1.2M" trend="-0.4%" trendType="neutral" />
          </div>

          <SecretKeyInput value="sk_live_9f82a40b7c12e59a114" label="Production Secret Key" />

          <DataTable
            selectable
            selectedKeys={selectedUsers}
            onSelectionChange={setSelectedUsers}
            keyExtractor={(u) => u.id}
            data={[
              { id: "usr_01", email: "alex@acme.com", role: "tenant_admin", status: "active" },
              { id: "usr_02", email: "sam@acme.com", role: "member", status: "active" },
            ]}
            columns={[
              { key: "id", header: "User ID", cell: (r) => r.id, isMonospace: true },
              { key: "email", header: "Email", cell: (r) => r.email },
              { key: "role", header: "Role", cell: (r) => <Badge variant="violet">{r.role}</Badge> },
              { key: "status", header: "Status", cell: (r) => <StatusDot status="active" label={r.status} /> },
            ]}
          />
        </main>
      </div>
    </div>
  );
}
```

---

## 4. Verification & Testing Instructions

To verify type safety and build output for `@authn/ui`:

```bash
# 1. Type check
cd packages/ui
pnpm run lint

# 2. Bundle with tsup
pnpm run build
```
