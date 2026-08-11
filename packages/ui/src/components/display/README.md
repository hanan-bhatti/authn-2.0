# Display Components (`@authn/ui/display`)

Data display and visual hierarchy primitives following the Resend **Black Velvet & Hairline Graphite** design system (`DESIGN.md`).

## Components Included

### 1. `Chevron`
Direction-aware vector chevron SVG supporting `up`, `down`, `left`, `right` and animation transitions.

```tsx
import { Chevron } from "@authn/ui";

<Chevron direction="down" size="sm" />
```

### 2. `Badge`
Monospaced terminal-style status badges with hairline borders.

```tsx
import { Badge } from "@authn/ui";

<Badge variant="violet">webauthn_passkey</Badge>
<Badge variant="green" dot>Active</Badge>
<Badge variant="red">Locked</Badge>
```

### 3. `StatusDot`
Live status dot indicator with optional CSS pulse ping.

```tsx
import { StatusDot } from "@authn/ui";

<StatusDot status="active" pulse label="System Ready" />
```

### 4. `StatCard`
Dashboard counter card with 16px radius and hairline graphite border.

```tsx
import { StatCard } from "@authn/ui";

<StatCard title="Active Users" value="14,892" trend="+12.4%" trendType="positive" />
```

### 5. `DataTable` & `Table`
High-density data table primitives with row selection, hairline dividers, and monospaced cell formatting.

```tsx
import { DataTable } from "@authn/ui";

<DataTable
  columns={[
    { key: "id", header: "User ID", cell: (r) => r.id, isMonospace: true },
    { key: "email", header: "Email", cell: (r) => r.email },
  ]}
  data={[{ id: "usr_9f82a", email: "alice@company.com" }]}
  keyExtractor={(r) => r.id}
/>
```
