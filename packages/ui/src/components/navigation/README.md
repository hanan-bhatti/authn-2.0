# Navigation Components (`@authn/ui/navigation`)

Navigation shell, sidebars, breadcrumbs, tabs, dropdown menus, and pagination primitives following the Resend **Black Velvet & Hairline Graphite** design system (`DESIGN.md`).

## Components Included

### 1. `Navbar`
Top header navigation bar with brand mark, tenant selector slot, and user profile slot.

```tsx
import { Navbar } from "@authn/ui";

<Navbar brandName="Authn Console" />
```

### 2. `Sidebar`
Dashboard side menu with collapsable groups, active route indicator, and footer.

```tsx
import { Sidebar } from "@authn/ui";

<Sidebar
  groups={[
    {
      title: "Core",
      items: [{ id: "users", label: "Users", isActive: true }],
    },
  ]}
/>
```

### 3. `Breadcrumb`
Path hierarchy trail with vector SVG chevrons.

```tsx
import { Breadcrumb } from "@authn/ui";

<Breadcrumb items={[{ label: "Dashboard", href: "/" }, { label: "Users", isCurrent: true }]} />
```

### 4. `Tabs` & `Pagination`
Text tabs with active bottom hairline indicator and table page switcher.

```tsx
import { Tabs, Pagination } from "@authn/ui";

<Tabs tabs={[{ id: "all", label: "All Users" }]} activeId="all" onChange={() => {}} />
<Pagination currentPage={1} totalPages={5} onPageChange={() => {}} />
```
