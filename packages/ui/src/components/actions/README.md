# Actions Components (`@authn/ui/actions`)

Action components provide interactive trigger elements following the **Authn Product Design** system (`DESIGN.md`).

## Components Included

### 1. `Button`
The foundational trigger element with Ghost-on-Black default styling, 8px radius, and hairline borders.

```tsx
import { Button } from "@authn/ui";

// Ghost default — the everyday action
<Button variant="ghost">Continue with Email</Button>

// Primary — a white rectangle on black; at most one per viewport
<Button variant="primary">Create Tenant</Button>

// Destructive
<Button variant="destructive">Revoke API Key</Button>

// Loading State
<Button isLoading>Authenticating...</Button>
```

### 2. `ButtonGroup`
Container for segmenting joined buttons.

```tsx
import { ButtonGroup, Button } from "@authn/ui";

<ButtonGroup>
  <Button variant="ghost">Overview</Button>
  <Button variant="outline">Analytics</Button>
</ButtonGroup>
```

### 3. `IconButton`
Compact SVG icon action button. Shares `Button`'s `ghost` / `secondary` / `outline` variants.

```tsx
import { IconButton } from "@authn/ui";

<IconButton icon={<FilterIcon />} label="Filter results" />
<IconButton icon={<TrashIcon />} label="Delete" variant="outline" />
```

### 4. `CopyButton`
One-click copy-to-clipboard button with monospaced text and green pulse checkmark feedback.

```tsx
import { CopyButton } from "@authn/ui";

<CopyButton value="sk_live_9f82a40b7c12" label="Copy Key" />
```
