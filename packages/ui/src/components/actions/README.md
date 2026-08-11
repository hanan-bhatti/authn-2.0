# Actions Components (`@authn/ui/actions`)

Action components provide interactive trigger elements following the Resend **Black Velvet & Hairline Graphite** design system (`DESIGN.md`).

## Components Included

### 1. `Button`
The foundational trigger element with Ghost-on-Black default styling, 6px radius, and hairline borders.

```tsx
import { Button } from "@authn/ui";

// Ghost Default (Signature Resend style)
<Button variant="ghost">Continue with Email</Button>

// Primary Filled (Signal Blue)
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
Compact SVG icon action button.

```tsx
import { IconButton } from "@authn/ui";

<IconButton icon={<FilterIcon />} label="Filter results" />
```

### 4. `CopyButton`
One-click copy-to-clipboard button with monospaced text and green pulse checkmark feedback.

```tsx
import { CopyButton } from "@authn/ui";

<CopyButton value="sk_live_9f82a40b7c12" label="Copy Key" />
```
