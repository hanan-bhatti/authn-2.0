# Overlays Components (`@authn/ui/overlays`)

Modal dialogs, slide-over sheets, command palette (`⌘K`), toasts, popovers, and loading skeletons following the Resend **Black Velvet & Hairline Graphite** design system (`DESIGN.md`).

## Components Included

### 1. `Dialog` & `Sheet`
Modals and slide-over drawers with `#000000f2` backdrop blur (25px) and 16px radius containers.

```tsx
import { Dialog, Sheet } from "@authn/ui";

<Dialog isOpen={isOpen} onClose={() => setIsOpen(false)} title="Create Webhook">
  <p>Configure event triggers</p>
</Dialog>

<Sheet isOpen={isDrawerOpen} onClose={() => setIsDrawerOpen(false)} title="Inspect Payload">
  <p>Webhook details</p>
</Sheet>
```

### 2. `CommandMenu`
Global `⌘K` command palette modal.

```tsx
import { CommandMenu } from "@authn/ui";

<CommandMenu
  isOpen={isOpen}
  onClose={() => setIsOpen(false)}
  items={[{ id: "users", label: "Go to Users", shortcut: "⌘U" }]}
/>
```

### 3. `Toast` & `Skeleton` & `EmptyState`
System notifications, data shimmer placeholders, and clean empty state illustrations.

```tsx
import { Toast, Skeleton, EmptyState } from "@authn/ui";

<Toast type="success" title="Webhook Created" description="Secret key generated" />
<Skeleton variant="card" />
<EmptyState title="No API Keys Found" description="Create a secret key to get started" />
```
