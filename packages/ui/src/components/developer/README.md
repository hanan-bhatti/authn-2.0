# Developer Components (`@authn/ui/developer`)

Developer-facing code containers, JSON syntax highlighters, and security key tools following the **Authn Product Design** system (`DESIGN.md`).

## Components Included

### 1. `SyntaxHighlighter`
JSON tokenizer. Keys are muted, string values green, booleans blue, `null` yellow and numbers orange — red stays reserved for genuine failure so an error surface beside a payload is still the alarming one. Output is React nodes, never an HTML string, because a response field is allowed to contain angle brackets.

```tsx
import { SyntaxHighlighter } from "@authn/ui";

<SyntaxHighlighter code={`{ "tenant_id": "tn_7f92a40b" }`} language="json" />
```

### 2. `CodeBlock`
Monospaced code viewer with line numbers and one-click copy feedback.

```tsx
import { CodeBlock } from "@authn/ui";

<CodeBlock title="authn.config.ts" code={`export default { tenantId: "tn_7f92a40b" };`} language="javascript" />
```

### 3. `TerminalWindow`
Dark terminal window container with traffic-light dots.

```tsx
import { TerminalWindow } from "@authn/ui";

<TerminalWindow title="authn-cli" output="pnpm dev --filter web-console" />
```

### 4. `PayloadViewer`
JSON tree payload inspector for audit logs & webhooks.

```tsx
import { PayloadViewer } from "@authn/ui";

<PayloadViewer payload={{ event: "user.created", user_id: "usr_9f82a" }} />
```

### 5. `SecretKeyInput`
Masked `sk_live_...` API key component with reveal toggle & copy action.

```tsx
import { SecretKeyInput } from "@authn/ui";

<SecretKeyInput value="sk_live_9f82a40b7c12e59" label="Publishable Secret Key" />
```
