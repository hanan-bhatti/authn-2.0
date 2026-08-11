# Inputs Components (`@authn/ui/inputs`)

Form input primitives built for the Resend **Black Velvet & Hairline Graphite** design system (`DESIGN.md`).

## Components Included

### 1. `Input`
Standard text, email, password, and monospaced token input fields with 6px border-radius and `#000000` canvas background.

```tsx
import { Input } from "@authn/ui";

<Input type="email" placeholder="name@company.com" />
<Input isMonospace placeholder="pk_live_9f82a40b7c12" />
```

### 2. `InputOTP`
6-digit segmented input box for 2FA / TOTP authentication codes.

```tsx
import { InputOTP } from "@authn/ui";

<InputOTP length={6} onComplete={(code) => console.log(code)} />
```

### 3. `Textarea`
Monospaced multi-line input for metadata, SAML XML, and webhook payloads.

```tsx
import { Textarea } from "@authn/ui";

<Textarea isMonospace rows={4} placeholder="Paste SAML Metadata XML..." />
```

### 4. `Select`
Custom searchable dropdown with 1px hairline border and custom SVG arrow.

```tsx
import { Select } from "@authn/ui";

<Select options={[{ value: "admin", label: "Admin" }, { value: "member", label: "Member" }]} />
```

### 5. `Checkbox` & `Switch`
Accessible boolean toggle controls.

```tsx
import { Checkbox, Switch } from "@authn/ui";

<Checkbox label="Remember this device" />
<Switch label="Require 2FA for all admins" checked={is2FAEnforced} />
```

### 6. `FormField` & `Label`
Form control wrapper with error messages and monospaced tag support.

```tsx
import { FormField, Input } from "@authn/ui";

<FormField label="Secret Key" isRequired monospaceTag="sk_live_..." error="Key invalid">
  <Input isMonospace placeholder="sk_live_..." />
</FormField>
```
