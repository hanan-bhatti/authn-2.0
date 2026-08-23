# Inputs Components (`@authn/ui/inputs`)

Form input primitives built for the **Authn Product Design** system (`DESIGN.md`).

## Components Included

### 1. `Input`
Standard text, email, password, and monospaced token input fields. 8px radius, card-surface fill so the field reads as an inset well before focus, and `aria-invalid` wired to `isInvalid`.

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
Native `<select>` with the chrome hidden and a custom SVG chevron drawn over it, so keyboard and mobile pickers behave exactly as the platform expects.

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
