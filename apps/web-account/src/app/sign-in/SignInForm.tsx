"use client";

/**
 * Authn Platform — Sign-in form
 * File: apps/web-account/src/app/sign-in/SignInForm.tsx
 */

import {
  useCallback,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { useRouter } from "next/navigation";
import { Button, FormField, Input, Skeleton, Toast } from "@authn/ui";
import { useAppConfig, useMagicLink, useSignIn } from "@authn/react";
import type { AuthnError, AuthnUser, TwoFactorMethod } from "@authn/js";
import { presentSignInError, type FieldName } from "@/lib/authError";
import { SecondFactorPanel } from "./SecondFactorPanel";

/**
 * What the form is asking for.
 *
 * The single visible text field means something different in each mode: a
 * password names an account, and either an address or a handle does that equally
 * well, while a link has to be delivered somewhere and a handle names no mailbox.
 * So the mode decides the label, the validation and the request.
 */
type Mode = "password" | "link";

/**
 * Where the attempt stopped, when it stopped somewhere other than signed in.
 */
type Outcome =
  | { kind: "linkSent"; email: string }
  | {
      kind: "secondFactor";
      methods: readonly TwoFactorMethod[];
      mfaToken: string;
      user: AuthnUser;
    };

interface FieldMessage {
  field: FieldName;
  message: string;
}

interface ToastMessage {
  type: "error" | "info";
  title: string;
  description?: string;
}

export function SignInForm(): ReactNode {
  const { config, isLoading: isConfigLoading, error: configError, reload } = useAppConfig();
  const { signIn, isLoading: isSigningIn } = useSignIn();
  const { sendMagicLink, isLoading: isSendingLink } = useMagicLink();

  const [mode, setMode] = useState<Mode>("password");
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");

  const [fieldMessage, setFieldMessage] = useState<FieldMessage | null>(null);
  const [formMessage, setFormMessage] = useState<string | null>(null);
  const [toast, setToast] = useState<ToastMessage | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);

  const router = useRouter();
  const identifierRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  const focusField = useCallback((field: FieldName) => {
    const target = field === "password" ? passwordRef.current : identifierRef.current;
    target?.focus();
  }, []);

  /**
   * Routes one refusal to one place, and moves focus there when it is a field.
   *
   * Without the focus move the message is only visible: a keyboard user is left
   * on the submit button and a screen-reader user hears nothing, because an
   * `aria-describedby` target announces when the control is read, not when its
   * text changes. A form-level message is focused too, for the same reason —
   * wrong credentials is the common case and it belongs to no field.
   */
  const present = useCallback(
    (error: AuthnError) => {
      const presented = presentSignInError(error);

      if ("toast" in presented) {
        setToast({ type: "error", ...presented.toast });
        return;
      }
      if ("form" in presented) {
        setFormMessage(presented.form);
        focusField("password");
        return;
      }

      setFieldMessage({ field: presented.field, message: presented.message });
      focusField(presented.field);
    },
    [focusField],
  );

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();

      setFieldMessage(null);
      setFormMessage(null);
      setToast(null);

      const trimmed = identifier.trim();
      if (trimmed === "") {
        setFieldMessage({
          field: "identifier",
          message: mode === "link" ? "Enter your email address." : "Enter your email or username.",
        });
        focusField("identifier");
        return;
      }

      if (mode === "link") {
        // A handle is a perfectly good way to name an account and a useless way to
        // address an email, so this is refused here rather than sent: the engine
        // would answer the same generic "if an account exists" message it answers
        // for an unknown address, and the user would be left waiting for a link
        // that was never addressed to anywhere.
        if (!trimmed.includes("@")) {
          setFieldMessage({
            field: "identifier",
            message: "A sign-in link needs your email address, not your username.",
          });
          focusField("identifier");
          return;
        }

        const result = await sendMagicLink({ email: trimmed });
        if (!result.ok) {
          present(result.error);
          return;
        }
        setOutcome({ kind: "linkSent", email: trimmed });
        return;
      }

      if (password === "") {
        setFieldMessage({ field: "password", message: "Enter your password." });
        focusField("password");
        return;
      }

      const result = await signIn({ identifier: trimmed, password });
      if (!result.ok) {
        present(result.error);
        return;
      }

      if (result.mfaRequired) {
        setOutcome({
          kind: "secondFactor",
          methods: result.methods,
          mfaToken: result.mfaToken,
          user: result.user,
        });
        return;
      }

      // `replace` rather than `push`: going back to a sign-in form you have
      // already used is never what the back button was for, and the guard on
      // `/account` would only bounce a signed-in visitor straight back here.
      router.replace("/account");
    },
    [identifier, password, mode, focusField, present, router, sendMagicLink, signIn],
  );

  if (isConfigLoading || (!config && !configError)) return <FormSkeleton />;

  if (!config) {
    return (
      <div className="flex flex-col gap-lg">
        <p className="text-body-sm text-charcoal">
          Sign-in could not be loaded. This is usually temporary.
        </p>
        <Button variant="ghost" onClick={() => void reload()}>
          Try again
        </Button>
      </div>
    );
  }

  if (outcome?.kind === "secondFactor") {
    return (
      <SecondFactorPanel
        mfaToken={outcome.mfaToken}
        methods={outcome.methods}
        user={outcome.user}
        // The challenge token cannot be renewed, so starting again means
        // presenting the password again. The identifier is kept and the password
        // cleared: the address was not what expired.
        onRestart={() => {
          setOutcome(null);
          setPassword("");
          setFieldMessage(null);
          setFormMessage(null);
          setToast(null);
        }}
      />
    );
  }

  if (outcome) return <OutcomePanel outcome={outcome} />;

  const { signInMethods } = config;
  const canUsePassword = signInMethods.password;
  const canUseMagicLink = signInMethods.magicLink;

  if (!canUsePassword && !canUseMagicLink) {
    return (
      <p className="text-body-sm text-charcoal">
        This application has no sign-in method enabled. Its owner needs to turn one on.
      </p>
    );
  }

  // A tenant with only one method gets that method, whatever the toggle last
  // said: the mode is a user preference among what is offered, not a way to reach
  // something that is switched off.
  const isPasswordMode = mode === "password" ? canUsePassword : !canUseMagicLink;
  const isSubmitting = isPasswordMode ? isSigningIn : isSendingLink;

  return (
    <>
      {/* The browser's own validation is off so that a refusal appears in one
          place. Left on, a native bubble fires first, says something this page
          did not write, and disappears before a screen reader reaches it —
          while the inline message it preempted is still sitting there. */}
      <form noValidate onSubmit={handleSubmit} className="flex flex-col gap-lg">
        <FormField
          label={isPasswordMode ? "Email or username" : "Email"}
          isRequired
          error={fieldMessage?.field === "identifier" ? fieldMessage.message : undefined}
        >
          <Input
            ref={identifierRef}
            // Deliberately `text` even for the address: `type="email"` brings the
            // browser's own format check, which refuses a username on a field
            // that accepts one.
            type={isPasswordMode ? "text" : "email"}
            name="identifier"
            value={identifier}
            required
            // The spec's token for "the thing that names the account", which is
            // what a password manager needs to pair with the password below.
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            placeholder={isPasswordMode ? "you@company.com or alexsmith" : "you@company.com"}
            onChange={(e) => {
              setIdentifier(e.target.value);
              if (fieldMessage?.field === "identifier") setFieldMessage(null);
              if (formMessage) setFormMessage(null);
            }}
          />
        </FormField>

        {isPasswordMode && (
          <FormField
            label="Password"
            isRequired
            error={fieldMessage?.field === "password" ? fieldMessage.message : undefined}
          >
            <Input
              ref={passwordRef}
              type="password"
              name="password"
              value={password}
              required
              autoComplete="current-password"
              onChange={(e) => {
                setPassword(e.target.value);
                if (fieldMessage?.field === "password") setFieldMessage(null);
                if (formMessage) setFormMessage(null);
              }}
            />
          </FormField>
        )}

        {/* Announced rather than only shown. This is where wrong credentials
            land, and a message that appears silently is a message a screen-reader
            user does not get. */}
        {formMessage && (
          <p role="alert" className="text-caption text-accent-red">
            {formMessage}
          </p>
        )}

        <Button type="submit" variant="primary" isLoading={isSubmitting} className="w-full">
          {isPasswordMode ? "Sign in" : "Email me a sign-in link"}
        </Button>
      </form>

      {canUsePassword && canUseMagicLink && (
        <>
          <div className="my-lg h-px w-full bg-divider-soft" />

          {/* Doubles as the way past a forgotten password: a link signs the
              account holder in without one, and the password can be changed from
              security settings afterwards. It is a button rather than a link
              because there is no separate page to send them to. */}
          <Button
            variant="ghost"
            className="w-full"
            onClick={() => {
              setMode((previous) => (previous === "password" ? "link" : "password"));
              setFieldMessage(null);
              setFormMessage(null);
              setToast(null);
            }}
          >
            {isPasswordMode ? "Forgot your password? Email me a link" : "Use a password instead"}
          </Button>
        </>
      )}

      {toast && (
        <div className="fixed inset-x-lg bottom-lg z-50 flex justify-center sm:justify-end">
          <Toast
            type={toast.type}
            title={toast.title}
            description={toast.description}
            onClose={() => setToast(null)}
          />
        </div>
      )}
    </>
  );
}

function OutcomePanel({ outcome }: { outcome: Extract<Outcome, { kind: "linkSent" }> }): ReactNode {
  return (
    <div className="flex flex-col gap-md">
      <h2 className="font-display text-heading-sm text-ink">Check your email</h2>
      <p className="text-body-sm text-charcoal">
        A sign-in link is on its way to{" "}
        <span className="font-mono text-ink">{outcome.email}</span>. Opening it signs you in.
      </p>
      <p className="text-caption text-mute">
        The link is single-use and expires shortly.
      </p>
    </div>
  );
}

function FormSkeleton(): ReactNode {
  // Matches the real form's shape rather than showing a spinner, so the card
  // does not resize the moment the configuration lands. The bars themselves are
  // hidden from the accessibility tree — there is no text in them to read — and
  // the one thing worth announcing is announced once, as prose.
  return (
    <div className="flex flex-col gap-lg">
      <span role="status" className="sr-only">
        Loading the sign-in form.
      </span>

      <div aria-hidden="true" className="flex flex-col gap-lg">
        <Skeleton variant="text" className="w-28" />
        <Skeleton variant="control" />
        <Skeleton variant="text" className="w-20" />
        <Skeleton variant="control" />
        <Skeleton variant="control" />
      </div>
    </div>
  );
}
