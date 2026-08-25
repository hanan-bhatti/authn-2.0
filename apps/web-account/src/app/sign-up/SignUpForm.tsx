"use client";

/**
 * Authn Platform — Sign-up form
 * File: apps/web-account/src/app/sign-up/SignUpForm.tsx
 */

import {
  useCallback,
  useId,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { useRouter } from "next/navigation";
import { Button, FormField, Input, Skeleton, Toast } from "@authn/ui";
import {
  useAppConfig,
  useMagicLink,
  useSignUp,
  useUsernameAvailability,
  type UsernameStatus,
} from "@authn/react";
import type { AuthnError } from "@authn/js";
import { USERNAME_MIN_LENGTH, USERNAME_RULE_HINT } from "@authn/js";
import { PasswordCriteria } from "@/components/PasswordCriteria";
import { presentSignUpError, type FieldName } from "@/lib/authError";
import { applyServerCriteria, evaluatePassword } from "@/lib/password";
import { byteLength } from "@/lib/text";

/** The engine's own ceiling on the name column, counted in bytes as it counts it. */
const MAX_NAME_BYTES = 255;

/**
 * How the attempt ended, once it has.
 *
 * The two paths finish in genuinely different states — one has a session and one
 * has an unread email — so they are separate arms rather than one shape with
 * half its fields unset.
 */
type Outcome =
  | { kind: "created"; email: string; isVerified: boolean; missingCriteria?: string[] }
  | { kind: "linkSent"; email: string };

interface FieldMessage {
  field: FieldName;
  message: string;
  /** Free alternatives the engine sent with a taken handle. */
  suggestions?: string[];
}

/** A toast's colour and its screen-reader urgency both come from this. */
interface ToastMessage {
  type: "error" | "info";
  title: string;
  description?: string;
}

export function SignUpForm(): ReactNode {
  const { config, isLoading: isConfigLoading, error: configError, reload } = useAppConfig();
  const { signUp, isLoading: isSigningUp } = useSignUp();
  const { sendMagicLink, isLoading: isSendingLink } = useMagicLink();

  const [usePassword, setUsePassword] = useState(true);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [hasTypedPassword, setHasTypedPassword] = useState(false);
  const [hasLeftHandle, setHasLeftHandle] = useState(false);

  const [fieldMessage, setFieldMessage] = useState<FieldMessage | null>(null);
  const [serverMissing, setServerMissing] = useState<readonly string[]>([]);
  const [toast, setToast] = useState<ToastMessage | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);

  const router = useRouter();
  const criteriaId = useId();
  const handleStatusId = useId();
  const emailRef = useRef<HTMLInputElement>(null);
  const nameRef = useRef<HTMLInputElement>(null);
  const usernameRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  // A handle is only asked for in password mode: the magic-link path posts to an
  // endpoint that provisions the account itself and has nowhere to put one.
  const handle = useUsernameAvailability(username, {
    name,
    enabled: usePassword && !outcome,
  });

  const trimmedHandle = username.trim();

  /**
   * Holds a shape complaint back until the value could plausibly satisfy the
   * rules, or until the field has been left.
   *
   * The hook answers a shape problem on the first keystroke, which is right for
   * the hook and wrong for the field: "must be at least 3 characters" under a
   * one-character handle marks it red for the act of starting to fill it in. The
   * rule the user has not finished typing is already stated as the hint.
   */
  const isHandleJudged =
    hasLeftHandle || [...trimmedHandle].length >= USERNAME_MIN_LENGTH;

  const handleError =
    isHandleJudged && (handle.status === "invalid" || handle.status === "unavailable")
      ? (handle.message ?? "Choose a different username.")
      : undefined;

  const localCriteria = useMemo(
    () => (config ? evaluatePassword(password, config.passwordRules) : []),
    [password, config],
  );

  // A refusal names criteria, and the engine outranks the local mirror on them
  // until the user edits the field — at which point the local verdict is the
  // only one describing what is actually in the box.
  const { criteria, unrecognised } = useMemo(
    () =>
      serverMissing.length > 0
        ? applyServerCriteria(localCriteria, serverMissing)
        : { criteria: localCriteria, unrecognised: [] as string[] },
    [localCriteria, serverMissing],
  );

  const focusField = useCallback((field: FieldName) => {
    const target =
      field === "email"
        ? emailRef.current
        : field === "password"
          ? passwordRef.current
          : field === "username"
            ? usernameRef.current
            : nameRef.current;
    target?.focus();
  }, []);

  /**
   * Routes one refusal to one place, and moves focus there when it is a field.
   *
   * Without the focus move the message is only visible: a keyboard user is left
   * on the submit button and a screen-reader user hears nothing, because an
   * `aria-describedby` target announces when the control is read, not when its
   * text changes.
   */
  const present = useCallback(
    (error: AuthnError) => {
      const presented = presentSignUpError(error);

      if ("toast" in presented) {
        setToast({ type: "error", ...presented.toast });
        return;
      }

      setFieldMessage({
        field: presented.field,
        message: presented.message,
        suggestions: presented.suggestions,
      });
      if (presented.missingCriteria) setServerMissing(presented.missingCriteria);
      focusField(presented.field);
    },
    [focusField],
  );

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!config) return;

      setFieldMessage(null);
      setServerMissing([]);
      setToast(null);

      const trimmedName = name.trim();
      if (byteLength(trimmedName) > MAX_NAME_BYTES) {
        setFieldMessage({ field: "name", message: `Name must be ${MAX_NAME_BYTES} characters or fewer.` });
        focusField("name");
        return;
      }

      if (!usePassword) {
        const result = await sendMagicLink({ email, name: trimmedName || undefined });
        if (!result.ok) {
          present(result.error);
          return;
        }
        setOutcome({ kind: "linkSent", email });
        return;
      }

      // A refusal the probe already reported is refused here rather than sent: the
      // engine would answer the same thing after hashing a password for an account
      // it was never going to create. A handle still being checked is sent anyway —
      // the probe is guidance and the server is the authority, so waiting on it
      // would make the button feel stuck for no gain.
      if (
        trimmedHandle !== "" &&
        (handle.status === "invalid" || handle.status === "unavailable")
      ) {
        setFieldMessage({
          field: "username",
          message: handle.message ?? "Choose a different username.",
          suggestions: handle.suggestions,
        });
        focusField("username");
        return;
      }

      const result = await signUp({
        email,
        password,
        name: trimmedName || undefined,
        username: trimmedHandle || undefined,
      });
      if (!result.ok) {
        present(result.error);
        return;
      }

      if (result.mfaRequired) {
        // Not a path sign-up can actually take: a just-created account holds no
        // second factor, and an address that already holds one is refused as a
        // conflict before any challenge is issued. Answered anyway because the
        // result type permits it, and the alternative is reading a session that
        // this arm documents as absent.
        setToast({
          type: "info",
          title: "Account created",
          description: "Sign in to finish setting it up.",
        });
        return;
      }

      setOutcome({
        kind: "created",
        email: result.session.user.email,
        isVerified: result.session.user.emailVerified,
        missingCriteria: result.policyWarning?.missingCriteria,
      });
    },
    [config, email, name, trimmedHandle, password, usePassword, handle, focusField, present, sendMagicLink, signUp],
  );

  if (isConfigLoading || (!config && !configError)) return <FormSkeleton />;

  if (!config) {
    return (
      <div className="flex flex-col gap-lg">
        <p className="text-body-sm text-charcoal">
          Sign-up could not be loaded. This is usually temporary.
        </p>
        <Button variant="ghost" onClick={() => void reload()}>
          Try again
        </Button>
      </div>
    );
  }

  if (outcome) {
    return (
      <Confirmation
        outcome={outcome}
        onContinue={() => router.push("/")}
        // In hard mode an unverified account cannot use the session it was just
        // given, so offering a way in would hand the user a door that is locked
        // on the other side.
        isBlockedUntilVerified={
          outcome.kind === "created" &&
          !outcome.isVerified &&
          config.emailVerification.required &&
          config.emailVerification.mode === "hard"
        }
      />
    );
  }

  const { signInMethods } = config;
  const canUsePassword = signInMethods.password;
  const canUseMagicLink = signInMethods.magicLink;

  // Both are compiled-in capabilities the engine reports rather than assumes, so
  // a tenant with neither is a configuration to surface, not a form to render
  // half of.
  if (!canUsePassword && !canUseMagicLink) {
    return (
      <p className="text-body-sm text-charcoal">
        This application has no sign-up method enabled. Its owner needs to turn one on.
      </p>
    );
  }

  const isPasswordMode = usePassword && canUsePassword;
  const isSubmitting = isPasswordMode ? isSigningUp : isSendingLink;

  return (
    <>
      {/* The browser's own validation is off so that a refusal appears in one
          place. Left on, a native bubble fires first, says something this page
          did not write, and disappears before a screen reader reaches it —
          while the inline message it preempted is still sitting there. */}
      <form noValidate onSubmit={handleSubmit} className="flex flex-col gap-lg">
        <FormField
          label="Email"
          isRequired
          error={fieldMessage?.field === "email" ? fieldMessage.message : undefined}
        >
          <Input
            ref={emailRef}
            type="email"
            name="email"
            value={email}
            required
            autoComplete="email"
            autoCapitalize="none"
            spellCheck={false}
            placeholder="you@company.com"
            onChange={(e) => {
              setEmail(e.target.value);
              if (fieldMessage?.field === "email") setFieldMessage(null);
            }}
          />
        </FormField>

        <FormField
          label="Name"
          hint="Optional. Used to address you."
          error={fieldMessage?.field === "name" ? fieldMessage.message : undefined}
        >
          <Input
            ref={nameRef}
            type="text"
            name="name"
            value={name}
            autoComplete="name"
            placeholder="Alex Smith"
            onChange={(e) => {
              setName(e.target.value);
              if (fieldMessage?.field === "name") setFieldMessage(null);
            }}
          />
        </FormField>

        {isPasswordMode && (
          <div className="flex flex-col gap-sm">
            <FormField
              label="Username"
              hint={`Optional. ${USERNAME_RULE_HINT}.`}
              error={fieldMessage?.field === "username" ? fieldMessage.message : handleError}
            >
              <Input
                ref={usernameRef}
                type="text"
                name="username"
                value={username}
                isMonospace
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                placeholder="alexsmith"
                aria-describedby={handleStatusId}
                leftIcon={<span className="font-mono text-caption">@</span>}
                onBlur={() => setHasLeftHandle(true)}
                onChange={(e) => {
                  setUsername(e.target.value);
                  if (fieldMessage?.field === "username") setFieldMessage(null);
                }}
              />
            </FormField>

            <HandleStatus
              id={handleStatusId}
              status={handle.status}
              canonical={handle.canonical}
              typed={trimmedHandle}
            />

            {/* Whichever list is fresher. The submit-time one came from the engine
                a moment ago and describes the value in the box; the probe's is
                replaced on the next keystroke. */}
            <Suggestions
              options={fieldMessage?.suggestions ?? handle.suggestions}
              onPick={(pick) => {
                setUsername(pick);
                setFieldMessage(null);
                usernameRef.current?.focus();
              }}
            />
          </div>
        )}

        {isPasswordMode && (
          <div className="flex flex-col gap-sm">
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
                autoComplete="new-password"
                aria-describedby={criteriaId}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setHasTypedPassword(true);
                  // The server's verdict described the previous value. Keeping a
                  // row forced red after the user fixed it is the exact
                  // disagreement this list exists to prevent.
                  if (serverMissing.length > 0) setServerMissing([]);
                  if (fieldMessage?.field === "password") setFieldMessage(null);
                }}
              />
            </FormField>

            <PasswordCriteria id={criteriaId} criteria={criteria} isActive={hasTypedPassword} />

            {unrecognised.length > 0 && (
              <p className="text-caption text-accent-red">
                This password also breaks a rule this page cannot describe. Try a longer,
                more varied one.
              </p>
            )}

            {!config.passwordRules.enforced && (
              <p className="text-caption text-mute">
                These are recommendations — a password that misses them is still accepted.
              </p>
            )}
          </div>
        )}

        <Button type="submit" variant="primary" isLoading={isSubmitting} className="w-full">
          {isPasswordMode ? "Create account" : "Email me a sign-up link"}
        </Button>
      </form>

      {canUsePassword && canUseMagicLink && (
        <>
          <div className="my-lg h-px w-full bg-divider-soft" />
          <Button
            variant="ghost"
            className="w-full"
            onClick={() => {
              setUsePassword((previous) => !previous);
              setFieldMessage(null);
              setServerMissing([]);
              setToast(null);
            }}
          >
            {isPasswordMode ? "Use a sign-up link instead" : "Use a password instead"}
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

/**
 * The live verdict on the handle, as prose.
 *
 * Only the states the field itself cannot show land here. A refusal — bad shape,
 * already taken — is the field's `error`, and repeating it underneath would read
 * as two problems. What is left is the waiting state, the confirmation, and the
 * one case that is neither: a probe that could not reach the server, which must
 * not look like a refusal because the handle may well be free.
 *
 * Rendered even when it has nothing to say. The field points at this node with
 * `aria-describedby`, and a live region has to be in the document before its text
 * changes or the change is never announced.
 */
function HandleStatus({
  id,
  status,
  canonical,
  typed,
}: {
  id: string;
  status: UsernameStatus;
  canonical: string | null;
  typed: string;
}): ReactNode {
  // Worth saying only when the stored form differs from what was typed, so
  // someone who entered `AlexSmith` learns the handle is held as `alexsmith`
  // before they find out from their profile.
  const isFolded = canonical !== null && canonical !== typed;

  const text =
    status === "checking"
      ? "Checking availability…"
      : status === "available"
        ? isFolded
          ? `Available, and saved as @${canonical}.`
          : "Available."
        : status === "error"
          ? "Could not check this username right now. You can still submit it."
          : "";

  const tone =
    status === "available"
      ? "text-accent-green"
      : status === "error"
        ? "text-accent-yellow"
        : "text-mute";

  return (
    <span id={id} role="status" aria-live="polite" className={`text-caption ${tone}`}>
      {text}
    </span>
  );
}

/**
 * Free alternatives, as buttons rather than text.
 *
 * The engine generates these knowing which ones are actually unclaimed, so the
 * useful action is taking one — retyping a name from a sentence is the work this
 * saves. `type="button"` is load-bearing: the shared Button sets no default type,
 * and a typeless button inside a form submits it, so a tap meant to fill the field
 * would post the form with the old value still in it.
 */
function Suggestions({
  options,
  onPick,
}: {
  options: readonly string[];
  onPick: (username: string) => void;
}): ReactNode {
  if (options.length === 0) return null;

  return (
    <div className="flex flex-col gap-xs">
      <span className="text-caption text-mute">These are free:</span>
      <div className="flex flex-wrap gap-xs">
        {options.map((option) => (
          <Button
            key={option}
            type="button"
            variant="outline"
            size="sm"
            className="font-mono"
            onClick={() => onPick(option)}
          >
            @{option}
          </Button>
        ))}
      </div>
    </div>
  );
}

function Confirmation({
  outcome,
  isBlockedUntilVerified,
  onContinue,
}: {
  outcome: Outcome;
  isBlockedUntilVerified: boolean;
  onContinue: () => void;
}): ReactNode {
  if (outcome.kind === "linkSent") {
    return (
      <div className="flex flex-col gap-md">
        <h2 className="font-display text-heading-sm text-ink">Check your email</h2>
        <p className="text-body-sm text-charcoal">
          A sign-up link is on its way to <span className="font-mono text-ink">{outcome.email}</span>.
          Opening it creates your account and signs you in.
        </p>
        <p className="text-caption text-mute">
          The link is single-use and expires shortly. Nothing was created yet.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-md">
      <h2 className="font-display text-heading-sm text-ink">Account created</h2>

      {!outcome.isVerified && (
        <p className="text-body-sm text-charcoal">
          We sent a verification link to{" "}
          <span className="font-mono text-ink">{outcome.email}</span>.
          {isBlockedUntilVerified
            ? " Open it to finish signing in."
            : " You can open it whenever — you are already signed in."}
        </p>
      )}

      {/* Notify mode: the engine accepted the password and reported what it
          missed anyway. Said once, here, rather than as a refusal on a form the
          user has already left. */}
      {outcome.missingCriteria && outcome.missingCriteria.length > 0 && (
        <p className="text-caption text-accent-yellow">
          Your password is weaker than this application recommends. Consider changing it
          in your security settings.
        </p>
      )}

      {!isBlockedUntilVerified && (
        // A router push rather than a styled anchor. Copying the primary
        // button's classes onto a Link is how a design system drifts: the two
        // stop matching the first time one of them is tuned.
        <Button variant="primary" className="mt-sm w-full" onClick={onContinue}>
          Continue to your account
        </Button>
      )}
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
        Loading the sign-up form.
      </span>

      <div aria-hidden="true" className="flex flex-col gap-lg">
        <Skeleton variant="text" className="w-16" />
        <Skeleton variant="control" />
        <Skeleton variant="text" className="w-16" />
        <Skeleton variant="control" />
        <Skeleton variant="text" className="w-20" />
        <Skeleton variant="control" />
        <Skeleton variant="control" />
      </div>
    </div>
  );
}
