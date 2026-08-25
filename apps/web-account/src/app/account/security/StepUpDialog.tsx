"use client";

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Button, Dialog, FormField, Input } from "@authn/ui";
import { AuthnErrorCode, type AuthnError } from "@authn/js";

/**
 * Authn Platform — Password step-up
 * File: apps/web-account/src/app/account/security/StepUpDialog.tsx
 *
 * The dialog every destructive second-factor change goes through: turning off an
 * authenticator, removing a phone number, replacing a set of recovery codes,
 * deleting the last passkey.
 *
 * One component rather than a password field inside each of those, because the
 * engine's rule is the same in every case — `POST .../disable` and
 * `.../regenerate` refuse a request with no `password` before they look at
 * anything else — and because the failure is the same too: a 401 that means "wrong
 * password", not "you are signed out". Written four times, that 401 gets handled
 * correctly in three of them and logs the reader out of the fourth.
 */

export interface StepUpDialogProps {
  isOpen: boolean;
  onClose: () => void;
  /** Names the action, e.g. "Turn off the authenticator app". */
  title: string;
  /** What will happen, in full, including anything irreversible. */
  description: string;
  /** Label for the confirming button, e.g. "Turn it off". */
  confirmLabel: string;
  /** `red` for a removal, `primary` for a replacement. */
  tone?: "red" | "primary";
  /**
   * Extra warning shown in a framed block above the field, for a consequence the
   * description cannot carry in one sentence — the sign-out that follows removing a
   * last factor being the case that needs it.
   */
  consequence?: ReactNode;
  /** Runs the request. Resolves to an error to keep the dialog open and show it. */
  onConfirm: (password: string) => Promise<AuthnError | null>;
}

export function StepUpDialog({
  isOpen,
  onClose,
  title,
  description,
  confirmLabel,
  tone = "red",
  consequence,
  onConfirm,
}: StepUpDialogProps): ReactNode {
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [isWorking, setIsWorking] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // On open rather than on close: clearing as the dialog fades would blank the
  // field while it is still on screen, which reads as the form resetting itself.
  useEffect(() => {
    if (!isOpen) return;
    setPassword("");
    setMessage(null);
    setIsWorking(false);
    inputRef.current?.focus();
  }, [isOpen]);

  const submit = useCallback(async () => {
    if (password === "") {
      setMessage("Enter your password to confirm.");
      inputRef.current?.focus();
      return;
    }

    setIsWorking(true);
    setMessage(null);
    const error = await onConfirm(password);
    setIsWorking(false);

    if (!error) return;

    /* A wrong password is answered here and not by the shared error presenter. The
       401 is expected on this dialog — it is what a typo looks like — and the
       presenter's line for an expired session would tell someone whose session is
       working perfectly to sign in again. */
    setMessage(
      error.code === AuthnErrorCode.INVALID_CREDENTIALS
        ? "That password is not right. Try again."
        : (error.message ?? "That did not work. Try again."),
    );
    setPassword("");
    inputRef.current?.focus();
  }, [onConfirm, password]);

  return (
    <Dialog isOpen={isOpen} onClose={onClose} title={title} description={description}>
      <form
        noValidate
        className="flex flex-col gap-lg"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        {consequence ? (
          <div className="rounded-md border border-accent-yellow/40 bg-accent-yellow/8 p-md text-caption text-charcoal">
            {consequence}
          </div>
        ) : null}

        <FormField
          label="Your password"
          isRequired
          error={message ?? undefined}
          hint="The password you sign in with, not a code from your authenticator."
        >
          <Input
            ref={inputRef}
            type="password"
            value={password}
            /* `current-password` and not `new-password`: this field is a proof of
               identity, so a password manager should offer the stored entry rather
               than propose a fresh one. */
            autoComplete="current-password"
            disabled={isWorking}
            onChange={(event) => {
              setPassword(event.target.value);
              if (message) setMessage(null);
            }}
          />
        </FormField>

        <div className="flex justify-end gap-sm">
          <Button type="button" variant="ghost" disabled={isWorking} onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant={tone === "red" ? "destructive" : "primary"}
            isLoading={isWorking}
          >
            {confirmLabel}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
