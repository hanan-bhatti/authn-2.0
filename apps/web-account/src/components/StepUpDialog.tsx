"use client";

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Button, Dialog, FormField, Input } from "@authn/ui";
import { AuthnErrorCode, type AuthnError } from "@authn/js";
import { asSentence } from "@/lib/authError";

/**
 * Authn Platform — Credential step-up
 * File: apps/web-account/src/components/StepUpDialog.tsx
 *
 * The dialog every sensitive change goes through: turning off an authenticator,
 * removing a phone number, replacing a set of recovery codes, deleting the last
 * passkey, writing a set of security questions.
 *
 * One component rather than a password field inside each of those, because the
 * engine's rule is the same in every case — those routes refuse a request with no
 * credential before they look at anything else — and because the failure is the
 * same too: a 401 that means "wrong password", not "you are signed out". Written
 * five times, that 401 gets handled correctly in four of them and logs the reader
 * out of the fifth.
 *
 * Which credential is asked for is not the reader's choice, and not this dialog's
 * either. The engine checks an account holding a password on the password, and only
 * one holding none falls through to an authenticator code. So the caller passes
 * `factor` from the profile's `hasPassword`, and a wrong guess costs a refused
 * request rather than a silent mismatch.
 */

/** Which credential the account is checked on. */
export type StepUpFactor = "password" | "totp";

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
   * Which credential to collect. Defaults to `password`, which is what all but a
   * social-only or passkey-only account holds.
   */
  factor?: StepUpFactor;
  /**
   * Extra warning shown in a framed block above the field, for a consequence the
   * description cannot carry in one sentence — the sign-out that follows removing a
   * last factor being the case that needs it.
   */
  consequence?: ReactNode;
  /**
   * Runs the request with whatever was typed. Resolves to an error to keep the
   * dialog open and show it.
   *
   * One string rather than a `{password}`/`{totpCode}` union, because the caller
   * already chose `factor` and therefore knows which field it is handing to the SDK.
   */
  onConfirm: (credential: string) => Promise<AuthnError | null>;
}

/** The field's wording per factor, so the two branches differ in text only. */
const FIELD_COPY: Record<StepUpFactor, { label: string; hint: string; empty: string; wrong: string }> = {
  password: {
    label: "Your password",
    hint: "The password you sign in with, not a code from your authenticator.",
    empty: "Enter your password to confirm.",
    wrong: "That password is not right. Try again.",
  },
  totp: {
    label: "Code from your authenticator app",
    hint: "This account has no password, so its authenticator code is what confirms the change.",
    empty: "Enter the current 6-digit code to confirm.",
    wrong: "That code is not valid right now. Codes change every 30 seconds — use the current one.",
  },
};

export function StepUpDialog({
  isOpen,
  onClose,
  title,
  description,
  confirmLabel,
  tone = "red",
  factor = "password",
  consequence,
  onConfirm,
}: StepUpDialogProps): ReactNode {
  const [credential, setCredential] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [isWorking, setIsWorking] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const copy = FIELD_COPY[factor];

  // On open rather than on close: clearing as the dialog fades would blank the
  // field while it is still on screen, which reads as the form resetting itself.
  useEffect(() => {
    if (!isOpen) return;
    setCredential("");
    setMessage(null);
    setIsWorking(false);
    inputRef.current?.focus();
  }, [isOpen]);

  const submit = useCallback(async () => {
    if (credential === "") {
      setMessage(copy.empty);
      inputRef.current?.focus();
      return;
    }

    setIsWorking(true);
    setMessage(null);
    const error = await onConfirm(credential);
    setIsWorking(false);

    if (!error) return;

    /* A wrong credential is answered here and not by the shared error presenter. The
       401 is expected on this dialog — it is what a typo looks like — and the
       presenter's line for an expired session would tell someone whose session is
       working perfectly to sign in again.

       `STEP_UP_REQUIRED` lands here too, which means the engine wanted the other
       factor: the profile said one thing and the account holds another. Reported as
       the engine worded it, since it names the credential it is waiting for. */
    setMessage(
      error.code === AuthnErrorCode.INVALID_CREDENTIALS
        ? copy.wrong
        : (asSentence(error.message) ?? "That did not work. Try again."),
    );
    setCredential("");
    inputRef.current?.focus();
  }, [copy, onConfirm, credential]);

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

        <FormField label={copy.label} isRequired error={message ?? undefined} hint={copy.hint}>
          <Input
            ref={inputRef}
            /* A code is not a secret to be hidden from the person typing it — it is on
               a screen in their hand and expires in seconds — so it is shown, and gets
               the numeric keypad on a phone. A password is masked. */
            type={factor === "password" ? "password" : "text"}
            value={credential}
            /* `current-password` and not `new-password`: this field is a proof of
               identity, so a password manager should offer the stored entry rather
               than propose a fresh one. `one-time-code` lets a phone offer the code
               from its notification shade. */
            autoComplete={factor === "password" ? "current-password" : "one-time-code"}
            inputMode={factor === "password" ? undefined : "numeric"}
            maxLength={factor === "password" ? undefined : 6}
            isMonospace={factor !== "password"}
            disabled={isWorking}
            onChange={(event) => {
              setCredential(
                factor === "password"
                  ? event.target.value
                  : // Digits only, so a code pasted with a space in the middle is
                    // accepted rather than refused for a character the reader cannot
                    // see. The engine trims but does not strip interior whitespace.
                    event.target.value.replace(/\D/g, ""),
              );
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
