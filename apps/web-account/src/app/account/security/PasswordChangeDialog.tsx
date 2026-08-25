"use client";

import { useCallback, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { Button, Dialog, FormField, Input, useToast } from "@authn/ui";
import { useAppConfig, useAuth } from "@authn/react";
import { AuthnErrorCode } from "@authn/js";
import { PasswordCriteria } from "@/components/PasswordCriteria";
import { presentSaveError } from "@/lib/authError";
import { evaluatePassword } from "@/lib/password";

/**
 * Authn Platform — Password change
 * File: apps/web-account/src/app/account/security/PasswordChangeDialog.tsx
 *
 * `POST /v1/client/user/password`, with the tenant's own policy shown beside the
 * field.
 *
 * The policy comes from `GET /v1/client/app-config`, not from a constant here. A
 * checklist that says "at least 8 characters" while the tenant requires twelve is
 * worse than no checklist: it tells the reader they have satisfied a rule and then
 * the request refuses them.
 *
 * Two things this dialog will not do. It does not confirm the new password twice —
 * a reveal toggle catches a typo where a second field only catches it being made
 * once. And it does not sign the reader out: the engine keeps the calling session
 * and revokes the others, so the page behind this dialog stays usable.
 */

export interface PasswordChangeDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export function PasswordChangeDialog({ isOpen, onClose }: PasswordChangeDialogProps): ReactNode {
  const { client } = useAuth();
  const { config } = useAppConfig();
  const toast = useToast();

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [isRevealed, setIsRevealed] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [currentMessage, setCurrentMessage] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  const criteriaId = useId();
  const currentRef = useRef<HTMLInputElement>(null);
  const nextRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!isOpen) return;
    setCurrent("");
    setNext("");
    setIsRevealed(false);
    setMessage(null);
    setCurrentMessage(null);
    setIsSaving(false);
    currentRef.current?.focus();
  }, [isOpen]);

  const criteria = useMemo(
    () => (config ? evaluatePassword(next, config.passwordRules) : []),
    [next, config],
  );

  /**
   * Whether the local mirror is willing to send.
   *
   * Only in enforced mode. A tenant in notify mode accepts a non-compliant password
   * and returns the unmet rules as a warning, so blocking the button here would
   * refuse something the engine would have allowed — and the reader has no way to
   * tell which of the two rules they are up against.
   */
  const isBlockedLocally =
    config?.passwordRules.enforced === true && criteria.some((criterion) => !criterion.met);

  const submit = useCallback(async () => {
    if (current === "") {
      setCurrentMessage("Enter your current password.");
      currentRef.current?.focus();
      return;
    }
    if (next === "") {
      setMessage("Enter the password you want to use.");
      nextRef.current?.focus();
      return;
    }
    if (next === current) {
      setMessage("That is the password you already have. Choose a different one.");
      nextRef.current?.focus();
      return;
    }

    setIsSaving(true);
    setMessage(null);
    setCurrentMessage(null);
    const result = await client.changePassword(current, next);
    setIsSaving(false);

    if (!result.ok) {
      // The 401 belongs to the current-password field and the 400 to the new one.
      // Both arrive as one error, and putting either in the wrong place sends the
      // reader to re-type something that was correct.
      if (result.error.code === AuthnErrorCode.INVALID_CREDENTIALS) {
        setCurrentMessage("That is not your current password.");
        setCurrent("");
        currentRef.current?.focus();
        return;
      }
      setMessage(presentSaveError(result.error, "password"));
      nextRef.current?.focus();
      return;
    }

    toast.success(
      "Password changed",
      "Your other sessions have been signed out. This one is still active.",
    );
    onClose();
  }, [client, current, next, onClose, toast]);

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title="Change your password"
      description="Your current password confirms it is you. Every other session is signed out; this one stays."
    >
      <form
        noValidate
        className="flex flex-col gap-lg"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <FormField label="Current password" isRequired error={currentMessage ?? undefined}>
          <Input
            ref={currentRef}
            type="password"
            value={current}
            autoComplete="current-password"
            disabled={isSaving}
            onChange={(event) => {
              setCurrent(event.target.value);
              if (currentMessage) setCurrentMessage(null);
            }}
          />
        </FormField>

        <div className="flex flex-col gap-sm">
          <FormField label="New password" isRequired error={message ?? undefined}>
            <Input
              ref={nextRef}
              /* Toggled rather than paired with a confirm field. Someone choosing a
                 password wants to check what they typed, and reading it back is a
                 more reliable check than typing it twice — a doubled typo passes a
                 confirm field and fails the next sign-in. */
              type={isRevealed ? "text" : "password"}
              value={next}
              autoComplete="new-password"
              aria-describedby={criteriaId}
              disabled={isSaving}
              onChange={(event) => {
                setNext(event.target.value);
                if (message) setMessage(null);
              }}
            />
          </FormField>

          <div className="flex items-start justify-between gap-md">
            {config ? (
              <PasswordCriteria id={criteriaId} criteria={criteria} isActive={next.length > 0} />
            ) : (
              <span id={criteriaId} className="text-caption text-ash">
                Loading your organization's password rules…
              </span>
            )}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => setIsRevealed((shown) => !shown)}
            >
              {isRevealed ? "Hide" : "Show"}
            </Button>
          </div>

          {config && !config.passwordRules.enforced ? (
            <p className="text-caption text-accent-yellow">
              Your organization treats these as advice rather than requirements, so a
              password that misses one is still accepted.
            </p>
          ) : null}
        </div>

        <div className="flex justify-end gap-sm">
          <Button type="button" variant="ghost" disabled={isSaving} onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            isLoading={isSaving}
            disabled={isBlockedLocally || next === ""}
          >
            Change password
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
