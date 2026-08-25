"use client";

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { AlertIcon, Button, Dialog, FormField, Input } from "@authn/ui";
import { useAuth } from "@authn/react";
import { AuthnErrorCode } from "@authn/js";
import { presentSaveError } from "@/lib/authError";

/**
 * Authn Platform — Passkey removal
 * File: apps/web-account/src/app/account/security/PasskeyRemoveDialog.tsx
 *
 * `DELETE .../webauthn/credentials/:id`, where the password is conditional.
 *
 * The engine asks for it only when this passkey is the account's last second
 * factor, and it does not announce that in advance — the same 401 covers "you
 * need to confirm" and "that was the wrong password". So the delete is attempted
 * without one first, and the field appears only if the account turns out to need
 * it. Showing it up front would ask most readers for a password to remove a spare
 * key they have three of.
 *
 * The consequence of the last-factor path is stated where it is discovered, not
 * on the button: removing that factor signs out every other session, and someone
 * who learns that after typing their password has already been surprised.
 */

export interface PasskeyRemoveTarget {
  id: string;
  name: string;
}

export interface PasskeyRemoveDialogProps {
  isOpen: boolean;
  onClose: () => void;
  passkey: PasskeyRemoveTarget | null;
  onRemoved: () => void;
}

export function PasskeyRemoveDialog({
  isOpen,
  onClose,
  passkey,
  onRemoved,
}: PasskeyRemoveDialogProps): ReactNode {
  const { client } = useAuth();

  const [needsPassword, setNeedsPassword] = useState(false);
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [isWorking, setIsWorking] = useState(false);

  const passwordRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!isOpen) return;
    setNeedsPassword(false);
    setPassword("");
    setMessage(null);
    setIsWorking(false);
  }, [isOpen]);

  const remove = useCallback(async () => {
    if (!passkey) return;
    if (needsPassword && password === "") {
      setMessage("Enter your password to confirm.");
      passwordRef.current?.focus();
      return;
    }

    setIsWorking(true);
    setMessage(null);
    const result = await client.revokeWebAuthnCredential({
      id: passkey.id,
      ...(needsPassword ? { password } : {}),
    });
    setIsWorking(false);

    if (!result.ok) {
      if (result.error.code === AuthnErrorCode.INVALID_CREDENTIALS) {
        // First refusal means step-up; a second one, with a password already in
        // hand, means the password was wrong. Same code, different situation, and
        // only the attempt we made tells them apart.
        if (!needsPassword) {
          setNeedsPassword(true);
          setMessage(null);
        } else {
          setMessage("That password is not right. Try again.");
          setPassword("");
        }
        // Focused after the field exists, which is the render this state change
        // causes rather than the one we are in.
        requestAnimationFrame(() => passwordRef.current?.focus());
        return;
      }
      setMessage(presentSaveError(result.error, "passkey"));
      return;
    }

    onRemoved();
    onClose();
  }, [client, needsPassword, onClose, onRemoved, passkey, password]);

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title="Remove this passkey?"
      description={
        passkey
          ? `${passkey.name} will no longer sign you in. The device keeps a copy it can no longer use, so remove it there too if you can.`
          : undefined
      }
    >
      <form
        noValidate
        className="flex flex-col gap-lg"
        onSubmit={(event) => {
          event.preventDefault();
          void remove();
        }}
      >
        {needsPassword ? (
          <>
            <div className="flex items-start gap-sm rounded-md border border-accent-yellow/40 bg-accent-yellow/8 p-md">
              <AlertIcon variant="line" size={16} className="mt-px shrink-0 text-accent-yellow" />
              <p className="text-caption text-charcoal">
                This is the only second factor on the account. Removing it leaves your
                password alone protecting you, so it needs your password to confirm — and
                every other session will be signed out.
              </p>
            </div>

            <FormField label="Your password" isRequired error={message ?? undefined}>
              <Input
                ref={passwordRef}
                type="password"
                value={password}
                autoComplete="current-password"
                disabled={isWorking}
                onChange={(event) => {
                  setPassword(event.target.value);
                  if (message) setMessage(null);
                }}
              />
            </FormField>
          </>
        ) : (
          <>
            <p className="text-body-sm text-charcoal">
              Your other passkeys and second factors are unaffected.
            </p>
            {message ? <p className="text-body-sm text-accent-red">{message}</p> : null}
          </>
        )}

        <div className="flex justify-end gap-sm">
          <Button type="button" variant="ghost" disabled={isWorking} onClick={onClose}>
            Keep it
          </Button>
          <Button type="submit" variant="destructive" isLoading={isWorking}>
            {needsPassword ? "Confirm and remove" : "Remove"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
