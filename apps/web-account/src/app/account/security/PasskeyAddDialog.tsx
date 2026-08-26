"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Button, Dialog, FormField, Input } from "@authn/ui";
import { useAuth } from "@authn/react";
import { isPasskeySupported } from "@authn/js";
import { presentSaveError } from "@/lib/authError";
import { RecoveryCodesPanel } from "@/components/RecoveryCodesPanel";

/**
 * Authn Platform — Passkey registration
 * File: apps/web-account/src/app/account/security/PasskeyAddDialog.tsx
 *
 * A name, then the browser's own prompt. `client.registerPasskey` runs
 * begin → `navigator.credentials.create` → finish as one call, and translates what
 * the authenticator threw into an ordinary error, so this dialog has one request to
 * make and one message to show.
 *
 * The name is asked for first and not afterwards. Once the ceremony is done the
 * reader has moved on, and a list of passkeys called "Passkey", "Passkey 2" and
 * "Passkey 3" is a list where nobody can tell which device died.
 *
 * Support is checked before the field is offered, because the failure is not the
 * reader's: an insecure origin or a browser without `PublicKeyCredential` cannot be
 * fixed by trying again, and a prompt that never appears reads as a broken button.
 */

export interface PasskeyAddDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onAdded: () => void;
}

export function PasskeyAddDialog({ isOpen, onClose, onAdded }: PasskeyAddDialogProps): ReactNode {
  const { client } = useAuth();

  const [name, setName] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [isWorking, setIsWorking] = useState(false);
  const [codes, setCodes] = useState<string[] | null>(null);

  /**
   * Resolved after mount, not during render.
   *
   * `isPasskeySupported` reads `window.isSecureContext` and `navigator.credentials`,
   * neither of which exists on the server. Deciding during the first render makes
   * the server say "unsupported" and the browser say "supported", and React discards
   * the mismatched subtree.
   */
  const [isSupported, setIsSupported] = useState<boolean | null>(null);
  useEffect(() => {
    setIsSupported(isPasskeySupported());
  }, []);

  useEffect(() => {
    if (!isOpen) return;
    setName("");
    setMessage(null);
    setIsWorking(false);
    setCodes(null);
  }, [isOpen]);

  const register = useCallback(async () => {
    const label = name.trim();

    setIsWorking(true);
    setMessage(null);
    // An empty name is allowed through: the engine names an unnamed passkey itself,
    // and refusing here would block someone whose authenticator prompt is already
    // waiting on screen.
    const result = await client.registerPasskey(label === "" ? undefined : label);
    setIsWorking(false);

    if (!result.ok) {
      /* The presenter and not the raw message, even though a ceremony failure is
         one of the few the engine words usefully: it reads that message itself for
         the codes where it is worth repeating, and answers the rest — a dropped
         connection, an expired token — with advice the engine has no way to give. */
      setMessage(presentSaveError(result.error, "passkey"));
      return;
    }

    onAdded();

    // A first passkey on an account with no other factor mints recovery codes, the
    // same as a first authenticator does.
    if (result.recoveryCodesCreated && result.recoveryCodes && result.recoveryCodes.length > 0) {
      setCodes(result.recoveryCodes);
      return;
    }
    onClose();
  }, [client, name, onAdded, onClose]);

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title={codes ? "Save your recovery codes" : "Add a passkey"}
      description={
        codes
          ? undefined
          : "Your device will ask for your fingerprint, face or screen lock. Nothing is typed, so there is nothing to phish."
      }
      maxWidth={codes ? "lg" : "md"}
    >
      {codes ? (
        <RecoveryCodesPanel codes={codes} acknowledgeLabel="Done" onAcknowledge={onClose} />
      ) : isSupported === false ? (
        <div className="flex flex-col gap-lg">
          <p className="text-body-sm text-charcoal">
            This browser cannot create a passkey. Passkeys need a browser that supports
            WebAuthn and a secure (https) connection to this exact domain.
          </p>
          <p className="text-caption text-ash">
            An authenticator app works everywhere and protects the account just as well
            against a stolen password.
          </p>
          <div className="flex justify-end">
            <Button variant="secondary" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      ) : (
        <form
          noValidate
          className="flex flex-col gap-lg"
          onSubmit={(event) => {
            event.preventDefault();
            void register();
          }}
        >
          <FormField
            label="Name this passkey"
            error={message ?? undefined}
            hint="Which device is holding it. This is how you will tell it apart from the others later."
          >
            <Input
              value={name}
              placeholder="Work laptop"
              maxLength={64}
              disabled={isWorking}
              onChange={(event) => {
                setName(event.target.value);
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
              variant="primary"
              isLoading={isWorking}
              /* Held until support is known rather than assumed either way. The gap
                 is one render. */
              disabled={isSupported === null}
            >
              {isWorking ? "Waiting for your device" : "Continue"}
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
