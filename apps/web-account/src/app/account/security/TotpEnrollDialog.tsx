"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Button, CopyButton, Dialog, FormField, InputOTP } from "@authn/ui";
import { useAuth } from "@authn/react";
import { AuthnErrorCode } from "@authn/js";
import { QrCode } from "@/components/QrCode";
import { presentSaveError } from "@/lib/authError";
import { RecoveryCodesPanel } from "./RecoveryCodesPanel";

/**
 * Authn Platform — Authenticator app enrollment
 * File: apps/web-account/src/app/account/security/TotpEnrollDialog.tsx
 *
 * Three steps in one dialog: `POST .../totp/enroll` returns a secret, the reader
 * gets it into an app, and `POST .../totp/confirm` proves it arrived.
 *
 * One dialog rather than three screens because the middle step happens on a
 * different device. Navigating away from the QR code to type the code means the
 * code is gone when the phone is showing digits, so the two live side by side and
 * the reader looks between them.
 *
 * The confirm step is where recovery codes are minted, and it is the only response
 * that ever carries them. That is why the dialog does not close on success: closing
 * would be discarding the one copy of them that will ever exist.
 */

type Step =
  | { kind: "starting" }
  | { kind: "failed"; message: string }
  | { kind: "scan"; secret: string; uri: string }
  | { kind: "codes"; codes: string[] }
  | { kind: "done" };

export interface TotpEnrollDialogProps {
  isOpen: boolean;
  onClose: () => void;
  /** Called once the factor is confirmed, so the page can re-read its state. */
  onEnrolled: () => void;
}

export function TotpEnrollDialog({
  isOpen,
  onClose,
  onEnrolled,
}: TotpEnrollDialogProps): ReactNode {
  const { client } = useAuth();

  const [step, setStep] = useState<Step>({ kind: "starting" });
  const [code, setCode] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [isConfirming, setIsConfirming] = useState(false);

  /**
   * Enrollment starts on open, not on the button that opened it.
   *
   * The request stages a disabled secret, and staging one per open is harmless —
   * the engine keeps a single pending row per user — while making the QR code
   * present the moment the dialog is. Starting it on the button instead means the
   * dialog opens onto a spinner every time.
   */
  useEffect(() => {
    if (!isOpen) return;

    let isCurrent = true;
    setStep({ kind: "starting" });
    setCode("");
    setMessage(null);
    setIsConfirming(false);

    void (async () => {
      const result = await client.enrollTOTP();
      if (!isCurrent) return;

      if (!result.ok) {
        setStep({ kind: "failed", message: presentSaveError(result.error, "authenticator") });
        return;
      }
      // The URI is what the QR code carries and it is what the engine builds; a
      // response without one cannot be scanned, and inventing one here would mean
      // guessing the issuer and the account label the engine chose.
      if (!result.uri) {
        setStep({
          kind: "failed",
          message: "The server did not return a setup link. Close this and try again.",
        });
        return;
      }
      setStep({ kind: "scan", secret: result.secret, uri: result.uri });
    })();

    return () => {
      isCurrent = false;
    };
  }, [client, isOpen]);

  const confirm = useCallback(
    async (entered: string) => {
      if (entered.length !== 6) {
        setMessage("Enter all six digits from your authenticator app.");
        return;
      }

      setIsConfirming(true);
      setMessage(null);
      const result = await client.confirmTOTP({ code: entered });
      setIsConfirming(false);

      if (!result.ok) {
        setMessage(
          result.error.code === AuthnErrorCode.INVALID_MFA_CODE
            ? "That code was not accepted. Codes last 30 seconds — wait for the next one and enter it fresh."
            : presentSaveError(result.error, "authenticator"),
        );
        setCode("");
        return;
      }

      onEnrolled();

      // Codes arrive only here. If the account already had a set, none are issued
      // and there is nothing to show, so the dialog finishes instead.
      if (result.recoveryCodesCreated && result.recoveryCodes && result.recoveryCodes.length > 0) {
        setStep({ kind: "codes", codes: result.recoveryCodes });
        return;
      }
      setStep({ kind: "done" });
    },
    [client, onEnrolled],
  );

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title={
        step.kind === "codes"
          ? "Save your recovery codes"
          : step.kind === "done"
            ? "Authenticator app is on"
            : "Set up an authenticator app"
      }
      description={
        step.kind === "scan"
          ? "Scan this with your authenticator app, then type the six digits it shows to prove it worked."
          : undefined
      }
      maxWidth={step.kind === "codes" ? "lg" : "md"}
    >
      {step.kind === "starting" ? (
        <p role="status" className="py-lg text-body-sm text-mute">
          Preparing your setup code…
        </p>
      ) : step.kind === "failed" ? (
        <div className="flex flex-col gap-lg">
          <p className="text-body-sm text-accent-red">{step.message}</p>
          <div className="flex justify-end">
            <Button variant="secondary" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      ) : step.kind === "codes" ? (
        <RecoveryCodesPanel
          codes={step.codes}
          acknowledgeLabel="Done"
          onAcknowledge={() => setStep({ kind: "done" })}
        />
      ) : step.kind === "done" ? (
        <div className="flex flex-col gap-lg">
          <p className="text-body-sm text-charcoal">
            Your next sign-in will ask for a code from the app after your password.
          </p>
          <div className="flex justify-end">
            <Button variant="primary" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      ) : (
        /* `sm:` and not a plain flex row. On a phone the QR code is being scanned by
           a second device or long-pressed on this one, and either way it wants the
           full width; side by side it would be 120px across and unreliable. */
        <form
          noValidate
          className="flex flex-col gap-lg"
          onSubmit={(event) => {
            event.preventDefault();
            void confirm(code);
          }}
        >
          <div className="flex flex-col items-center gap-lg sm:flex-row sm:items-start">
            <QrCode
              value={step.uri}
              size={176}
              label="QR code containing your authenticator setup key"
              className="shrink-0"
            />

            <div className="flex min-w-0 flex-1 flex-col gap-sm">
              <p className="text-caption text-ash">
                No camera on this device? Enter this key in your app by hand instead.
              </p>
              {/* Broken into four-character groups. A 32-character base32 string
                  typed as one run is where transcription fails, and the grouping is
                  display only — the copy button hands over the unbroken key. */}
              <div className="flex items-center gap-sm rounded-md border border-hairline bg-surface-elevated p-sm">
                <code className="min-w-0 flex-1 font-mono text-caption break-all text-ink select-all">
                  {groupSecret(step.secret)}
                </code>
                <CopyButton value={step.secret} label="Copy" />
              </div>
              <p className="text-caption text-ash">
                Works with any TOTP app — 1Password, Bitwarden, Google Authenticator, Aegis.
              </p>
            </div>
          </div>

          <FormField label="Code from the app" isRequired error={message ?? undefined}>
            <InputOTP
              value={code}
              isDisabled={isConfirming}
              onChange={(next) => {
                setCode(next);
                if (message) setMessage(null);
              }}
              /* Submitted on the sixth digit. The code expires in seconds, so
                 asking someone to reach for a button after typing it is asking them
                 to race a clock they cannot see. */
              onComplete={(next) => void confirm(next)}
            />
          </FormField>

          <div className="flex justify-end gap-sm">
            <Button type="button" variant="ghost" disabled={isConfirming} onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" isLoading={isConfirming}>
              Turn it on
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

/** Splits a base32 secret into four-character groups for reading aloud or typing. */
function groupSecret(secret: string): string {
  return secret.replace(/(.{4})/g, "$1 ").trim();
}
