"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Button, Dialog, FormField, Input, InputOTP } from "@authn/ui";
import { useAuth } from "@authn/react";
import { AuthnErrorCode } from "@authn/js";
import { presentSaveError } from "@/lib/authError";
import { RecoveryCodesPanel } from "./RecoveryCodesPanel";

/**
 * Authn Platform — Text-message enrollment
 * File: apps/web-account/src/app/account/security/SmsEnrollDialog.tsx
 *
 * A number, then the code sent to it: `POST .../sms/enroll` then
 * `POST .../sms/confirm`.
 *
 * The number is held as a pending, disabled row until the code comes back, which is
 * the behaviour worth surfacing in the copy — an abandoned setup leaves nothing
 * behind, so a mistyped number costs one message and no cleanup.
 *
 * Confirming can mint recovery codes, exactly as the authenticator path can, so this
 * dialog ends on the same panel and for the same reason: it is the only response
 * that will ever carry them.
 */

type Step =
  | { kind: "number" }
  | { kind: "code"; phoneNumber: string }
  | { kind: "codes"; codes: string[] }
  | { kind: "done"; phoneNumber: string };

export interface SmsEnrollDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onEnrolled: () => void;
}

export function SmsEnrollDialog({
  isOpen,
  onClose,
  onEnrolled,
}: SmsEnrollDialogProps): ReactNode {
  const { client } = useAuth();

  const [step, setStep] = useState<Step>({ kind: "number" });
  const [phoneNumber, setPhoneNumber] = useState("");
  const [code, setCode] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [isWorking, setIsWorking] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    setStep({ kind: "number" });
    setPhoneNumber("");
    setCode("");
    setMessage(null);
    setIsWorking(false);
  }, [isOpen]);

  const sendCode = useCallback(async () => {
    const next = phoneNumber.trim();

    /* Checked here because the engine's refusal for a bad number is a generic 400,
       and the one thing a reader needs told is the leading plus. E.164 is the only
       format accepted and nothing about an empty field says so. */
    if (!/^\+[1-9]\d{6,14}$/.test(next)) {
      setMessage(
        "Use the international format, starting with + and your country code — for example +447700900471.",
      );
      return;
    }

    setIsWorking(true);
    setMessage(null);
    const result = await client.enrollSMS({ phoneNumber: next });
    setIsWorking(false);

    if (!result.ok) {
      setMessage(presentSaveError(result.error, "phone number"));
      return;
    }

    setCode("");
    setStep({ kind: "code", phoneNumber: next });
  }, [client, phoneNumber]);

  const confirm = useCallback(
    async (entered: string, number: string) => {
      if (entered.length !== 6) {
        setMessage("Enter all six digits from the message.");
        return;
      }

      setIsWorking(true);
      setMessage(null);
      const result = await client.confirmSMS({ code: entered });
      setIsWorking(false);

      if (!result.ok) {
        setMessage(
          result.error.code === AuthnErrorCode.INVALID_MFA_CODE
            ? "That code was not accepted. Check the message again, or go back and resend."
            : presentSaveError(result.error, "phone number"),
        );
        setCode("");
        return;
      }

      onEnrolled();

      if (result.recoveryCodesCreated && result.recoveryCodes && result.recoveryCodes.length > 0) {
        setStep({ kind: "codes", codes: result.recoveryCodes });
        return;
      }
      setStep({ kind: "done", phoneNumber: number });
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
            ? "Text messages are on"
            : step.kind === "code"
              ? "Enter the code we sent"
              : "Add a phone number"
      }
      description={
        step.kind === "number"
          ? "We send a six-digit code to confirm the number reaches you. Nothing is saved to your account until it does."
          : step.kind === "code"
            ? `Sent to ${step.phoneNumber}. It expires in a few minutes.`
            : undefined
      }
      maxWidth={step.kind === "codes" ? "lg" : "md"}
    >
      {step.kind === "codes" ? (
        <RecoveryCodesPanel
          codes={step.codes}
          acknowledgeLabel="Done"
          onAcknowledge={() => setStep({ kind: "done", phoneNumber })}
        />
      ) : step.kind === "done" ? (
        <div className="flex flex-col gap-lg">
          <p className="text-body-sm text-charcoal">
            Your next sign-in will text a code to{" "}
            <span className="font-mono text-ink">{step.phoneNumber}</span> after your password.
            The same verified number can also be used to recover the account.
          </p>
          <div className="flex justify-end">
            <Button variant="primary" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      ) : step.kind === "code" ? (
        <form
          noValidate
          className="flex flex-col gap-lg"
          onSubmit={(event) => {
            event.preventDefault();
            void confirm(code, step.phoneNumber);
          }}
        >
          <FormField label="Code from the message" isRequired error={message ?? undefined}>
            <InputOTP
              value={code}
              isDisabled={isWorking}
              onChange={(next) => {
                setCode(next);
                if (message) setMessage(null);
              }}
              onComplete={(next) => void confirm(next, step.phoneNumber)}
            />
          </FormField>

          <div className="flex flex-wrap items-center justify-between gap-sm">
            {/* Back rather than a resend button. Resending needs the number again,
                and the reader who did not get a message frequently mistyped it — the
                step that lets them look at what they typed is the useful one. */}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              disabled={isWorking}
              onClick={() => {
                setMessage(null);
                setStep({ kind: "number" });
              }}
            >
              Use a different number
            </Button>
            <div className="flex gap-sm">
              <Button type="button" variant="ghost" disabled={isWorking} onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" isLoading={isWorking}>
                Turn it on
              </Button>
            </div>
          </div>
        </form>
      ) : (
        <form
          noValidate
          className="flex flex-col gap-lg"
          onSubmit={(event) => {
            event.preventDefault();
            void sendCode();
          }}
        >
          <FormField
            label="Phone number"
            isRequired
            error={message ?? undefined}
            hint="International format, starting with +."
          >
            <Input
              type="tel"
              value={phoneNumber}
              autoComplete="tel"
              placeholder="+447700900471"
              disabled={isWorking}
              onChange={(event) => {
                setPhoneNumber(event.target.value);
                if (message) setMessage(null);
              }}
            />
          </FormField>

          <p className="text-caption text-ash">
            A text-message code is the weakest of the second factors: a number can be
            moved to another SIM by someone who convinces the carrier they are you. If
            you can use an authenticator app or a passkey instead, use that.
          </p>

          <div className="flex justify-end gap-sm">
            <Button type="button" variant="ghost" disabled={isWorking} onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" isLoading={isWorking}>
              Send the code
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
