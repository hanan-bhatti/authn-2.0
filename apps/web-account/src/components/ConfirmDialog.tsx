"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { AlertIcon, Button, Dialog } from "@authn/ui";
import type { AuthnError } from "@authn/js";
import { presentSaveError } from "@/lib/authError";

/**
 * Authn Platform — Confirmation dialog
 * File: apps/web-account/src/components/ConfirmDialog.tsx
 *
 * The dialog for a change that is destructive but needs no password: signing a
 * device out, disconnecting a provider, removing a guardian, leaving a workspace.
 *
 * Separate from `StepUpDialog`, which exists for the changes the engine refuses
 * without a password. Reusing that one here would put a password field in front of
 * actions the engine does not ask one for — which trains a reader to type their
 * password whenever a dialog asks, and that habit is what phishing needs.
 *
 * The refusal is shown inside the dialog rather than as a toast on a closed one.
 * A confirmation that closes and then reports a failure elsewhere leaves the
 * reader unsure whether the thing happened, and their next move is to try again.
 */

export interface ConfirmDialogProps {
  isOpen: boolean;
  onClose: () => void;
  /** The question, e.g. "Sign this device out?". */
  title: string;
  /** What confirming does, including anything that cannot be undone. */
  description?: string;
  /**
   * Extra context inside the dialog: what is unaffected, what the reader will need
   * afterwards. Rendered above the buttons.
   */
  children?: ReactNode;
  /** Framed warning for a consequence the description cannot carry in a sentence. */
  consequence?: ReactNode;
  /** Label for the confirming button, e.g. "Sign it out". */
  confirmLabel: string;
  /** Label for the way out. Phrased as the safe choice, not as "Cancel". */
  cancelLabel?: string;
  /** `destructive` for a removal, `primary` for a replacement. */
  tone?: "destructive" | "primary";
  /** Names the thing being changed, for the refusal text: "sessions", "connection". */
  subject: string;
  /** Runs the request. Resolves to an error to keep the dialog open and show it. */
  onConfirm: () => Promise<AuthnError | null>;
}

export function ConfirmDialog({
  isOpen,
  onClose,
  title,
  description,
  children,
  consequence,
  confirmLabel,
  cancelLabel = "Cancel",
  tone = "destructive",
  subject,
  onConfirm,
}: ConfirmDialogProps): ReactNode {
  const [message, setMessage] = useState<string | null>(null);
  const [isWorking, setIsWorking] = useState(false);

  // On open rather than on close, so a refusal is not wiped from the screen while
  // the dialog is still fading out.
  useEffect(() => {
    if (!isOpen) return;
    setMessage(null);
    setIsWorking(false);
  }, [isOpen]);

  const confirm = useCallback(async () => {
    setIsWorking(true);
    setMessage(null);
    const error = await onConfirm();
    setIsWorking(false);
    if (error) {
      setMessage(presentSaveError(error, subject));
      return;
    }
    // Left to the caller. Some confirmations open a second dialog with something
    // to save, and closing here would take it away before it was read.
  }, [onConfirm, subject]);

  return (
    <Dialog isOpen={isOpen} onClose={onClose} title={title} description={description}>
      <form
        noValidate
        className="flex flex-col gap-lg"
        onSubmit={(event) => {
          event.preventDefault();
          void confirm();
        }}
      >
        {consequence ? (
          <div className="flex items-start gap-sm rounded-md border border-accent-yellow/40 bg-accent-yellow/8 p-md">
            <AlertIcon variant="line" size={16} className="mt-px shrink-0 text-accent-yellow" />
            <p className="text-caption text-charcoal">{consequence}</p>
          </div>
        ) : null}

        {children ? <div className="text-body-sm text-charcoal">{children}</div> : null}

        {message ? <p className="text-body-sm text-accent-red">{message}</p> : null}

        <div className="flex justify-end gap-sm">
          <Button type="button" variant="ghost" disabled={isWorking} onClick={onClose}>
            {cancelLabel}
          </Button>
          <Button
            type="submit"
            variant={tone === "primary" ? "primary" : "destructive"}
            isLoading={isWorking}
          >
            {confirmLabel}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
