"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  AlertIcon,
  Button,
  CopyButton,
  Dialog,
  FormField,
  Input,
  MailIcon,
  PlusIcon,
  TrashIcon,
} from "@authn/ui";
import type { AuthnError, GuardianInviteLink } from "@authn/js";
import { presentSaveError } from "@/lib/authError";

/**
 * Authn Platform — Guardian invitation
 * File: apps/web-account/src/app/account/recovery/GuardianInviteDialog.tsx
 *
 * Collects up to five names and addresses, sends them, and then shows the links
 * that came back.
 *
 * The second half is the reason this is a dialog with two phases rather than a form.
 * Nothing is emailed: `POST /v1/client/account/guardians/invite` answers with one
 * URL per guardian and the account holder delivers them. A dialog that closed on
 * success would drop the only copy of those links, and with them the shares in their
 * fragments — the engine keeps only a digest of each, so those guardians could never
 * be activated and nobody would be able to say why. So the links are the outcome
 * screen, and there is no way past it that does not go through reading them.
 */

/** One row of the form. `key` is stable so React does not reuse inputs across removals. */
interface Draft {
  key: number;
  name: string;
  email: string;
}

export interface GuardianInviteDialogProps {
  isOpen: boolean;
  onClose: () => void;
  /** How many are already enrolled, so the form caps at the engine's five. */
  existingCount: number;
  /** The engine's ceiling, from `config.accountRecovery.maxGuardians`. */
  maxGuardians: number;
  /**
   * Sends the roster. Resolves to the links to show, or to an error to keep the form
   * open with the message under it.
   */
  onInvite: (
    guardians: { name: string; email: string }[],
  ) => Promise<{ ok: true; invites: GuardianInviteLink[] } | { ok: false; error: AuthnError }>;
}

export function GuardianInviteDialog({
  isOpen,
  onClose,
  existingCount,
  maxGuardians,
  onInvite,
}: GuardianInviteDialogProps): ReactNode {
  const [drafts, setDrafts] = useState<Draft[]>([{ key: 0, name: "", email: "" }]);
  const [message, setMessage] = useState<string | null>(null);
  const [isWorking, setIsWorking] = useState(false);
  const [sent, setSent] = useState<GuardianInviteLink[] | null>(null);

  const remaining = Math.max(0, maxGuardians - existingCount);

  useEffect(() => {
    if (!isOpen) return;
    setDrafts([{ key: 0, name: "", email: "" }]);
    setMessage(null);
    setIsWorking(false);
    setSent(null);
  }, [isOpen]);

  const addRow = useCallback(() => {
    setDrafts((rows) => [...rows, { key: (rows.at(-1)?.key ?? 0) + 1, name: "", email: "" }]);
  }, []);

  const removeRow = useCallback((key: number) => {
    setDrafts((rows) => rows.filter((row) => row.key !== key));
  }, []);

  const editRow = useCallback((key: number, field: "name" | "email", next: string) => {
    setDrafts((rows) => rows.map((row) => (row.key === key ? { ...row, [field]: next } : row)));
    setMessage(null);
  }, []);

  const submit = useCallback(async () => {
    const filled = drafts
      .map((row) => ({ name: row.name.trim(), email: row.email.trim() }))
      .filter((row) => row.name !== "" || row.email !== "");

    if (filled.length === 0) {
      setMessage("Add at least one name and address.");
      return;
    }
    // Checked here rather than left to the engine's 422, because the engine reports
    // the roster as a whole and the reader needs to know which row is short.
    const incomplete = filled.findIndex((row) => row.name === "" || row.email === "");
    if (incomplete !== -1) {
      setMessage(`Guardian ${incomplete + 1} needs both a name and an email address.`);
      return;
    }
    const addresses = filled.map((row) => row.email.toLowerCase());
    if (new Set(addresses).size !== addresses.length) {
      setMessage("Two of these are the same address. Each guardian needs their own.");
      return;
    }

    setIsWorking(true);
    setMessage(null);
    const result = await onInvite(filled);
    setIsWorking(false);

    if (!result.ok) {
      setMessage(presentSaveError(result.error, "guardians"));
      return;
    }

    setSent(result.invites);
  }, [drafts, onInvite]);

  // The links, once they exist. A separate return rather than a branch inside the
  // form, because the two phases share nothing: different title, different body,
  // and one button that is a dismissal rather than a submit.
  if (sent) {
    return (
      <Dialog
        isOpen
        /* No `onClose`. Escape and the backdrop are disabled here for the same reason
           the recovery-code panel disables them: this is the only copy of these links,
           and a stray click would be the reader losing them without being asked. */
        onClose={() => undefined}
        title={sent.length === 1 ? "Send this link to your guardian" : "Send each link to its guardian"}
        description="We do not email these for you. Copy each link and send it to that person however you normally reach them."
        maxWidth="lg"
      >
        <div className="flex flex-col gap-lg">
          <div className="flex items-start gap-sm rounded-md border border-accent-yellow/40 bg-accent-yellow/8 p-md">
            <AlertIcon variant="line" size={16} className="mt-px shrink-0 text-accent-yellow" />
            <p className="text-caption text-charcoal">
              These links are shown once and expire in 7 days. Each one carries that
              guardian's own recovery code, which we never store and cannot send again — a
              guardian who does not open theirs does not count towards recovery, and until
              they do, this account is no better protected than it was.
            </p>
          </div>

          <ul className="flex flex-col gap-md">
            {/* Iterated over the invites rather than over the roster: each invite names the
                guardian it belongs to, so nothing here has to line two lists up by
                position — and a link sent to the wrong person hands them someone else's
                code. */}
            {sent.map((invite) => (
              <li
                key={invite.contactId}
                className="flex flex-col gap-sm rounded-md border border-hairline bg-surface-elevated p-md"
              >
                <div className="flex flex-wrap items-baseline justify-between gap-sm">
                  <span className="text-body-md text-ink">{invite.guardianName}</span>
                  <span className="text-caption text-ash">{invite.guardianEmail}</span>
                </div>
                <div className="flex flex-wrap items-center gap-sm">
                  {/* `break-all` and not `truncate`: a reader checking they copied the
                      right one needs to see the whole thing, and the two hex strings in
                      the fragment make every one of these look alike at 40 characters. */}
                  <code className="min-w-0 flex-1 basis-[16rem] break-all rounded-sm bg-surface-card px-sm py-xs font-mono text-caption text-charcoal select-all">
                    {invite.url}
                  </code>
                  <CopyButton value={invite.url} label="Copy link" />
                </div>
              </li>
            ))}
          </ul>

          <div className="flex justify-end">
            <Button variant="primary" onClick={onClose}>
              I have sent them
            </Button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title="Invite guardians"
      description="People you trust to confirm it is you if you are ever locked out. You will get a link for each of them to send on yourself."
      maxWidth="lg"
    >
      <form
        noValidate
        className="flex flex-col gap-lg"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <p className="text-caption text-ash">
          {existingCount > 0
            ? `You have ${existingCount} already. You can add ${remaining} more.`
            : `Add up to ${remaining}. Recovery will need more than half of them to agree, so two is the smallest number worth having.`}
        </p>

        <ul className="flex flex-col gap-md">
          {drafts.map((row, index) => (
            <li key={row.key} className="flex flex-wrap items-end gap-sm">
              <div className="min-w-0 flex-1 basis-[9rem]">
                <FormField label={`Guardian ${index + 1}`}>
                  <Input
                    value={row.name}
                    placeholder="Their name"
                    autoComplete="off"
                    disabled={isWorking}
                    onChange={(event) => editRow(row.key, "name", event.target.value)}
                  />
                </FormField>
              </div>
              <div className="min-w-0 flex-1 basis-[13rem]">
                <FormField label="Email">
                  <Input
                    type="email"
                    value={row.email}
                    placeholder="them@example.com"
                    autoComplete="off"
                    leftIcon={<MailIcon variant="line" size={14} />}
                    disabled={isWorking}
                    onChange={(event) => editRow(row.key, "email", event.target.value)}
                  />
                </FormField>
              </div>
              {/* Only from the second row down. A remove button on a sole row would
                  empty the form with no way to get a row back except reopening. */}
              {drafts.length > 1 ? (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  aria-label={`Remove guardian ${index + 1}`}
                  disabled={isWorking}
                  onClick={() => removeRow(row.key)}
                >
                  <TrashIcon variant="line" size={14} />
                </Button>
              ) : null}
            </li>
          ))}
        </ul>

        {drafts.length < remaining ? (
          <div>
            <Button type="button" variant="secondary" size="sm" disabled={isWorking} onClick={addRow}>
              <PlusIcon variant="line" size={14} />
              Add another
            </Button>
          </div>
        ) : null}

        {message ? <p className="text-body-sm text-accent-red">{message}</p> : null}

        <div className="flex justify-end gap-sm">
          <Button type="button" variant="ghost" disabled={isWorking} onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" isLoading={isWorking}>
            {drafts.length === 1 ? "Create the link" : "Create the links"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
