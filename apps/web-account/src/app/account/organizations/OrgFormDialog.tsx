"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Button, Dialog, FormField, Input, InfoIcon } from "@authn/ui";
import { AuthnErrorCode, type AuthnError } from "@authn/js";
import { presentSaveError } from "@/lib/authError";

/**
 * Authn Platform — Organization name and slug
 * File: apps/web-account/src/app/account/organizations/OrgFormDialog.tsx
 *
 * Creating a workspace and renaming one take the same two fields, so they are the
 * same dialog with a different verb. Splitting them would put the slug rules — which
 * are the only fiddly part — in two places to drift apart.
 *
 * The slug is offered rather than demanded. Left empty on creation the engine derives
 * one from the name, which is right nearly always; the field exists because the
 * derived form of "Ada & Co." is not something a reader would predict, and it ends up
 * in links.
 */

/** Bounds from `internal/org/types.go`, checked here so a slip is answered without a round trip. */
const MIN_NAME = 2;
const MAX_NAME = 100;
const MIN_SLUG = 2;
const MAX_SLUG = 50;

/** `SlugRegex` from the same file: lowercase alphanumeric segments joined by single hyphens. */
const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export interface OrgFormDialogProps {
  isOpen: boolean;
  onClose: () => void;
  mode: "create" | "rename";
  /** Prefilled on rename, so the reader edits what is there rather than retyping it. */
  initialName?: string;
  initialSlug?: string;
  /** Resolves to an error to keep the dialog open, or null once it has been saved. */
  onSubmit: (values: { name: string; slug: string }) => Promise<AuthnError | null>;
}

export function OrgFormDialog({
  isOpen,
  onClose,
  mode,
  initialName = "",
  initialSlug = "",
  onSubmit,
}: OrgFormDialogProps): ReactNode {
  const [name, setName] = useState(initialName);
  const [slug, setSlug] = useState(initialSlug);
  const [message, setMessage] = useState<string | null>(null);
  const [isWorking, setIsWorking] = useState(false);

  // Reset on open rather than on close: a dialog cleared on the way out flashes its
  // emptied fields during the closing transition.
  useEffect(() => {
    if (!isOpen) return;
    setName(initialName);
    setSlug(initialSlug);
    setMessage(null);
    setIsWorking(false);
  }, [initialName, initialSlug, isOpen]);

  const isRenaming = mode === "rename";

  const submit = useCallback(async () => {
    const trimmedName = name.trim();
    const trimmedSlug = slug.trim().toLowerCase();

    if (trimmedName.length < MIN_NAME || trimmedName.length > MAX_NAME) {
      setMessage(`A name has to be between ${MIN_NAME} and ${MAX_NAME} characters.`);
      return;
    }
    if (trimmedSlug !== "") {
      if (trimmedSlug.length < MIN_SLUG || trimmedSlug.length > MAX_SLUG) {
        setMessage(`A slug has to be between ${MIN_SLUG} and ${MAX_SLUG} characters.`);
        return;
      }
      if (!SLUG_PATTERN.test(trimmedSlug)) {
        setMessage(
          "A slug can hold lowercase letters, digits and single hyphens between them — nothing else, and not at either end.",
        );
        return;
      }
    }
    if (isRenaming && trimmedName === initialName && trimmedSlug === initialSlug) {
      setMessage("Nothing has changed yet.");
      return;
    }

    setIsWorking(true);
    setMessage(null);
    const error = await onSubmit({ name: trimmedName, slug: trimmedSlug });
    setIsWorking(false);

    if (!error) return;

    // A taken slug is the one refusal that names the field to fix, so it is worded
    // here rather than through the shared presenter's generic advice.
    //
    // `EMAIL_ALREADY_EXISTS` despite there being no email in sight: the SDK maps the
    // engine's one `already_exists` code onto that name, and the engine sends it for
    // a slug collision too.
    if (error.code === AuthnErrorCode.EMAIL_ALREADY_EXISTS) {
      setMessage(
        "Another workspace in your tenant already uses that slug. Pick a different one.",
      );
      return;
    }
    setMessage(presentSaveError(error, "this organization"));
  }, [initialName, initialSlug, isRenaming, name, onSubmit, slug]);

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title={isRenaming ? "Rename this organization" : "Create an organization"}
      description={
        isRenaming
          ? "The name is what everyone sees. The slug is what appears in links, so changing it can break ones already shared."
          : "A shared workspace with its own members and roles. You become its first administrator."
      }
      maxWidth="md"
    >
      <form
        noValidate
        className="flex flex-col gap-lg"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <FormField
          label="Name"
          isRequired
          hint="What the workspace is called. Change it whenever you like."
        >
          <Input
            value={name}
            maxLength={MAX_NAME}
            placeholder="Acme Inc"
            autoComplete="off"
            autoFocus
            disabled={isWorking}
            onChange={(event) => {
              setName(event.target.value);
              setMessage(null);
            }}
          />
        </FormField>

        <FormField
          label={isRenaming ? "Slug" : "Slug (optional)"}
          hint={
            isRenaming
              ? "Has to be unique in your tenant."
              : "Leave it empty and we build one from the name."
          }
        >
          <Input
            value={slug}
            maxLength={MAX_SLUG}
            placeholder="acme"
            autoComplete="off"
            isMonospace
            disabled={isWorking}
            /* Folded as it is typed, matching what the engine stores. Letting a
               capital through and lowercasing it on submit shows the reader one
               value and saves another. */
            onChange={(event) => {
              setSlug(event.target.value.toLowerCase());
              setMessage(null);
            }}
          />
        </FormField>

        {isRenaming ? (
          <div className="flex items-start gap-sm rounded-md border border-hairline bg-surface-elevated p-md">
            <InfoIcon variant="line" size={16} className="mt-px shrink-0 text-ash" />
            <p className="text-caption text-charcoal">
              Existing members are unaffected — they stay in the workspace with the roles
              they hold. Only the name and the slug change.
            </p>
          </div>
        ) : null}

        {message ? <p className="text-body-sm text-accent-red">{message}</p> : null}

        <div className="flex justify-end gap-sm">
          <Button type="button" variant="ghost" disabled={isWorking} onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" isLoading={isWorking}>
            {isRenaming ? "Save changes" : "Create it"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
