"use client";

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import {
  AtSignIcon,
  Avatar,
  Badge,
  Button,
  CameraIcon,
  Dialog,
  FormField,
  GlobeIcon,
  Input,
  MailIcon,
  UserIcon,
  useToast,
} from "@authn/ui";
import { useAuth, useUsernameAvailability } from "@authn/react";
import {
  USERNAME_RULE_HINT,
  checkUsernameFormat,
  type AuthnProfile,
  type UpdateProfileParams,
} from "@authn/js";
import { EditableRow, type SaveOutcome } from "@/components/EditableRow";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { LoadError, RowSkeleton } from "@/components/CardState";
import { SettingsCard, SettingsRow } from "@/components/SettingsCard";
import { presentSaveError } from "@/lib/authError";
import { formatDate } from "@/lib/datetime";
import { useResource, type ResourceResult } from "@/lib/useResource";
import { byteLength } from "@/lib/text";

/**
 * Authn Platform — Profile page body
 * File: apps/web-account/src/app/account/ProfileCards.tsx
 *
 * Everything on the profile page that needs the engine: one read of
 * `GET /v1/client/user/profile`, and a write per row.
 *
 * A row at a time rather than a page-level Save, for a reason that is as much
 * about errors as about layout. `PATCH /v1/client/user/profile` answers a bad
 * name, a bad locale and a bad avatar URL with the same 400 and the same sentence
 * — "one or more fields are invalid" — so the only thing in the browser that knows
 * which field was refused is the control that sent it. Batch four fields into one
 * request and the refusal can be attached to nothing.
 *
 * The 255 on a display name is in bytes, matching the engine, which measures with
 * Go's `len`. A limit stated in characters and enforced in bytes is a limit that
 * moves depending on the alphabet.
 */

/** The engine's ceiling on a display name, in UTF-8 bytes. */
const MAX_NAME_BYTES = 255;

/** `SanitizeString(locale, 2, 20)` in the engine, also bytes. */
const MIN_LOCALE_BYTES = 2;
const MAX_LOCALE_BYTES = 20;

export function ProfileCards(): ReactNode {
  const { client, isAuthenticated } = useAuth();
  const toast = useToast();

  const load = useCallback(async (): Promise<ResourceResult<AuthnProfile>> => {
    const result = await client.getProfile();
    return result.ok ? { ok: true, data: result.profile } : { ok: false, error: result.error };
  }, [client]);

  // Held back until the provider's refresh call has settled. A read fired on the
  // first render goes out with no access token and comes back 401, which would
  // render as "could not load your profile" on a page that was merely early.
  const { data: profile, error, isLoading, isRefetching, refetch, mutate } = useResource(load, {
    enabled: isAuthenticated,
  });

  const [isChangingEmail, setIsChangingEmail] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [isRemovingRecovery, setIsRemovingRecovery] = useState(false);

  /**
   * Sends one field and reports back in the shape `EditableRow` expects.
   *
   * The response body is the whole updated profile, so it is written straight into
   * the cache rather than triggering a re-read: the new value is already in hand,
   * and spending a round trip to fetch what was just returned shows the reader the
   * old value for the length of it.
   */
  const saveField = useCallback(
    async (
      params: UpdateProfileParams,
      subject: string,
      confirmation: string,
    ): Promise<SaveOutcome> => {
      const result = await client.updateProfile(params);
      if (!result.ok) {
        return { ok: false, message: presentSaveError(result.error, subject) };
      }

      mutate(result.profile);
      toast.success(confirmation);
      return { ok: true };
    },
    [client, mutate, toast],
  );

  const resendPrimaryVerification = useCallback(async () => {
    if (!profile) return;

    setIsResending(true);
    const result = await client.resendVerification({ email: profile.email });
    setIsResending(false);

    if (!result.ok) {
      toast.error("Could not send the link", presentSaveError(result.error, "email address"));
      return;
    }
    toast.success("Verification link sent", `Open the link in the message we sent to ${profile.email}.`);
  }, [client, profile, toast]);

  const removeRecoveryEmail = useCallback(async () => {
    setIsRemovingRecovery(true);
    const result = await client.deleteRecoveryEmail();
    setIsRemovingRecovery(false);

    if (!result.ok) {
      toast.error("Could not remove it", presentSaveError(result.error, "recovery email"));
      return;
    }

    // A re-read rather than a local write: this endpoint answers with a message
    // and not a profile, so the only way to be sure what the account now holds is
    // to ask.
    toast.success("Recovery email removed");
    await refetch();
  }, [client, refetch, toast]);

  const displayName = profile?.name ?? profile?.username ?? profile?.email ?? "";

  return (
    <div className="mx-auto flex w-full max-w-page flex-col gap-xl px-lg py-xxl sm:px-xl">
      <SettingsCard
        title="Identity"
        description="How you appear across Authn and to anyone you share an organization with."
        footer={
          profile ? (
            <p className="text-caption text-ash">
              Account created {formatDate(profile.createdAt)}.
            </p>
          ) : undefined
        }
      >
        {isLoading ? (
          <RowSkeleton rows={3} hasIcon label="your profile" />
        ) : !profile ? (
          <LoadError
            label="your profile"
            message={error?.message}
            onRetry={() => void refetch()}
            isRetrying={isRefetching}
          />
        ) : (
          <>
            <EditableRow
              label="Avatar"
              value={profile.avatarUrl ?? null}
              emptyText="Drawn from your initials"
              hint="A link to an image on the web. There is nowhere to upload a file yet, and clearing the field goes back to your initials."
              /* The picture rather than a plaque: what a reader is checking here is
                 whether the image is the right one, and the URL in the field does
                 not tell them that. */
              leading={<Avatar size="lg" src={profile.avatarUrl} name={displayName} />}
              icon={CameraIcon}
              inputType="url"
              isMonospace
              canClear
              placeholder="https://example.com/photo.jpg"
              onSave={(next) =>
                saveField({ avatarUrl: next }, "avatar", next === "" ? "Avatar removed" : "Avatar updated")
              }
            />

            <EditableRow
              label="Display name"
              value={profile.name ?? null}
              emptyText="No name set"
              hint="Shown on invitations and in member lists."
              icon={UserIcon}
              autoComplete="name"
              validate={(next) =>
                byteLength(next) > MAX_NAME_BYTES
                  ? "That name is too long. Keep it under 255 bytes — accented and non-Latin letters take more than one each."
                  : null
              }
              onSave={(next) => saveField({ name: next }, "display name", "Display name saved")}
            />

            {/* The one field on this page that is globally unique, which is why it
                is the only one with a live check and a set of alternatives. */}
            <EditableRow
              label="Username"
              value={profile.username ?? null}
              emptyText="No username claimed"
              hint={
                profile.username
                  ? `Sign in with @${profile.username} instead of your email. ${USERNAME_RULE_HINT}.`
                  : `Claim one and you can sign in with it instead of your email. ${USERNAME_RULE_HINT}.`
              }
              helpTopic="username"
              icon={AtSignIcon}
              isMonospace
              canClear
              autoComplete="username"
              placeholder="alexsmith"
              /* The shape rules are shared with the engine, so a handle that breaks
                 one is refused here and costs no round trip. Whether it is *taken*
                 cannot be answered locally and is left to the assist below and, in
                 the end, to the save. */
              validate={(next) => checkUsernameFormat(next).message ?? null}
              renderAssist={(draft) => <UsernameAssist draft={draft} current={profile.username} />}
              onSave={(next) =>
                saveField(
                  { username: next },
                  "username",
                  next === "" ? "Username released" : `Username set to @${next}`,
                )
              }
            />
          </>
        )}
      </SettingsCard>

      <SettingsCard
        title="Email"
        description="Where verification links, security notices and sign-in links are sent."
        footer={<HelpText topic="emailChange" />}
      >
        {isLoading ? (
          <RowSkeleton rows={2} hasIcon label="your email addresses" />
        ) : !profile ? (
          <LoadError
            label="your email addresses"
            message={error?.message}
            onRetry={() => void refetch()}
            isRetrying={isRefetching}
          />
        ) : (
          <>
            <SettingsRow
              label="Primary email"
              value={<span className="font-mono">{profile.email}</span>}
              hint={
                profile.emailVerified
                  ? "Used to sign in. A change is confirmed from the new address before anything moves."
                  : "Not confirmed yet. Until it is, this address cannot receive a sign-in link."
              }
              icon={MailIcon}
              accent={profile.emailVerified ? "green" : "yellow"}
              action={
                <>
                  <Badge variant={profile.emailVerified ? "green" : "yellow"} dot>
                    {profile.emailVerified ? "verified" : "unverified"}
                  </Badge>
                  <InfoHint topic="emailChange" label="changing your email" />
                  {!profile.emailVerified && (
                    <Button
                      size="sm"
                      variant="ghost"
                      isLoading={isResending}
                      onClick={() => void resendPrimaryVerification()}
                    >
                      Resend link
                    </Button>
                  )}
                  <Button size="sm" variant="secondary" onClick={() => setIsChangingEmail(true)}>
                    Change
                  </Button>
                </>
              }
            />

            {/* An `EditableRow` and not a dialog, unlike the primary address above:
                setting this one takes effect immediately — as unverified — so the
                row can show the result, where a primary change shows nothing until
                a link in another mailbox is opened. */}
            <EditableRow
              label="Recovery email"
              value={profile.recoveryEmail ?? null}
              emptyText="No recovery email"
              hint={
                !profile.recoveryEmail
                  ? "A second address, used only if you lose access to your main one. It can never be used to sign in."
                  : profile.recoveryEmailVerified
                    ? "Confirmed. It can be used to prove it is you if you lose access to your main address."
                    : "Saved, but not confirmed. Open the link we sent there — until you do, it cannot be used for recovery."
              }
              helpTopic="recoveryEmail"
              icon={MailIcon}
              accent={profile.recoveryEmail && !profile.recoveryEmailVerified ? "yellow" : undefined}
              inputType="email"
              autoComplete="email"
              placeholder="you@personal.example"
              onSave={async (next) => {
                const result = await client.setRecoveryEmail(next);
                if (!result.ok) {
                  return { ok: false, message: presentSaveError(result.error, "recovery email") };
                }
                toast.success("Recovery email saved", `Confirm it from the link we sent to ${next}.`);
                await refetch();
                return { ok: true };
              }}
              extraAction={
                profile.recoveryEmail ? (
                  <Button
                    size="sm"
                    variant="ghost"
                    isLoading={isRemovingRecovery}
                    onClick={() => void removeRecoveryEmail()}
                  >
                    Remove
                  </Button>
                ) : undefined
              }
            />
          </>
        )}
      </SettingsCard>

      <SettingsCard title="Preferences" description="Applied to the language of the emails we send.">
        {isLoading ? (
          <RowSkeleton rows={1} hasIcon label="your preferences" />
        ) : !profile ? (
          <LoadError
            label="your preferences"
            message={error?.message}
            onRetry={() => void refetch()}
            isRetrying={isRefetching}
          />
        ) : (
          <EditableRow
            label="Language"
            value={profile.locale ?? null}
            emptyText="Not set — emails come in English"
            hint="A language tag such as en-GB or fr. It travels with your account, so it is the same wherever you sign in."
            icon={GlobeIcon}
            isMonospace
            placeholder="en-GB"
            validate={(next) =>
              byteLength(next) < MIN_LOCALE_BYTES || byteLength(next) > MAX_LOCALE_BYTES
                ? "Use a language tag between 2 and 20 characters, such as en or en-GB."
                : null
            }
            onSave={(next) => saveField({ locale: next }, "language", "Language saved")}
          />
        )}
      </SettingsCard>

      {profile && (
        <EmailChangeDialog
          isOpen={isChangingEmail}
          currentEmail={profile.email}
          onClose={() => setIsChangingEmail(false)}
        />
      )}
    </div>
  );
}

/**
 * The live verdict on a handle being typed into the username row.
 *
 * Its own component rather than a body inside `renderAssist`, because it calls a
 * hook: a callback invoked during another component's render is not a component,
 * so React has nowhere to keep the hook's state. Mounting it as a child gives it
 * one, and the debounce timer inside it survives the parent's keystroke renders.
 */
function UsernameAssist({
  draft,
  current,
}: {
  draft: string;
  current: string | undefined;
}): ReactNode {
  const { status, message, suggestions, canonical } = useUsernameAvailability(draft);

  const trimmed = draft.trim();

  // Nothing to say about an empty field — clearing the handle is a legitimate save
  // and the row's own copy already explains it — nor about the handle the account
  // already holds, which the availability endpoint would report as taken by the
  // person asking.
  if (trimmed === "") return null;
  if (canonical !== null && current !== undefined && canonical === current.toLowerCase()) {
    return <span className="text-caption text-mute">This is your current username.</span>;
  }

  // A shape failure is the row's own error, put there by `validate` on submit.
  // Repeating it here would read as two separate problems with one handle.
  if (status === "invalid") return null;

  const isFolded = canonical !== null && canonical !== trimmed;

  return (
    <div className="flex flex-col gap-xs">
      <span
        role="status"
        aria-live="polite"
        className={
          status === "available"
            ? "text-caption text-accent-green"
            : status === "unavailable"
              ? "text-caption text-accent-red"
              : status === "error"
                ? "text-caption text-accent-yellow"
                : "text-caption text-mute"
        }
      >
        {status === "checking"
          ? "Checking availability…"
          : status === "available"
            ? isFolded
              ? `Available, and saved as @${canonical}.`
              : "Available."
            : status === "unavailable"
              ? (message ?? "That username is taken.")
              : status === "error"
                ? "Could not check this one right now. You can still save it."
                : ""}
      </span>

      {status === "unavailable" && suggestions.length > 0 && (
        <span className="text-caption text-mute">
          Free instead: {suggestions.map((option) => `@${option}`).join(", ")}
        </span>
      )}
    </div>
  );
}

/**
 * Changing the primary address, in a dialog.
 *
 * A dialog and not an in-place row, because this is the one field on the page whose
 * save changes nothing visible: the engine mails a link to the *new* address and the
 * account keeps the old one until that link is opened. A row that closed and went on
 * showing the previous value would read as a save that silently failed. The dialog
 * has room to say what actually happened, and stays open to say it.
 */
function EmailChangeDialog({
  isOpen,
  currentEmail,
  onClose,
}: {
  isOpen: boolean;
  currentEmail: string;
  onClose: () => void;
}): ReactNode {
  const { client } = useAuth();

  const [draft, setDraft] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [isSending, setIsSending] = useState(false);
  const [sentTo, setSentTo] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  /**
   * Reset on open, not on close. Clearing on close would empty the fields while
   * the dialog is still fading out, and the reader watches their own address
   * disappear from the confirmation they were reading.
   */
  useEffect(() => {
    if (!isOpen) return;
    setDraft("");
    setMessage(null);
    setSentTo(null);
    setIsSending(false);
    inputRef.current?.focus();
  }, [isOpen]);

  const submit = useCallback(async () => {
    const next = draft.trim();

    if (next === "") {
      setMessage("Enter the address you want to move to.");
      return;
    }
    if (next.toLowerCase() === currentEmail.toLowerCase()) {
      setMessage("That is already your email address.");
      return;
    }

    setIsSending(true);
    setMessage(null);
    const result = await client.requestEmailChange(next);
    setIsSending(false);

    if (!result.ok) {
      setMessage(presentSaveError(result.error, "email address"));
      inputRef.current?.focus();
      return;
    }

    setSentTo(next);
  }, [client, currentEmail, draft]);

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title={sentTo ? "Confirm the new address" : "Change your email address"}
      description={
        sentTo
          ? undefined
          : `Your account currently uses ${currentEmail}. Nothing changes until the new address is confirmed.`
      }
    >
      {sentTo ? (
        <div className="flex flex-col gap-md">
          <p className="text-body-sm text-charcoal">
            We sent a confirmation link to <span className="font-mono text-ink">{sentTo}</span>. Open
            it from that mailbox and your account moves across.
          </p>
          <p className="text-caption text-ash">
            Until then <span className="font-mono">{currentEmail}</span> keeps working, and it is
            still the address you sign in with. The link expires, so a change started by mistake
            needs no undoing.
          </p>
          <div className="flex justify-end">
            <Button variant="primary" onClick={onClose}>
              Done
            </Button>
          </div>
        </div>
      ) : (
        /* The form element is what makes Enter send. The buttons are inside it
           rather than in the dialog's footer slot for the same reason: a submit
           button outside its form is an ordinary button. */
        <form
          noValidate
          className="flex flex-col gap-lg"
          onSubmit={(event) => {
            event.preventDefault();
            void submit();
          }}
        >
          <FormField label="New email address" isRequired error={message ?? undefined}>
            <Input
              ref={inputRef}
              type="email"
              value={draft}
              autoComplete="email"
              autoCapitalize="none"
              spellCheck={false}
              placeholder="you@company.com"
              disabled={isSending}
              onChange={(event) => {
                setDraft(event.target.value);
                if (message) setMessage(null);
              }}
            />
          </FormField>

          <div className="flex justify-end gap-sm">
            <Button type="button" variant="ghost" disabled={isSending} onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" isLoading={isSending}>
              Send confirmation link
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
