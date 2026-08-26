"use client";

import { useCallback, useMemo, useState, type ReactNode } from "react";
import {
  Badge,
  BackupCodesIcon,
  Button,
  Dialog,
  KeyIcon,
  MailIcon,
  PhoneIcon,
  UsersIcon,
  useToast,
  type IconComponent,
} from "@authn/ui";
import { useAppConfig, useAuth } from "@authn/react";
import {
  AuthnErrorCode,
  type AuthnGuardian,
  type AuthnProfile,
  type RecoveryCodesStatus,
  type SecurityQuestion,
} from "@authn/js";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { LoadError, RowSkeleton } from "@/components/CardState";
import { RecoveryCodesPanel } from "@/components/RecoveryCodesPanel";
import { SettingsCard, SettingsRow } from "@/components/SettingsCard";
import { StepUpDialog, type StepUpFactor } from "@/components/StepUpDialog";
import { EditableRow, type SaveOutcome } from "@/components/EditableRow";
import { GuardianInviteDialog } from "./GuardianInviteDialog";
import { SecurityQuestionsDialog } from "./SecurityQuestionsDialog";
import { presentSaveError } from "@/lib/authError";
import { formatDate } from "@/lib/datetime";
import { useResource, type ResourceResult } from "@/lib/useResource";

/**
 * Authn Platform — Recovery page body
 * File: apps/web-account/src/app/account/recovery/RecoveryCards.tsx
 *
 * Four reads — the profile, the recovery-code count, the guardian roster and the
 * security questions — and every control the account's ways back in have.
 *
 * The page's job is to say truthfully which of them would actually work. That is
 * not the same as which ones exist: a guardian who has not accepted their invitation
 * is not counted by `InitiateRecovery`, an unverified second address is ignored, and
 * a phone number is only a route if it was confirmed. So each row states the
 * condition rather than the setting, and the tally at the top counts what recovery
 * would offer today.
 *
 * Two things the page deliberately does not do. It does not display a set of
 * recovery codes it was not just handed — there is no endpoint that returns existing
 * ones, so a list rendered from anywhere but a regeneration response would be
 * invented. And it does not claim the recovery address receives a code: today the
 * engine's `email_otp` goes to the primary address, and the second one is a way to
 * be reached rather than a proof.
 */

/** One dialog at a time, carrying what it cannot act without. */
type Modal =
  | null
  | { kind: "codes-regenerate" }
  | { kind: "codes-show"; codes: string[] }
  | { kind: "guardians-invite" }
  | { kind: "guardian-revoke"; guardian: AuthnGuardian }
  | { kind: "questions-set" }
  | { kind: "questions-remove" };

/** A guardian counts towards recovery only once they have opened their link. */
function isAccepted(guardian: AuthnGuardian): boolean {
  return guardian.status === "active" || guardian.status === "accepted";
}

/**
 * One row of the overview, and one entry in its tally.
 *
 * The two are the same list so they cannot drift. `unreadyLabel` varies per option
 * because the reason differs: a phone is "Not set up" until one is added, while an
 * address the account already has is "Not confirmed".
 */
interface RecoveryOption {
  key: string;
  label: string;
  icon: IconComponent;
  value: string;
  hint: string;
  isReady: boolean;
  unreadyLabel: string;
}

/**
 * The number of guardians who would have to agree, which is a majority.
 *
 * Mirrors `CalculateThreshold` in the engine. Shown rather than left implicit
 * because one guardian is a majority of one — the person could act alone — and a
 * reader who was told "several have to agree" would not know that.
 */
function threshold(accepted: number): number {
  return Math.floor(accepted / 2) + 1;
}

export function RecoveryCards(): ReactNode {
  const { client, isAuthenticated } = useAuth();
  const { config } = useAppConfig();
  const toast = useToast();

  const loadProfile = useCallback(async (): Promise<ResourceResult<AuthnProfile>> => {
    const result = await client.getProfile();
    return result.ok ? { ok: true, data: result.profile } : { ok: false, error: result.error };
  }, [client]);

  const loadCodes = useCallback(async (): Promise<ResourceResult<RecoveryCodesStatus>> => {
    const result = await client.getRecoveryCodesStatus();
    return result.ok ? { ok: true, data: result.status } : { ok: false, error: result.error };
  }, [client]);

  const loadGuardians = useCallback(async (): Promise<ResourceResult<AuthnGuardian[]>> => {
    const result = await client.listGuardians();
    return result.ok ? { ok: true, data: result.guardians } : { ok: false, error: result.error };
  }, [client]);

  const loadQuestions = useCallback(async (): Promise<ResourceResult<SecurityQuestion[]>> => {
    const result = await client.getSecurityQuestions();
    if (result.ok) return { ok: true, data: result.questions };
    // 404 is the engine's way of saying "this factor is not set up", which is an
    // answer and not a failure. Reported as an empty roster so the card renders its
    // empty state instead of "could not load your security questions".
    if (result.error.code === AuthnErrorCode.NOT_FOUND) return { ok: true, data: [] };
    return { ok: false, error: result.error };
  }, [client]);

  // Held until the provider's refresh has settled, or all four go out with no access
  // token and the page renders as four failures.
  const profile = useResource(loadProfile, { enabled: isAuthenticated });
  const codes = useResource(loadCodes, { enabled: isAuthenticated });
  const guardians = useResource(loadGuardians, { enabled: isAuthenticated });
  const questions = useResource(loadQuestions, { enabled: isAuthenticated });

  const [modal, setModal] = useState<Modal>(null);
  const close = useCallback(() => setModal(null), []);

  const recoveryOptions = config?.accountRecovery;
  const maxGuardians = recoveryOptions?.maxGuardians ?? 5;

  /* Which credential a step-up will be checked on. The engine decides this from the
     account, not from the request: one holding a password is checked on it and only
     one holding none falls through to TOTP. Asking for the wrong thing costs a
     refused request and a second dialog for something the person never set. */
  const factor: StepUpFactor = profile.data?.hasPassword === false ? "totp" : "password";

  const acceptedGuardians = useMemo(
    () => (guardians.data ?? []).filter(isAccepted),
    [guardians.data],
  );
  const pendingGuardians = useMemo(
    () => (guardians.data ?? []).filter((guardian) => !isAccepted(guardian)),
    [guardians.data],
  );

  /**
   * The password-recovery methods this deployment can actually offer, and whether
   * each one would work right now.
   *
   * The tally and the rows are the same list on purpose. Counting one set and
   * rendering another is how a page ends up saying "1 of 3" above four rows, and
   * the extra row is always the one telling someone to go configure a method the
   * engine will never accept.
   *
   * A method the tenant has switched off is left out entirely rather than shown as
   * unfinished work. `phone_otp` in particular is `PhoneOTPEnabled && smsDeliverable`
   * in the engine, so a deployment with no SMS driver reports it off — and a row
   * saying "add a number to use this" would be an instruction that leads nowhere.
   *
   * Recovery codes are not here. They are checked at a sign-in that is already
   * going — the second-factor prompt — so they need the password that is still
   * known. `POST /auth/recovery/initiate` does not offer them, and a tally that
   * counted them would tell someone with a printed sheet and nothing else that they
   * are covered for losing their password. They are not.
   *
   * Readiness matches what `InitiateRecovery` would offer, under its conditions:
   * only accepted guardians, only a confirmed phone, only a confirmed address.
   * Something configured but not yet usable does not count — a reader told they
   * have four ways in when they have one finds out at the worst moment.
   */
  const options = useMemo(() => {
    const rows: RecoveryOption[] = [];

    if (recoveryOptions?.guardians !== false) {
      rows.push({
        key: "guardians",
        label: "Guardians",
        icon: UsersIcon,
        value: describeGuardians(acceptedGuardians.length, pendingGuardians.length),
        hint:
          acceptedGuardians.length > 0
            ? `${threshold(acceptedGuardians.length)} of your ${acceptedGuardians.length} would have to agree.`
            : "People you trust to confirm it is you.",
        isReady: acceptedGuardians.length > 0,
        unreadyLabel: "Not set up",
      });
    }
    if (recoveryOptions?.phoneOtp !== false) {
      rows.push({
        key: "phone",
        label: "Confirmed phone",
        icon: PhoneIcon,
        value: profile.data?.phoneNumber ?? "No number",
        hint: profile.data?.phoneVerified
          ? "A code can be sent here."
          : "Add and confirm a number on the Security page to use this.",
        isReady: profile.data?.phoneVerified === true,
        unreadyLabel: "Not set up",
      });
    }
    if (recoveryOptions?.emailOtp !== false) {
      rows.push({
        key: "email",
        label: "Confirmed email",
        icon: MailIcon,
        value: profile.data?.email ?? "—",
        hint: profile.data?.emailVerified
          ? "A code is sent to your main address, not to your recovery address."
          : "Confirm your main address to use this.",
        isReady: profile.data?.emailVerified === true,
        unreadyLabel: "Not confirmed",
      });
    }
    if (recoveryOptions?.securityQuestions !== false) {
      const count = (questions.data ?? []).length;
      rows.push({
        key: "questions",
        label: "Security questions",
        icon: KeyIcon,
        value: count > 0 ? `${count} questions set` : "None set",
        hint: "A last resort, used when nothing else is left.",
        isReady: count > 0,
        unreadyLabel: "Not set up",
      });
    }

    return rows;
  }, [
    acceptedGuardians.length,
    pendingGuardians.length,
    profile.data,
    questions.data,
    recoveryOptions,
  ]);

  const readyCount = options.filter((option) => option.isReady).length;

  const isOverviewLoading =
    profile.isLoading || guardians.isLoading || questions.isLoading;

  const regenerateCodes = useCallback(
    async (credential: string) => {
      const result = await client.regenerateRecoveryCodes(
        factor === "password" ? { password: credential } : { totpCode: credential },
      );
      if (!result.ok) return result.error;

      // Straight to the new set, without closing first. This response is the only
      // place the codes exist as text, so dismissing the dialog to open another one
      // would be dropping them.
      setModal({ kind: "codes-show", codes: result.recoveryCodes });
      void codes.refetch();
      return null;
    },
    [client, codes, factor],
  );

  const inviteGuardians = useCallback(
    async (roster: { name: string; email: string }[]) => {
      const result = await client.inviteGuardians({ guardians: roster });
      if (!result.ok) return { ok: false as const, error: result.error };

      void guardians.refetch();
      // Only the invites, which are already scoped to the guardians this call created
      // and already name the person each one belongs to. The roster in the same reply
      // is not needed here: pairing links to people by position is how a reader ends up
      // sending one guardian another guardian's code.
      return { ok: true as const, invites: result.invites };
    },
    [client, guardians],
  );

  const revokeGuardian = useCallback(async () => {
    if (modal?.kind !== "guardian-revoke") return null;
    const result = await client.revokeGuardian(modal.guardian.id);
    if (!result.ok) return result.error;

    close();
    void guardians.refetch();
    toast.success(
      "Guardian removed",
      acceptedGuardians.length > 1
        ? `${modal.guardian.guardianName} can no longer help you recover this account. Your other guardians keep the codes they already have and do not need to do anything.`
        : `${modal.guardian.guardianName} can no longer help you recover this account.`,
    );
    return null;
  }, [acceptedGuardians.length, client, close, guardians, modal, toast]);

  const saveQuestions = useCallback(
    async (roster: { question: string; answer: string }[], credential: string) => {
      const result = await client.setSecurityQuestions({
        questions: roster,
        ...(factor === "password" ? { password: credential } : { totpCode: credential }),
      });
      if (!result.ok) return result.error;

      close();
      void questions.refetch();
      toast.success(
        "Security questions saved",
        `Recovery will ask for all ${roster.length} answers. Nobody, including us, can read them back.`,
      );
      return null;
    },
    [client, close, factor, questions, toast],
  );

  const removeQuestions = useCallback(
    async (credential: string) => {
      const result = await client.deleteSecurityQuestions(
        factor === "password" ? { password: credential } : { totpCode: credential },
      );
      if (!result.ok) return result.error;

      close();
      void questions.refetch();
      toast.success(
        "Security questions removed",
        "They can no longer be used to recover this account.",
      );
      return null;
    },
    [client, close, factor, questions, toast],
  );

  const saveRecoveryEmail = useCallback(
    async (next: string): Promise<SaveOutcome> => {
      const result = await client.setRecoveryEmail(next);
      if (!result.ok) return { ok: false, message: presentSaveError(result.error, "recovery email") };

      void profile.refetch();
      toast.success(
        "Check that inbox",
        `We sent a confirmation link to ${next}. It only becomes usable once that link is opened.`,
      );
      return { ok: true };
    },
    [client, profile, toast],
  );

  const removeRecoveryEmail = useCallback(async () => {
    const result = await client.deleteRecoveryEmail();
    if (!result.ok) {
      toast.error("Could not remove it", presentSaveError(result.error, "recovery email"));
      return;
    }
    void profile.refetch();
    toast.success("Recovery email removed", "That address is no longer linked to this account.");
  }, [client, profile, toast]);

  const recoveryEmail = profile.data?.recoveryEmail ?? null;
  const isRecoveryEmailVerified = profile.data?.recoveryEmailVerified === true;
  const hasQuestions = (questions.data ?? []).length > 0;

  return (
    <div className="mx-auto flex w-full max-w-page flex-col gap-xl px-lg py-xxl sm:px-xl">
      {/* The proofs `POST /auth/recovery/initiate` can offer, in the order it offers
          them. Recovery codes are not among them and are not listed here — they have
          their own card below, because they solve the other problem. */}
      <SettingsCard
        title="If you forget your password"
        description="These are what get you back into a locked-out account. Set up at least two: none of them can be added once you are already locked out."
        action={
          isOverviewLoading ? null : (
            <Badge variant={readyCount >= 2 ? "green" : "yellow"} dot>
              {readyCount} of {options.length} ready
            </Badge>
          )
        }
      >
        {isOverviewLoading ? (
          <RowSkeleton rows={4} hasIcon label="your recovery options" />
        ) : (
          options.map((option) => (
            <SettingsRow
              key={option.key}
              label={option.label}
              icon={option.icon}
              accent="yellow"
              value={option.value}
              hint={option.hint}
              action={
                <Badge variant={option.isReady ? "green" : "gray"}>
                  {option.isReady ? "Ready" : option.unreadyLabel}
                </Badge>
              }
            />
          ))
        )}
      </SettingsCard>

      <SettingsCard
        id="codes"
        title="If you lose your second factor"
        description="Recovery codes stand in for your phone at the second-factor prompt. They need your password, so they are not a way into a forgotten account — they are the way past a lost authenticator."
        action={<InfoHint topic="recoveryCodes" label="recovery codes" position="left" />}
        footer={<HelpText topic="recoveryCodes" />}
      >
        {codes.isLoading ? (
          <RowSkeleton rows={1} hasIcon label="your recovery codes" />
        ) : !codes.data ? (
          <LoadError
            label="your recovery codes"
            message={codes.error?.message}
            isRetrying={codes.isRefetching}
            onRetry={() => void codes.refetch()}
          />
        ) : (
          <SettingsRow
            label="Codes remaining"
            icon={BackupCodesIcon}
            accent="yellow"
            value={describeCodes(codes.data)}
            hint={
              codes.data.hasRecoveryCodes
                ? "Each one works once. Make a new set when you are running low — the old set stops working the moment you do."
                : "Generate a set and keep it somewhere that is not the device holding your second factor."
            }
            action={
              <Button
                variant={codes.data.hasRecoveryCodes ? "secondary" : "primary"}
                size="sm"
                onClick={() => setModal({ kind: "codes-regenerate" })}
              >
                {codes.data.hasRecoveryCodes ? "Replace them" : "Generate codes"}
              </Button>
            }
          />
        )}
      </SettingsCard>

      <SettingsCard
        id="guardians"
        title="Guardians"
        description="People who can vouch for you. You send each of them a link yourself — nothing is emailed on your behalf."
        action={
          <div className="flex items-center gap-sm">
            <InfoHint topic="guardians" label="guardians" position="left" />
            {guardians.data && guardians.data.length < maxGuardians ? (
              <Button
                variant={acceptedGuardians.length > 0 ? "secondary" : "primary"}
                size="sm"
                onClick={() => setModal({ kind: "guardians-invite" })}
              >
                Invite
              </Button>
            ) : null}
          </div>
        }
        footer={<HelpText topic="guardians" />}
      >
        {guardians.isLoading ? (
          <RowSkeleton rows={2} hasIcon label="your guardians" />
        ) : !guardians.data ? (
          <LoadError
            label="your guardians"
            message={guardians.error?.message}
            isRetrying={guardians.isRefetching}
            onRetry={() => void guardians.refetch()}
          />
        ) : guardians.data.length === 0 ? (
          <div className="flex flex-col gap-sm p-lg">
            <p className="text-body-md text-ink">No guardians yet</p>
            <p className="text-body-sm text-charcoal">
              Invite two or more people you can reach without this account. If you are
              ever locked out, more than half of them confirming it is you is what gets
              you back in — so a single guardian is one person who could do it alone.
            </p>
          </div>
        ) : (
          guardians.data.map((guardian) => (
            <SettingsRow
              key={guardian.id}
              label={guardian.guardianName}
              icon={UsersIcon}
              accent={isAccepted(guardian) ? "green" : "yellow"}
              value={guardian.guardianEmail}
              hint={
                isAccepted(guardian)
                  ? `Accepted ${formatDate(guardian.createdAt)}. They hold their own recovery code.`
                  : `Invited ${formatDate(guardian.createdAt)}. They have not opened their link yet, so they do not count towards recovery.`
              }
              action={
                <div className="flex items-center gap-sm">
                  <Badge variant={isAccepted(guardian) ? "green" : "yellow"} dot>
                    {isAccepted(guardian) ? "Accepted" : "Waiting"}
                  </Badge>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setModal({ kind: "guardian-revoke", guardian })}
                  >
                    Remove
                  </Button>
                </div>
              }
            />
          ))
        )}
      </SettingsCard>

      <SettingsCard
        id="questions"
        title="Security questions"
        description="The last resort, for when every other way in is gone. Recovery asks for every answer, not just one."
        action={
          <div className="flex items-center gap-sm">
            <InfoHint topic="securityQuestions" label="security questions" position="left" />
            <Button
              variant={hasQuestions ? "secondary" : "primary"}
              size="sm"
              onClick={() => setModal({ kind: "questions-set" })}
            >
              {hasQuestions ? "Replace" : "Set them up"}
            </Button>
          </div>
        }
        footer={<HelpText topic="securityQuestions" />}
      >
        {questions.isLoading ? (
          <RowSkeleton rows={3} hasIcon label="your security questions" />
        ) : !questions.data ? (
          <LoadError
            label="your security questions"
            message={questions.error?.message}
            isRetrying={questions.isRefetching}
            onRetry={() => void questions.refetch()}
          />
        ) : questions.data.length === 0 ? (
          <div className="flex flex-col gap-sm p-lg">
            <p className="text-body-md text-ink">No questions set</p>
            <p className="text-body-sm text-charcoal">
              Three to five questions only you can answer. Pick facts that will not have
              changed in five years and are not on any profile of yours — a first
              employer rather than a birthplace.
            </p>
          </div>
        ) : (
          <>
            {questions.data.map((question, index) => (
              <SettingsRow
                key={question.id}
                label={`Question ${index + 1}`}
                icon={KeyIcon}
                accent="yellow"
                value={question.question}
                hint={index === 0 ? "Your answers are hashed. Nobody can read them back, including us." : undefined}
                action={
                  index === 0 ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setModal({ kind: "questions-remove" })}
                    >
                      Remove all
                    </Button>
                  ) : undefined
                }
              />
            ))}
          </>
        )}
      </SettingsCard>

      <SettingsCard
        id="recovery-email"
        title="Recovery email"
        description="A second address we can reach you at. Useful when you have lost access to your main one — but confirm it now, while you still can."
        action={<InfoHint topic="recoveryEmail" label="the recovery email" position="left" />}
        footer={<HelpText topic="recoveryEmail" />}
      >
        {profile.isLoading ? (
          <RowSkeleton rows={1} hasIcon label="your recovery email" />
        ) : !profile.data ? (
          <LoadError
            label="your recovery email"
            message={profile.error?.message}
            isRetrying={profile.isRefetching}
            onRetry={() => void profile.refetch()}
          />
        ) : (
          <EditableRow
            label="Second address"
            value={recoveryEmail}
            emptyText="No second address"
            icon={MailIcon}
            accent="yellow"
            inputType="email"
            placeholder="you@another-provider.com"
            autoComplete="email"
            hint={
              recoveryEmail === null
                ? "Use an address at a different provider from your main one, so one provider's outage does not take both."
                : isRecoveryEmailVerified
                  ? "Confirmed. We can reach you here if you lose your main address."
                  : "Not confirmed yet. Open the link we sent to this address — until then it cannot be used."
            }
            validate={(next) =>
              next.trim() === ""
                ? "Enter an address, or use Remove to clear it."
                : next.includes("@")
                  ? null
                  : "That does not look like an email address."
            }
            onSave={saveRecoveryEmail}
            extraAction={
              recoveryEmail !== null ? (
                <Button variant="ghost" size="sm" onClick={() => void removeRecoveryEmail()}>
                  Remove
                </Button>
              ) : undefined
            }
          />
        )}
      </SettingsCard>

      <StepUpDialog
        isOpen={modal?.kind === "codes-regenerate"}
        onClose={close}
        title={codes.data?.hasRecoveryCodes ? "Replace your recovery codes?" : "Generate recovery codes"}
        description={
          codes.data?.hasRecoveryCodes
            ? "A new set is shown once, and every code from the old set stops working the moment it is created."
            : "A set of single-use codes, shown once. They are what gets you in when the device holding your second factor is gone."
        }
        confirmLabel={codes.data?.hasRecoveryCodes ? "Replace them" : "Generate them"}
        /* Not destructive in the way a removal is: the account ends up with codes
           either way, so the button should not read as a warning. */
        tone="primary"
        factor={factor}
        onConfirm={regenerateCodes}
      />

      {modal?.kind === "codes-show" ? (
        <Dialog
          isOpen
          /* No `onClose`, so the backdrop and Escape do nothing here. This dialog holds
             the only readable copy of the codes, and a stray click on the backdrop
             would be the reader losing them without being asked. */
          onClose={() => undefined}
          title="Save your recovery codes"
          maxWidth="lg"
        >
          <RecoveryCodesPanel codes={modal.codes} acknowledgeLabel="Done" onAcknowledge={close} />
        </Dialog>
      ) : null}

      <GuardianInviteDialog
        isOpen={modal?.kind === "guardians-invite"}
        onClose={close}
        existingCount={guardians.data?.length ?? 0}
        maxGuardians={maxGuardians}
        onInvite={inviteGuardians}
      />

      <ConfirmDialog
        isOpen={modal?.kind === "guardian-revoke"}
        onClose={close}
        title={
          modal?.kind === "guardian-revoke"
            ? `Remove ${modal.guardian.guardianName}?`
            : "Remove this guardian?"
        }
        description="They stop being able to help you recover this account."
        confirmLabel="Remove them"
        subject="guardian"
        consequence={
          acceptedGuardians.length > 1
            ? `Your other guardians keep the codes they already hold and do not have to do anything. That leaves ${acceptedGuardians.length - 1}, of whom ${threshold(acceptedGuardians.length - 1)} would have to agree.`
            : "This was your only guardian. Nobody will be able to vouch for you until you invite someone else."
        }
        onConfirm={revokeGuardian}
      />

      <SecurityQuestionsDialog
        isOpen={modal?.kind === "questions-set"}
        onClose={close}
        isReplacing={hasQuestions}
        factor={factor}
        onSave={saveQuestions}
      />

      <StepUpDialog
        isOpen={modal?.kind === "questions-remove"}
        onClose={close}
        title="Remove your security questions?"
        description="They stop being a way to recover this account. You can set a new set up at any time."
        confirmLabel="Remove them"
        factor={factor}
        onConfirm={removeQuestions}
      />
    </div>
  );
}

/**
 * The code count as a sentence.
 *
 * Both numbers, because the remaining one alone does not say whether four is most of
 * the set or nearly none of it.
 */
function describeCodes(status: RecoveryCodesStatus | null | undefined): string {
  if (!status || !status.hasRecoveryCodes) return "None generated";
  return `${status.remainingCount} of ${status.totalCount} unused`;
}

/**
 * The guardian tally, counting accepted and waiting separately.
 *
 * They are not interchangeable: `InitiateRecovery` reads only the accepted ones, so
 * a combined figure would tell a reader with three invitations out that they are
 * covered when nothing has happened yet.
 */
function describeGuardians(accepted: number, pending: number): string {
  if (accepted === 0 && pending === 0) return "None invited";
  if (accepted === 0) return `${pending} invited, none accepted yet`;
  if (pending === 0) return `${accepted} accepted`;
  return `${accepted} accepted, ${pending} still to accept`;
}
