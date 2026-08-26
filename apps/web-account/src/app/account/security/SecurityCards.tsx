"use client";

import { useCallback, useMemo, useState, type ReactNode } from "react";
import {
  BackupCodesIcon,
  Badge,
  Button,
  Dialog,
  FingerprintIcon,
  LockIcon,
  QrCodeIcon,
  SmartphoneIcon,
  useToast,
} from "@authn/ui";
import { useAppConfig, useAuth } from "@authn/react";
import type {
  PasswordRules,
  RecoveryCodesStatus,
  TwoFactorMethods,
  WebAuthnPasskey,
} from "@authn/js";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { LoadError, RowSkeleton } from "@/components/CardState";
import { SettingsCard, SettingsRow } from "@/components/SettingsCard";
import { formatDate, formatRelative } from "@/lib/datetime";
import { useResource, type ResourceResult } from "@/lib/useResource";
import { PasskeyAddDialog } from "./PasskeyAddDialog";
import { PasskeyRemoveDialog, type PasskeyRemoveTarget } from "./PasskeyRemoveDialog";
import { PasswordChangeDialog } from "./PasswordChangeDialog";
import { RecoveryCodesPanel } from "@/components/RecoveryCodesPanel";
import { SmsEnrollDialog } from "./SmsEnrollDialog";
import { StepUpDialog } from "@/components/StepUpDialog";
import { TotpEnrollDialog } from "./TotpEnrollDialog";

/**
 * Authn Platform — Security page body
 * File: apps/web-account/src/app/account/security/SecurityCards.tsx
 *
 * Three reads and every control the account's factors have:
 * `GET /v1/client/auth/2fa/methods`, `.../recovery-codes/status` and
 * `.../webauthn/credentials`.
 *
 * They are three requests rather than one because they answer to three different
 * events — a factor turned on, a code spent, a device added — and a single combined
 * read would have to be re-issued in full whenever any of them changed. As it is,
 * confirming an authenticator re-reads the factor list and the code count and
 * leaves the passkey list alone.
 *
 * What the page will not do is claim a state the engine cannot report. There is no
 * stored password strength and no record of when a password last changed, so the
 * password row shows the policy it is held to and nothing more. A row that said
 * "strong" would be inventing it.
 *
 * Which factors are offered comes from `app-config`'s `second_factors` rather than
 * from what the SDK can do. A tenant that has turned off SMS should not be shown a
 * button that enrolls it and then fails.
 */

/**
 * One dialog at a time, as a union rather than seven booleans.
 *
 * Two of these carry a value they cannot work without — which passkey is being
 * removed, which codes were just minted. A boolean plus a separate `target` state
 * can be true while the target is null; this cannot.
 */
type Modal =
  | null
  | { kind: "password" }
  | { kind: "totp-enroll" }
  | { kind: "totp-disable" }
  | { kind: "sms-enroll" }
  | { kind: "sms-disable" }
  | { kind: "codes-regenerate" }
  | { kind: "codes-show"; codes: string[] }
  | { kind: "passkey-add" }
  | { kind: "passkey-remove"; passkey: PasskeyRemoveTarget };

export function SecurityCards(): ReactNode {
  const { client, isAuthenticated } = useAuth();
  const { config } = useAppConfig();
  const toast = useToast();

  const loadTwoFactor = useCallback(async (): Promise<ResourceResult<TwoFactorMethods>> => {
    const result = await client.getTwoFactorMethods();
    return result.ok ? { ok: true, data: result.methods } : { ok: false, error: result.error };
  }, [client]);

  const loadRecoveryCodes = useCallback(async (): Promise<ResourceResult<RecoveryCodesStatus>> => {
    const result = await client.getRecoveryCodesStatus();
    return result.ok ? { ok: true, data: result.status } : { ok: false, error: result.error };
  }, [client]);

  const loadPasskeys = useCallback(async (): Promise<ResourceResult<WebAuthnPasskey[]>> => {
    const result = await client.listWebAuthnCredentials();
    return result.ok ? { ok: true, data: result.credentials } : { ok: false, error: result.error };
  }, [client]);

  // Held until the provider's refresh has settled, or all three go out with no
  // access token and the page renders as three failures.
  const factors = useResource(loadTwoFactor, { enabled: isAuthenticated });
  const codes = useResource(loadRecoveryCodes, { enabled: isAuthenticated });
  const passkeys = useResource(loadPasskeys, { enabled: isAuthenticated });

  const [modal, setModal] = useState<Modal>(null);
  const close = useCallback(() => setModal(null), []);

  /** Re-reads the factor list and the code count, which change together. */
  const refreshFactors = useCallback(() => {
    void factors.refetch();
    void codes.refetch();
  }, [codes, factors]);

  const refreshPasskeys = useCallback(() => {
    void passkeys.refetch();
    // A first passkey on a bare account becomes the account's second factor and
    // mints recovery codes, so the other two reads are stale as well.
    void factors.refetch();
    void codes.refetch();
  }, [codes, factors, passkeys]);

  const primaryFactors = useMemo(
    () => (factors.data?.methods ?? []).filter((method) => method !== "backup_code"),
    [factors.data],
  );
  const hasSecondFactor = primaryFactors.length > 0;
  const isLastFactor = primaryFactors.length === 1;

  /**
   * Whether the tenant permits each factor.
   *
   * Compared against `false` rather than read as truthy, so a page rendering before
   * `app-config` lands offers what the account already has instead of briefly
   * claiming every factor is switched off.
   */
  const allowsTOTP = config?.secondFactors.totp !== false;
  const allowsSMS = config?.secondFactors.sms !== false;
  const allowsPasskey = config?.secondFactors.passkey !== false;

  const disableTOTP = useCallback(
    async (password: string) => {
      const result = await client.disableTOTP({ password });
      if (!result.ok) return result.error;

      close();
      refreshFactors();
      // The sign-out is only mentioned when it happened. The engine revokes every
      // session when the factor removed was the last one, and saying so
      // unconditionally would have a reader with two other factors checking whether
      // their other devices had been kicked out.
      toast.success(
        "Authenticator app turned off",
        isLastFactor
          ? "Your other sessions have been signed out. Your next sign-in will ask for your password only."
          : "Your next sign-in will not ask for a code from the app.",
      );
      return null;
    },
    [client, close, isLastFactor, refreshFactors, toast],
  );

  const disableSMS = useCallback(
    async (password: string) => {
      const result = await client.disableSMS({ password });
      if (!result.ok) return result.error;

      close();
      refreshFactors();
      toast.success(
        "Phone number removed",
        isLastFactor
          ? "Your other sessions have been signed out. The number is no longer a second factor or a way to recover the account."
          : "It is no longer a second factor, and no longer a way to recover the account.",
      );
      return null;
    },
    [client, close, isLastFactor, refreshFactors, toast],
  );

  const regenerateCodes = useCallback(
    async (password: string) => {
      const result = await client.regenerateRecoveryCodes({ password });
      if (!result.ok) return result.error;

      // Straight to the new set, without closing first. This response is the only
      // place the codes exist as text, so dismissing the dialog to open another one
      // would be dropping them.
      setModal({ kind: "codes-show", codes: result.recoveryCodes });
      void codes.refetch();
      return null;
    },
    [client, codes],
  );

  return (
    <div className="mx-auto flex w-full max-w-page flex-col gap-xl px-lg py-xxl sm:px-xl">
      <SettingsCard
        id="password"
        title="Password"
        description="Changing it signs out every other session. This one stays signed in."
        action={
          <Button variant="primary" onClick={() => setModal({ kind: "password" })}>
            Change password
          </Button>
        }
        footer={<HelpText topic="password" />}
      >
        {/* The rule shown is the tenant's own, from `GET /v1/client/app-config`. A
            checklist quoting a deployment default while the tenant requires twelve
            characters tells the reader they have satisfied a rule and then the
            request refuses them. */}
        <SettingsRow
          icon={LockIcon}
          accent="green"
          label="Password"
          value="Set"
          hint={describePasswordRules(config?.passwordRules)}
          action={<InfoHint topic="password" label="password changes" position="left" />}
        />
      </SettingsCard>

      {/* The three methods are one card rather than three, and they are ordered by how
          much they actually protect you: a passkey cannot be phished, an
          authenticator code can be read out over the phone, an SMS code can be
          taken with the number. Presenting them as an unordered menu of equals is
          how people end up choosing the weakest one. */}
      <SettingsCard
        id="two-factor"
        title="Two-factor authentication"
        description="A second proof, asked for after your password. Turn on at least one, then keep the recovery codes somewhere that is not your phone."
        action={
          <>
            {factors.isLoading ? null : hasSecondFactor ? (
              <Badge variant="green" dot>
                on
              </Badge>
            ) : (
              <Badge variant="yellow" dot>
                off
              </Badge>
            )}
            <InfoHint topic="twoFactor" label="two-factor authentication" position="left" />
          </>
        }
        footer={
          <div className="flex flex-col gap-xs">
            {/* The step-up on the last factor is real behaviour and belongs on the page
                rather than in the dialog that enforces it: someone about to remove
                their only second factor should know it will end their other sessions
                before they start, not while being asked for a password. */}
            <p className="text-caption text-ash">
              Removing your last remaining second factor asks for your password and signs
              out every other session — that combination of events is what an attacker
              taking an account apart looks like, so it is not allowed to be quiet.
            </p>
            <HelpText topic="twoFactor" />
          </div>
        }
      >
        {factors.isLoading ? (
          <RowSkeleton rows={3} hasIcon label="your second factors" />
        ) : !factors.data ? (
          <LoadError
            label="your second factors"
            message={factors.error?.message}
            onRetry={() => void factors.refetch()}
            isRetrying={factors.isRefetching}
          />
        ) : (
          <>
            {allowsTOTP || factors.data.totp.enabled ? (
              <SettingsRow
                icon={QrCodeIcon}
                accent={factors.data.totp.enabled ? "green" : undefined}
                label="Authenticator app"
                value={factors.data.totp.enabled ? "On" : "Off"}
                hint={describeFactor(
                  "A six-digit code from an app on your device. Works with no signal, and nothing to intercept.",
                  factors.data.totp,
                )}
                action={
                  factors.data.totp.enabled ? (
                    <Button
                      variant="secondary"
                      onClick={() => setModal({ kind: "totp-disable" })}
                    >
                      Turn off
                    </Button>
                  ) : (
                    <Button variant="primary" onClick={() => setModal({ kind: "totp-enroll" })}>
                      Set up
                    </Button>
                  )
                }
              />
            ) : null}

            {allowsSMS || factors.data.sms.enabled ? (
              <SettingsRow
                icon={SmartphoneIcon}
                accent={factors.data.sms.enabled ? "yellow" : undefined}
                /* The number in full, not masked. This read needs a session and the
                   profile already returns the same number to the same caller, so
                   masking it here would withhold nothing while making the row unable
                   to answer the one question asked of it: is that still my number. */
                value={
                  factors.data.sms.enabled ? (factors.data.sms.phoneNumber ?? "On") : "Off"
                }
                label="Text message"
                hint={describeFactor(
                  "Weaker than the others: a number can be taken over by someone who convinces your carrier they are you. The same verified number also works for account recovery.",
                  factors.data.sms,
                )}
                action={
                  factors.data.sms.enabled ? (
                    <Button variant="secondary" onClick={() => setModal({ kind: "sms-disable" })}>
                      Remove
                    </Button>
                  ) : (
                    <Button variant="secondary" onClick={() => setModal({ kind: "sms-enroll" })}>
                      Add a number
                    </Button>
                  )
                }
              />
            ) : null}

            <SettingsRow
              icon={BackupCodesIcon}
              label="Recovery codes"
              value={describeCodeCount(codes.data, codes.isLoading)}
              hint="Single-use codes for when the device is gone. We store only hashes, so a set cannot be shown twice — regenerating is the only way to see codes again, and it voids the old set."
              action={
                <>
                  <InfoHint topic="recoveryCodes" label="recovery codes" />
                  {/* Offered only alongside a factor. The engine discards codes when
                      the last factor goes, so generating a set on a bare account
                      creates something it will throw away. */}
                  <Button
                    variant="secondary"
                    disabled={!hasSecondFactor}
                    onClick={() => setModal({ kind: "codes-regenerate" })}
                  >
                    {codes.data?.hasRecoveryCodes ? "Regenerate" : "Generate"}
                  </Button>
                </>
              }
            />
          </>
        )}
      </SettingsCard>

      <SettingsCard
        id="passkeys"
        title="Passkeys"
        description="A key held by the device, unlocked with your fingerprint or face. It cannot be typed into the wrong site, which is what makes it the one factor phishing does not beat."
        action={
          <>
            <InfoHint topic="passkey" label="passkeys" position="left" />
            {allowsPasskey ? (
              <Button variant="primary" onClick={() => setModal({ kind: "passkey-add" })}>
                Add a passkey
              </Button>
            ) : null}
          </>
        }
        footer={<HelpText topic="passkey" />}
      >
        {passkeys.isLoading ? (
          <RowSkeleton rows={2} hasIcon label="your passkeys" />
        ) : !passkeys.data ? (
          <LoadError
            label="your passkeys"
            message={passkeys.error?.message}
            onRetry={() => void passkeys.refetch()}
            isRetrying={passkeys.isRefetching}
          />
        ) : passkeys.data.length === 0 ? (
          /* Written as a row rather than with `EmptyState`, which brings its own
             border and would draw a second frame inside this card. The action is
             already on the card's header, so there is nothing to repeat. */
          <p className="p-lg text-body-sm text-charcoal">
            No passkeys yet. Adding one on this device takes about ten seconds and means
            you can sign in with a fingerprint instead of a password.
          </p>
        ) : (
          passkeys.data.map((passkey) => (
            <SettingsRow
              key={passkey.id}
              icon={FingerprintIcon}
              accent="green"
              label={passkey.name}
              value={`Added ${formatDate(passkey.createdAt)}`}
              hint={describePasskey(passkey)}
              action={
                <Button
                  variant="secondary"
                  onClick={() =>
                    setModal({
                      kind: "passkey-remove",
                      passkey: { id: passkey.id, name: passkey.name },
                    })
                  }
                >
                  Remove
                </Button>
              }
            />
          ))
        )}
      </SettingsCard>

      <PasswordChangeDialog isOpen={modal?.kind === "password"} onClose={close} />

      <TotpEnrollDialog
        isOpen={modal?.kind === "totp-enroll"}
        onClose={close}
        onEnrolled={refreshFactors}
      />

      <SmsEnrollDialog
        isOpen={modal?.kind === "sms-enroll"}
        onClose={close}
        onEnrolled={refreshFactors}
      />

      <StepUpDialog
        isOpen={modal?.kind === "totp-disable"}
        onClose={close}
        title="Turn off the authenticator app?"
        description="Your next sign-in will ask for your password only. The app's entry stops working, so delete it there as well."
        confirmLabel="Turn it off"
        consequence={isLastFactor ? LAST_FACTOR_WARNING : undefined}
        onConfirm={disableTOTP}
      />

      <StepUpDialog
        isOpen={modal?.kind === "sms-disable"}
        onClose={close}
        title="Remove this phone number?"
        description="It stops being a second factor and stops being a way to recover the account. You can add it again later."
        confirmLabel="Remove it"
        consequence={isLastFactor ? LAST_FACTOR_WARNING : undefined}
        onConfirm={disableSMS}
      />

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
        onConfirm={regenerateCodes}
      />

      {modal?.kind === "codes-show" ? (
        <Dialog
          isOpen
          /* No `onClose`, so the backdrop and Escape do nothing here. Every other
             dialog is dismissible; this one holds the only readable copy of the
             codes, and a stray click on the backdrop would be the reader losing
             them without being asked. The panel's own button is the way out. */
          onClose={() => undefined}
          title="Save your recovery codes"
          maxWidth="lg"
        >
          <RecoveryCodesPanel codes={modal.codes} acknowledgeLabel="Done" onAcknowledge={close} />
        </Dialog>
      ) : null}

      <PasskeyAddDialog
        isOpen={modal?.kind === "passkey-add"}
        onClose={close}
        onAdded={refreshPasskeys}
      />

      <PasskeyRemoveDialog
        isOpen={modal?.kind === "passkey-remove"}
        onClose={close}
        passkey={modal?.kind === "passkey-remove" ? modal.passkey : null}
        onRemoved={refreshPasskeys}
      />
    </div>
  );
}

/** Shown above the password field when the factor being removed is the only one. */
const LAST_FACTOR_WARNING =
  "This is the only second factor on the account. Removing it leaves your password alone protecting you, and signs out every other session.";

/**
 * States the tenant's password policy as a sentence.
 *
 * Assembled from `app-config` rather than written out, because the rules are the
 * tenant's to set: a page with "at least 8 characters, including a digit" baked in
 * is wrong for every tenant that chose otherwise, and wrong in the direction that
 * makes the engine look broken.
 */
function describePasswordRules(rules: PasswordRules | undefined): string {
  if (!rules) {
    return "You will need your current password to change it.";
  }

  const extras: string[] = [];
  if (rules.requireUppercase) extras.push("an upper-case letter");
  if (rules.requireLowercase) extras.push("a lower-case letter");
  if (rules.requireNumeric) extras.push("a number");
  if (rules.requireSpecial) extras.push("a symbol");

  const shape =
    extras.length === 0
      ? `At least ${rules.minLength} characters.`
      : `At least ${rules.minLength} characters, including ${asProse(extras)}.`;

  // Notify mode is worth saying out loud. A reader who misses a rule and is let
  // through anyway will otherwise conclude the rule was never real.
  const mode = rules.enforced
    ? ""
    : " Your organization treats these as advice, so a password that misses one is still accepted.";

  return `${shape} You will need your current password to change it.${mode}`;
}

/** Joins a short list the way a sentence would: "a, b and c". */
function asProse(items: string[]): string {
  if (items.length <= 1) return items[0] ?? "";
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

/**
 * Appends what is known about an enrolled factor to its description.
 *
 * "Not used yet" is stated rather than left blank, because a blank reads as missing
 * data. On a factor that was turned on and never exercised it is also the useful
 * fact: nothing has tested that it works.
 */
function describeFactor(
  description: string,
  state: { enabled: boolean; createdAt?: string; lastUsedAt?: string },
): string {
  if (!state.enabled) return description;

  const added = state.createdAt ? `On since ${formatDate(state.createdAt)}.` : "On.";
  const used = state.lastUsedAt
    ? `Last used ${formatRelative(state.lastUsedAt)}.`
    : "Not used to sign in yet.";
  return `${added} ${used} ${description}`;
}

/** The count row's value: a spent code is the thing this row exists to report. */
function describeCodeCount(status: RecoveryCodesStatus | null, isLoading: boolean): string {
  if (isLoading) return "…";
  if (!status || !status.hasRecoveryCodes) return "None";
  return `${status.remainingCount} of ${status.totalCount} unused`;
}

/**
 * A passkey's second line: how it can be reached, and when it last was.
 *
 * The transport is the difference between "the fingerprint reader on this laptop"
 * and "the key on your keyring", and a list that cannot tell those apart is a list
 * nobody can safely prune. An authenticator that declined to say is left unstated
 * rather than guessed at.
 */
function describePasskey(passkey: WebAuthnPasskey): string {
  const used = passkey.lastUsedAt
    ? `Last used ${formatRelative(passkey.lastUsedAt)}.`
    : "Not used to sign in yet.";

  const transports = passkey.transports ?? [];
  if (transports.includes("internal")) {
    return `${used} Built into the device it was created on.`;
  }
  if (transports.includes("hybrid")) {
    return `${used} A phone or tablet, used by scanning a code.`;
  }
  if (transports.some((transport) => transport === "usb" || transport === "nfc" || transport === "ble")) {
    return `${used} A security key you carry.`;
  }
  return used;
}
