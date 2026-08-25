import type { Metadata } from "next";
import type { ReactNode } from "react";
import {
  BackupCodesIcon,
  Badge,
  Button,
  FingerprintIcon,
  LockIcon,
  QrCodeIcon,
  ShieldKeyIllustration,
  SmartphoneIcon,
} from "@authn/ui";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { PageHeader } from "@/components/PageHeader";
import { SettingsCard, SettingsRow } from "@/components/SettingsCard";

/**
 * Authn Platform — Security page
 * File: apps/web-account/src/app/account/security/page.tsx
 *
 * Three cards, and their ids are the three children the sidebar shows under
 * Security. They are fragments of one page rather than three routes because the
 * question a reader arrives with is "how protected am I", and that question is
 * answered by seeing the factors together — split across three pages, each one
 * shows a single row and the answer has to be assembled from memory.
 *
 * Every state shown is one the engine can report. There is no stored password
 * strength and no record of when a password last changed, so neither is claimed;
 * the password row shows the policy it is held to, which is a fact.
 *
 * Structure and copy only: nothing here reads from
 * `GET /v1/client/auth/2fa/webauthn/credentials` or
 * `GET /v1/client/auth/2fa/recovery-codes/status`, and no control is wired.
 */

export const metadata: Metadata = { title: "Security" };

export default function SecurityPage(): ReactNode {
  return (
    <>
      <PageHeader
        eyebrow="Account"
        title="Security"
        description="Your password and the second factors that stand behind it. Two factors is the difference between a leaked password costing you an afternoon and costing you the account."
        illustration={ShieldKeyIllustration}
        accent="green"
      />

      <div className="mx-auto flex w-full max-w-page flex-col gap-xl px-lg py-xxl sm:px-xl">
        <SettingsCard
          id="password"
          title="Password"
          description="Changing it signs out every other session. This one stays signed in."
          action={<Button variant="primary">Change password</Button>}
          footer={<HelpText topic="password" />}
        >
          {/* The rule stated here is the deployment default. The real one is the
              tenant's, delivered by `GET /v1/client/app-config` as `password_rules`,
              and this row renders from that once wired — including the case where the
              tenant is in notify mode and a short password is accepted with a warning
              rather than refused. */}
          <SettingsRow
            icon={LockIcon}
            accent="green"
            label="Password"
            value="Set"
            hint="At least 8 characters, including a digit. Your organization can ask for more. You will need your current password to change it."
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
              <Badge variant="green" dot>on</Badge>
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
          <SettingsRow
            icon={QrCodeIcon}
            accent="green"
            label="Authenticator app"
            value="Enabled"
            hint="A six-digit code from an app on your device. Works with no signal, and nothing to intercept."
            action={<Button variant="secondary">Replace</Button>}
          />
          <SettingsRow
            icon={SmartphoneIcon}
            accent="yellow"
            label="Text message"
            value="+44 ••• ••• 4471"
            hint="Weaker than the others: a number can be taken over by someone who convinces your carrier they are you. The same verified number also works for account recovery."
            action={<Button variant="secondary">Remove</Button>}
          />
          <SettingsRow
            icon={BackupCodesIcon}
            label="Recovery codes"
            value="14 of 16 unused"
            hint="Single-use codes for when the device is gone. We store only hashes, so a set cannot be shown twice — regenerating is the only way to see codes again, and it voids the old set."
            action={
              <>
                <InfoHint topic="recoveryCodes" label="recovery codes" />
                <Button variant="secondary">Regenerate</Button>
              </>
            }
          />
        </SettingsCard>

        <SettingsCard
          id="passkeys"
          title="Passkeys"
          description="A key held by the device, unlocked with your fingerprint or face. It cannot be typed into the wrong site, which is what makes it the one factor phishing does not beat."
          action={
            <>
              <InfoHint topic="passkey" label="passkeys" position="left" />
              <Button variant="primary">Add a passkey</Button>
            </>
          }
          footer={<HelpText topic="passkey" />}
        >
          <SettingsRow
            icon={FingerprintIcon}
            accent="green"
            label="MacBook Pro — Touch ID"
            value="Added 2 March 2026"
            hint="Last used 3 hours ago."
            action={<Button variant="secondary">Remove</Button>}
          />
          <SettingsRow
            icon={FingerprintIcon}
            accent="green"
            label="iPhone 15 — Face ID"
            value="Added 2 March 2026"
            hint="Last used yesterday."
            action={<Button variant="secondary">Remove</Button>}
          />
        </SettingsCard>
      </div>
    </>
  );
}
