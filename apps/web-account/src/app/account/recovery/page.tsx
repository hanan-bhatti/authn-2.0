import type { Metadata } from "next";
import type { ReactNode } from "react";
import {
  BackupCodesIcon,
  Badge,
  BuoyIllustration,
  Button,
  CodeBlock,
  MailIcon,
  PhoneIcon,
  UsersIcon,
} from "@authn/ui";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { PageHeader } from "@/components/PageHeader";
import { SettingsCard, SettingsRow } from "@/components/SettingsCard";

/**
 * Authn Platform — Recovery page
 * File: apps/web-account/src/app/account/recovery/page.tsx
 *
 * The one page written for a reader who is not in trouble yet, about what happens
 * when they are. That shapes the copy: every row says what it will and will not
 * recover, because a recovery method someone believes in and cannot use is worse
 * than one they know is missing.
 *
 * Yellow, not green. Green on this page would say "you are protected", and the
 * honest claim is "you have a way back if something goes wrong" — which is a state
 * worth checking, not a state to be satisfied with.
 *
 * The rows are the proofs `POST /v1/client/auth/recovery/initiate` can actually
 * offer, in the order it offers them. Two of them are not set up from this page
 * and say so: a verified phone comes from SMS enrolment on the security page, and
 * a verified email address is simply the primary address once confirmed.
 *
 * Structure and copy only: nothing here reads from the engine, and no control is
 * wired.
 */

export const metadata: Metadata = { title: "Recovery" };

export default function RecoveryPage(): ReactNode {
  return (
    <>
      <PageHeader
        eyebrow="Account"
        title="Recovery"
        description="How you get back in when the password is gone, the phone is lost, or both. Set at least two of these up now — none of them can be added once you are locked out."
        illustration={BuoyIllustration}
        accent="yellow"
      />

      <div className="mx-auto flex w-full max-w-page flex-col gap-xl px-lg py-xxl sm:px-xl">
        <SettingsCard
          title="Recovery methods"
          description="Listed in the order you will be offered them. A code you have printed beats an address you can no longer read email at."
          action={<Badge variant="yellow" dot>2 of 4 ready</Badge>}
        >
          <SettingsRow
            icon={BackupCodesIcon}
            accent="yellow"
            label="Recovery codes"
            value="14 of 16 unused"
            hint="Works with no phone, no signal and no email. Each code is single-use, and generating a new set voids every old one immediately."
            action={
              <>
                <Badge variant="green">set</Badge>
                <InfoHint topic="recoveryCodes" label="recovery codes" />
                <Button variant="secondary">Regenerate</Button>
              </>
            }
          />
          <SettingsRow
            icon={UsersIcon}
            accent="yellow"
            label="Guardians"
            value="Not set"
            hint="Up to five people you trust. Recovery needs a majority of them to agree — two of three, three of five — so no one of them can act alone."
            action={
              <>
                <InfoHint topic="guardians" label="guardians" />
                <Button variant="primary">Invite guardians</Button>
              </>
            }
          />
          <SettingsRow
            icon={PhoneIcon}
            label="Verified phone"
            value="Not set"
            hint="A code by text, to the number you verified for two-factor sign-in. There is no separate recovery number — set the number up once, on the security page, and it covers both."
            action={<Button variant="secondary">Go to security</Button>}
          />
          <SettingsRow
            icon={MailIcon}
            label="Verified email"
            value="ada@example.com"
            hint="A code to your sign-in address, available as soon as that address is confirmed. Nothing to set up here."
            action={<Badge variant="green">verified</Badge>}
          />
        </SettingsCard>

        {/* Real-looking codes rather than lorem, because the format is information:
            two groups of four, drawn from an alphabet with no 0, O, 1 or I in it, and
            someone reading this page is deciding whether they can realistically write
            sixteen of them down. */}
        <SettingsCard
          id="codes"
          title="Your recovery codes"
          description="Shown once, when generated. We store a hash and cannot show them again — if this list is lost, regenerate."
          action={<Button variant="secondary">Download .txt</Button>}
          footer={
            <div className="flex flex-col gap-xs">
              <p className="text-caption text-ash">
                Each code works exactly once, in any order, in place of your second
                factor. This set replaces any earlier one — codes from a previous list
                stopped working the moment these were made.
              </p>
              <HelpText topic="recoveryCodes" />
            </div>
          }
        >
          <div className="p-lg">
            <CodeBlock
              title="recovery-codes.txt"
              language="bash"
              code={[
                "4H8K-2QW9",
                "9DFA-6BLE",
                "7TSN-XRQU",
                "2GKP-9CVR",
                "6MZB-4XHT",
                "TJVC-K8ZY",
                "5NLD-T6EA",
                "PQRF-W8JS",
                "3WVK-7HND",
                "8LQT-2FBG",
                "P5RJ-6CZM",
                "K9XS-4TWE",
                "2NHV-8GLP",
                "7BQD-3MSF",
                "W4KZ-9JTR",
                "5CGE-6PVN",
              ].join("\n")}
            />
          </div>
        </SettingsCard>

        {/* A second address, on its own card rather than in the list above, because it
            is not one of the proofs: it is a place we can reach you, and putting it
            among the four would read as a fifth way back in. */}
        <SettingsCard
          title="Recovery email"
          description="A second address on your account, confirmed by a link we send to it."
          action={<InfoHint topic="recoveryEmail" label="the recovery email" position="left" />}
          footer={<HelpText topic="recoveryEmail" />}
        >
          <SettingsRow
            icon={MailIcon}
            label="Second address"
            value="Not set"
            hint="Use an address at a different provider. Two addresses at the same company go down in the same outage, which is the situation this exists for."
            action={<Button variant="primary">Add address</Button>}
          />
        </SettingsCard>
      </div>
    </>
  );
}
