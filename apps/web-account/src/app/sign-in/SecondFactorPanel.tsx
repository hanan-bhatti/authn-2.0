"use client";

/**
 * Authn Platform — Second-factor step of sign-in
 * File: apps/web-account/src/app/sign-in/SecondFactorPanel.tsx
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { useRouter } from "next/navigation";
import {
  BackupCodesIcon,
  Button,
  FingerprintIcon,
  FormField,
  Input,
  PhoneIcon,
  QrCodeIcon,
  Toast,
  type IconComponent,
} from "@authn/ui";
import { usePasskeys, useTOTP } from "@authn/react";
import { isPasskeySupported, type AuthnUser, type TwoFactorMethod } from "@authn/js";
import { presentSecondFactorError } from "@/lib/authError";

/**
 * How long before a new text message may be requested.
 *
 * The engine allows three sends per ten minutes and counts enrollment against
 * the same budget, so a person who taps "send a new code" three times while the
 * first message is still in flight has locked themselves out of the only method
 * they can use. The cooldown spends the wait here, where it can be explained,
 * rather than at the limiter, where it cannot.
 */
const RESEND_COOLDOWN_SECONDS = 30;

/** Codes are fixed-width, so the field can refuse a wrong length before a request. */
const TOTP_CODE_LENGTH = 6;
const RECOVERY_CODE_LENGTH = 8;

/**
 * Strips a recovery code to the characters the engine hashes.
 *
 * The engine prints them grouped — `EF7B-73B4` — and normalises by upper-casing
 * and dropping dashes before comparing, so the field accepts the printed form,
 * the ungrouped form and either case. Anything else is a transcription slip.
 */
function normaliseRecoveryCode(value: string): string {
  return value.replace(/-/g, "").toUpperCase();
}

interface MethodPresentation {
  /** What this method is called where it is the current one. */
  title: string;
  /** What it is called in the list of alternatives. */
  switchLabel: string;
  icon: IconComponent;
}

const METHODS: Record<TwoFactorMethod, MethodPresentation> = {
  totp: {
    title: "Enter the code from your authenticator app",
    switchLabel: "Use my authenticator app",
    icon: QrCodeIcon,
  },
  sms: {
    title: "Enter the code we texted you",
    switchLabel: "Text me a code",
    icon: PhoneIcon,
  },
  passkey: {
    title: "Use your passkey",
    switchLabel: "Use my passkey",
    icon: FingerprintIcon,
  },
  backup_code: {
    title: "Enter one of your recovery codes",
    switchLabel: "Use a recovery code",
    icon: BackupCodesIcon,
  },
};

export interface SecondFactorPanelProps {
  mfaToken: string;
  /** The engine's list, most recently used first. */
  methods: readonly TwoFactorMethod[];
  user: AuthnUser;
  /** Returns to the credentials form, for when the challenge can no longer be spent. */
  onRestart: () => void;
}

interface ToastMessage {
  type: "error" | "info";
  title: string;
  description?: string;
}

interface SmsDelivery {
  phoneNumber?: string;
  expiresInSeconds?: number;
}

export function SecondFactorPanel({
  mfaToken,
  methods,
  user,
  onRestart,
}: SecondFactorPanelProps): ReactNode {
  const router = useRouter();
  const { verifyTOTP, sendSMSChallenge, isLoading: isTotpBusy } = useTOTP();
  const { loginWithPasskey, isLoading: isPasskeyBusy } = usePasskeys();

  // A passkey the browser cannot use is worse than no passkey option: the account
  // holder picks the method they recognise, and the button fails on a capability
  // they were never told about. Resolved once on mount because it cannot change
  // while the panel is open, and reading `window` during render would differ
  // between the server pass and the client one.
  const [canUsePasskey, setCanUsePasskey] = useState(false);
  useEffect(() => {
    setCanUsePasskey(isPasskeySupported());
  }, []);

  const available = useMemo(
    () => methods.filter((method) => method !== "passkey" || canUsePasskey),
    [methods, canUsePasskey],
  );

  // A recovery code is a way past a factor rather than a factor, so it is never
  // the method a screen opens on — someone who can reach their authenticator
  // should not be nudged into spending a single-use code. The engine returns the
  // list most-recently-used first, so the first ordinary factor is also the one
  // this account reached for last time.
  const [method, setMethod] = useState<TwoFactorMethod | null>(null);
  const active = method ?? available.find((m) => m !== "backup_code") ?? available[0] ?? null;

  const [code, setCode] = useState("");
  const [fieldMessage, setFieldMessage] = useState<string | null>(null);
  const [toast, setToast] = useState<ToastMessage | null>(null);
  const [restart, setRestart] = useState<{ title: string; description: string } | null>(null);
  const [sms, setSms] = useState<SmsDelivery | null>(null);
  const [cooldown, setCooldown] = useState(0);

  const codeRef = useRef<HTMLInputElement>(null);
  // Set before the request rather than after it, so React's development remount —
  // which runs effects twice against the same state — cannot spend two of the
  // three sends this account is allowed in ten minutes.
  const sendClaimed = useRef(false);

  const present = useCallback(
    (error: Parameters<typeof presentSecondFactorError>[0], forMethod: TwoFactorMethod) => {
      const presented = presentSecondFactorError(error, forMethod);

      if ("restart" in presented) {
        setRestart(presented.restart);
        return;
      }
      if ("toast" in presented) {
        setToast({
          // A dismissed passkey prompt is a decision, not a fault, and colouring
          // it as an error tells the user something went wrong when nothing did.
          type: presented.toast.title === "Passkey not used" ? "info" : "error",
          ...presented.toast,
        });
        return;
      }

      setFieldMessage(presented.code);
      setCode("");
      codeRef.current?.focus();
    },
    [],
  );

  /**
   * Replace rather than push: the challenge is spent, so the entry this would
   * leave in the history is a screen that can only fail if the user goes back to
   * it.
   */
  const succeed = useCallback(() => {
    router.replace("/account");
  }, [router]);

  const requestSms = useCallback(async () => {
    setFieldMessage(null);
    setToast(null);

    const result = await sendSMSChallenge({ mfaToken });
    if (!result.ok) {
      present(result.error, "sms");
      return;
    }

    setSms({ phoneNumber: result.phoneNumber, expiresInSeconds: result.expiresInSeconds });
    setCooldown(RESEND_COOLDOWN_SECONDS);
    codeRef.current?.focus();
  }, [mfaToken, present, sendSMSChallenge]);

  // Selecting "text me a code" is the request: a screen that says "enter the code
  // we texted you" beside a button that has not sent anything yet is a screen
  // that lies. Guarded so it happens once per panel, not once per render.
  useEffect(() => {
    if (active !== "sms" || sendClaimed.current) return;
    sendClaimed.current = true;
    void requestSms();
  }, [active, requestSms]);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => setCooldown((seconds) => seconds - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  const handlePasskey = useCallback(async () => {
    setToast(null);
    const result = await loginWithPasskey(mfaToken);
    if (!result.ok) {
      present(result.error, "passkey");
      return;
    }
    succeed();
  }, [loginWithPasskey, mfaToken, present, succeed]);

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (active === null || active === "passkey") return;

      setFieldMessage(null);
      setToast(null);

      const submitted = active === "backup_code" ? normaliseRecoveryCode(code) : code;
      const expected = active === "backup_code" ? RECOVERY_CODE_LENGTH : TOTP_CODE_LENGTH;
      if (submitted.length !== expected) {
        setFieldMessage(
          active === "backup_code"
            ? `A recovery code is ${RECOVERY_CODE_LENGTH} characters, written as four and four.`
            : `The code is ${TOTP_CODE_LENGTH} digits.`,
        );
        codeRef.current?.focus();
        return;
      }

      const result = await verifyTOTP({ code: submitted, mfaToken, method: active });
      if (!result.ok) {
        present(result.error, active);
        return;
      }
      succeed();
    },
    [active, code, mfaToken, present, succeed, verifyTOTP],
  );

  const switchTo = useCallback((next: TwoFactorMethod) => {
    setMethod(next);
    setCode("");
    setFieldMessage(null);
    setToast(null);
    if (next !== "sms") return;
    // Switching back to text messages should send again: the earlier code has
    // almost certainly expired, and the panel is about to claim one was sent.
    sendClaimed.current = false;
  }, []);

  if (restart) {
    return (
      <div className="flex flex-col gap-lg">
        <div className="flex flex-col gap-md">
          <h2 className="font-display text-heading-sm text-ink">{restart.title}</h2>
          <p className="text-body-sm text-charcoal">{restart.description}</p>
          <p className="text-caption text-mute">You have not been signed in.</p>
        </div>
        <Button variant="primary" className="w-full" onClick={onRestart}>
          Start again
        </Button>
      </div>
    );
  }

  if (active === null) {
    return (
      <div className="flex flex-col gap-md">
        <h2 className="font-display text-heading-sm text-ink">Two-step verification required</h2>
        <p className="text-body-sm text-charcoal">
          This account needs a second step, and none of its methods work in this browser. Open this
          page in a browser that supports passkeys, or use a device where your other methods are set
          up.
        </p>
        <p className="text-caption text-mute">You have not been signed in.</p>
      </div>
    );
  }

  const presentation = METHODS[active];
  const alternatives = available.filter((candidate) => candidate !== active);
  const isBusy = active === "passkey" ? isPasskeyBusy : isTotpBusy;

  return (
    <div className="flex flex-col gap-lg">
      <div className="flex flex-col gap-sm">
        <h2 className="font-display text-heading-sm text-ink">{presentation.title}</h2>
        <p className="text-body-sm text-charcoal">
          Your password was accepted. One more step for{" "}
          <span className="font-mono text-ink">{user.email ?? user.username}</span>.
        </p>
      </div>

      {active === "passkey" ? (
        <div className="flex flex-col gap-md">
          <Button
            variant="primary"
            className="w-full"
            isLoading={isPasskeyBusy}
            leftIcon={<FingerprintIcon size={16} />}
            onClick={() => void handlePasskey()}
          >
            Verify with your passkey
          </Button>
          <p className="text-caption text-mute">
            Your device will ask for your fingerprint, face or screen lock. Nothing leaves the
            device except the signed answer.
          </p>
        </div>
      ) : (
        <form noValidate onSubmit={handleSubmit} className="flex flex-col gap-lg">
          <FormField
            label={active === "backup_code" ? "Recovery code" : "Verification code"}
            isRequired
            error={fieldMessage ?? undefined}
          >
            <Input
              ref={codeRef}
              type="text"
              name="code"
              value={code}
              required
              autoFocus
              // `one-time-code` is what lets a phone offer the code straight from
              // the message notification. A recovery code is not one-time in that
              // sense and lives in a password manager, so autofill is off there.
              autoComplete={active === "backup_code" ? "off" : "one-time-code"}
              inputMode={active === "backup_code" ? "text" : "numeric"}
              autoCapitalize={active === "backup_code" ? "characters" : "none"}
              spellCheck={false}
              maxLength={active === "backup_code" ? RECOVERY_CODE_LENGTH + 1 : TOTP_CODE_LENGTH}
              placeholder={active === "backup_code" ? "ABCD-2345" : "123456"}
              className="font-mono tracking-[0.3em]"
              onChange={(event) => {
                // Filtered on the way in rather than refused on submit: a pasted
                // "123 456" is the right code copied in a reasonable way, and
                // rejecting it teaches nothing. The recovery field keeps the dash
                // it was printed with, so what is on screen matches what the
                // reader is copying from.
                const raw = event.target.value;
                setCode(
                  active === "backup_code"
                    ? raw.toUpperCase().replace(/[^A-Z0-9-]/g, "")
                    : raw.replace(/\D/g, ""),
                );
                if (fieldMessage) setFieldMessage(null);
              }}
            />
          </FormField>

          {active === "sms" && (
            <div className="flex flex-col gap-sm">
              {sms?.phoneNumber && (
                <p className="text-caption text-mute">
                  Sent to <span className="font-mono text-charcoal">{sms.phoneNumber}</span>
                  {sms.expiresInSeconds
                    ? ` · valid for ${Math.round(sms.expiresInSeconds / 60)} minutes`
                    : ""}
                </p>
              )}
              <button
                type="button"
                disabled={cooldown > 0 || isTotpBusy}
                onClick={() => void requestSms()}
                className="self-start text-caption text-mute underline decoration-hairline-strong underline-offset-2 transition-colors hover:text-ink hover:decoration-ink disabled:no-underline disabled:opacity-60 disabled:hover:text-mute"
              >
                {cooldown > 0 ? `Send a new code in ${cooldown}s` : "Send a new code"}
              </button>
            </div>
          )}

          <Button type="submit" variant="primary" isLoading={isBusy} className="w-full">
            Verify
          </Button>
        </form>
      )}

      {alternatives.length > 0 && (
        <>
          <div className="h-px w-full bg-divider-soft" />
          <div className="flex flex-col gap-sm">
            <p className="text-caption text-mute">Cannot use that right now?</p>
            <div className="flex flex-col items-start gap-xs">
              {alternatives.map((candidate) => {
                const Icon = METHODS[candidate].icon;
                return (
                  <button
                    key={candidate}
                    type="button"
                    onClick={() => switchTo(candidate)}
                    className="inline-flex items-center gap-sm text-body-sm text-charcoal transition-colors hover:text-ink"
                  >
                    <Icon size={16} className="text-mute" />
                    {METHODS[candidate].switchLabel}
                  </button>
                );
              })}
            </div>
          </div>
        </>
      )}

      {toast && (
        <div className="fixed inset-x-lg bottom-lg z-50 flex justify-center sm:justify-end">
          <Toast
            type={toast.type}
            title={toast.title}
            description={toast.description}
            onClose={() => setToast(null)}
          />
        </div>
      )}
    </div>
  );
}
