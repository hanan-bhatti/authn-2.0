"use client";

import { useCallback, useState, type ReactNode } from "react";
import { AlertIcon, Button, CopyButton } from "@authn/ui";

/**
 * Authn Platform — Recovery codes, shown once
 * File: apps/web-account/src/app/account/security/RecoveryCodesPanel.tsx
 *
 * The codes are hashed on the way in, so this is the only moment in the account's
 * life they exist as text. Two things follow from that, and both are the reason
 * this is a component and not a list.
 *
 * The panel makes saving them a step rather than an option: there is a copy, a
 * download, and a box the reader has to tick before the dialog will let them past.
 * That checkbox is not ceremony — the failure it prevents is the one where someone
 * closes the dialog, loses their phone a year later, and finds out then.
 *
 * And it never shows a set it was not handed. There is no endpoint that returns
 * existing codes, so a panel that fetched instead of receiving would have to invent
 * something to display.
 */

export interface RecoveryCodesPanelProps {
  codes: readonly string[];
  /** Called when the reader confirms they have saved them. */
  onAcknowledge: () => void;
  acknowledgeLabel?: string;
}

export function RecoveryCodesPanel({
  codes,
  onAcknowledge,
  acknowledgeLabel = "I have saved these codes",
}: RecoveryCodesPanelProps): ReactNode {
  const [hasSaved, setHasSaved] = useState(false);

  const asText = codes.join("\n");

  /**
   * Downloads the codes as a text file, built in the browser.
   *
   * A Blob URL rather than a link to the server: the codes were never persisted in
   * readable form, so there is nothing to link to, and a request that returned them
   * would put them in a proxy log.
   */
  const download = useCallback(() => {
    const blob = new Blob([`${asText}\n`], { type: "text/plain" });
    const url = URL.createObjectURL(blob);

    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "authn-recovery-codes.txt";
    anchor.click();

    // Released immediately: the click has already started the download, and a Blob
    // URL left behind pins its contents — these contents — in memory for the life of
    // the document.
    URL.revokeObjectURL(url);
  }, [asText]);

  return (
    <div className="flex flex-col gap-lg">
      <div className="flex items-start gap-sm rounded-md border border-accent-yellow/40 bg-accent-yellow/8 p-md">
        <AlertIcon variant="line" size={16} className="mt-px shrink-0 text-accent-yellow" />
        <p className="text-caption text-charcoal">
          This is the only time these codes are shown. We store a hash of each one, so
          we cannot show them to you again — the only way to get a readable set is to
          generate a new one, which cancels these.
        </p>
      </div>

      {/* Two columns of monospace, which is what makes a transcription error visible:
          the codes are the same length, so a missing character shows up as a short
          row rather than as a code that merely looks wrong. */}
      <ol className="grid grid-cols-2 gap-x-md gap-y-xs rounded-md border border-hairline bg-surface-elevated p-md">
        {codes.map((code, index) => (
          <li key={code} className="flex items-baseline gap-sm">
            <span className="w-5 shrink-0 text-right font-mono text-caption text-ash">
              {index + 1}
            </span>
            <span className="font-mono text-body-sm text-ink select-all">{code}</span>
          </li>
        ))}
      </ol>

      <div className="flex flex-wrap items-center gap-sm">
        <CopyButton value={asText} label="Copy all" />
        <Button variant="secondary" size="sm" onClick={download}>
          Download as a file
        </Button>
        <span className="text-caption text-ash">
          {codes.length} codes, each usable once.
        </span>
      </div>

      {/* A label wrapping the input, so the whole line is the hit area. A 16px
          checkbox on a phone is a target most thumbs miss. */}
      <label className="flex cursor-pointer items-start gap-sm text-body-sm text-charcoal">
        <input
          type="checkbox"
          checked={hasSaved}
          onChange={(event) => setHasSaved(event.target.checked)}
          className="mt-0.5 size-4 shrink-0 accent-accent-green"
        />
        <span>
          I have saved these codes somewhere I can reach without this device — not only
          in the phone that holds my authenticator.
        </span>
      </label>

      <div className="flex justify-end">
        <Button variant="primary" disabled={!hasSaved} onClick={onAcknowledge}>
          {acknowledgeLabel}
        </Button>
      </div>
    </div>
  );
}
