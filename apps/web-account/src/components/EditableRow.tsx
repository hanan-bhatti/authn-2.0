"use client";

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { ACCENT_SOLID, Button, Input, type Accent, type IconComponent } from "@authn/ui";
import { InfoHint } from "./InfoHint";
import type { HelpTopicId } from "@/lib/docs";

/**
 * Authn Platform — Editable settings row
 * File: apps/web-account/src/components/EditableRow.tsx
 *
 * A `SettingsRow` whose value can be changed in place: the current value with an
 * Edit button, becoming a field with Save and Cancel.
 *
 * In place rather than in a dialog, for the single-field settings. A dialog for one
 * text box costs a scrim, a focus trap and a return-focus dance to change something
 * the reader is already looking at, and it hides the rest of the card while they do
 * — so on Profile, where the point is that four related facts are visible at once,
 * it takes away the very thing that made the page readable. Dialogs are kept for
 * what genuinely needs the interruption: a step-up, a destructive confirmation.
 *
 * The geometry is copied from `SettingsRow` deliberately rather than composed from
 * it. The two states have to occupy the same box or the card jumps when Edit is
 * pressed, and a wrapper around `SettingsRow` cannot replace that row's value with
 * a form.
 */

/** What a save reports back. Refusals carry the sentence to show under the field. */
export type SaveOutcome = { ok: true } | { ok: false; message: string };

export interface EditableRowProps {
  label: string;
  /** The current value, or null when there is none set. */
  value: string | null;
  /**
   * What to show in place of a value when there is none. Written as a statement
   * about the account — "No username set" — rather than as an instruction, since
   * the Edit button beside it is already the instruction.
   */
  emptyText?: string;
  hint?: string;
  /** The "i" beside the label, for rules a reader wants before they start typing. */
  helpTopic?: HelpTopicId;
  icon?: IconComponent;
  /**
   * Shown at the leading edge in place of the icon plaque, for a row whose value
   * is better seen than read — an avatar being the case that needs it, where the
   * URL in the field is not what the reader is trying to check.
   */
  leading?: ReactNode;
  accent?: Accent;
  inputType?: "text" | "email" | "tel" | "url";
  placeholder?: string;
  autoComplete?: string;
  isMonospace?: boolean;
  /**
   * Refuses a value before it is sent, returning the sentence to show. For rules
   * the client already knows — a handle's shape, a required field — so a reader is
   * told without a round trip.
   */
  validate?: (next: string) => string | null;
  /**
   * True when submitting an empty field is meaningful: clearing a username
   * releases it, where clearing a display name is a mistake.
   */
  canClear?: boolean;
  onSave: (next: string) => Promise<SaveOutcome>;
  /**
   * Rendered under the field while editing — a live availability check, a strength
   * meter. Given the current draft so it does not need its own copy of the state.
   */
  renderAssist?: (draft: string) => ReactNode;
  /** Hides the Edit button. For a field the engine will not currently accept. */
  isReadOnly?: boolean;
  /** Why editing is unavailable, shown in place of the button. */
  readOnlyReason?: string;
  /**
   * A control beside Edit — a Remove, a Resend. Dropped while the row is open,
   * along with Edit itself: the only two answers to a form are save and cancel,
   * and a third button there is a way to lose what has been typed.
   */
  extraAction?: ReactNode;
}

export function EditableRow({
  label,
  value,
  emptyText = "Not set",
  hint,
  helpTopic,
  icon: Glyph,
  leading,
  accent,
  inputType = "text",
  placeholder,
  autoComplete,
  isMonospace = false,
  validate,
  canClear = false,
  onSave,
  renderAssist,
  isReadOnly = false,
  readOnlyReason,
  extraAction,
}: EditableRowProps): ReactNode {
  const [isEditing, setIsEditing] = useState(false);
  const [draft, setDraft] = useState(value ?? "");
  const [message, setMessage] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  const inputRef = useRef<HTMLInputElement>(null);
  const editButtonRef = useRef<HTMLButtonElement>(null);
  const messageId = useId();

  /**
   * The draft follows the stored value while the row is closed, so a value that
   * changed elsewhere — another tab, a refetch after some other save — is what
   * Edit opens with. While open it is left alone: overwriting a half-typed entry
   * because a background reload landed is the worst possible moment to lose it.
   */
  useEffect(() => {
    if (!isEditing) setDraft(value ?? "");
  }, [value, isEditing]);

  const open = useCallback(() => {
    setDraft(value ?? "");
    setMessage(null);
    setIsEditing(true);
  }, [value]);

  /**
   * Focus moves into the field on open and back to the Edit button on close.
   * Without the return trip, cancelling drops focus to the top of the document and
   * a keyboard user has to tab back through the whole page to reach the next row.
   */
  useEffect(() => {
    if (isEditing) inputRef.current?.focus();
  }, [isEditing]);

  const close = useCallback(() => {
    setIsEditing(false);
    setMessage(null);
    // After the row has re-rendered as a value, so the button exists to receive it.
    requestAnimationFrame(() => editButtonRef.current?.focus());
  }, []);

  const submit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();

      const next = draft.trim();

      if (next === (value ?? "")) {
        // Nothing changed. Closing quietly beats a request that would answer 200
        // and a toast that would claim something was saved.
        close();
        return;
      }

      if (next === "" && !canClear) {
        setMessage(`${label} cannot be empty.`);
        inputRef.current?.focus();
        return;
      }

      const refusal = next === "" ? null : validate?.(next);
      if (refusal) {
        setMessage(refusal);
        inputRef.current?.focus();
        return;
      }

      setIsSaving(true);
      setMessage(null);
      const result = await onSave(next);
      setIsSaving(false);

      if (!result.ok) {
        setMessage(result.message);
        inputRef.current?.focus();
        return;
      }

      close();
    },
    [canClear, close, draft, label, onSave, validate, value],
  );

  return (
    <div className="flex flex-wrap items-center justify-between gap-md p-lg not-first:border-t not-first:border-hairline">
      <div className="flex min-w-0 flex-1 basis-[20rem] items-center gap-md">
        {leading ? (
          <span className="mt-xxs shrink-0 self-start">{leading}</span>
        ) : Glyph ? (
          <span className="mt-xxs flex size-9 shrink-0 items-center justify-center self-start rounded-md border border-hairline bg-surface-elevated">
            <Glyph
              variant="line"
              size={16}
              style={accent ? { color: ACCENT_SOLID[accent] } : undefined}
              className={accent ? undefined : "text-ash"}
            />
          </span>
        ) : null}

        <div className="flex min-w-0 flex-1 flex-col gap-xxs">
          <span className="flex items-center gap-xs text-body-sm text-mute">
            {label}
            {helpTopic ? <InfoHint topic={helpTopic} label={label.toLowerCase()} /> : null}
          </span>

          {isEditing ? (
            /* The form element is what makes Enter save. A row of two buttons and an
               input responds to Enter with nothing at all, which is the first thing
               anyone tries after typing. */
            <form onSubmit={submit} className="flex flex-col gap-sm pt-xxs">
              <Input
                ref={inputRef}
                type={inputType}
                value={draft}
                placeholder={placeholder}
                autoComplete={autoComplete}
                autoCapitalize="none"
                spellCheck={false}
                isMonospace={isMonospace}
                isInvalid={message !== null}
                aria-label={label}
                aria-describedby={message ? messageId : undefined}
                disabled={isSaving}
                onChange={(event) => {
                  setDraft(event.target.value);
                  if (message) setMessage(null);
                }}
                onKeyDown={(event) => {
                  // Escape abandons the edit. Handled on the input rather than on
                  // the form, because a form has no key event of its own to cancel.
                  if (event.key === "Escape") {
                    event.preventDefault();
                    close();
                  }
                }}
              />

              {renderAssist ? renderAssist(draft) : null}

              {/* Announced, not merely shown: this is where a rejected value lands,
                  and an `aria-describedby` target reads when the control is reached
                  rather than when its text changes. */}
              {message ? (
                <p id={messageId} role="alert" className="text-caption text-accent-red">
                  {message}
                </p>
              ) : null}

              <div className="flex gap-sm">
                <Button type="submit" size="sm" variant="primary" isLoading={isSaving}>
                  Save
                </Button>
                <Button type="button" size="sm" variant="ghost" disabled={isSaving} onClick={close}>
                  Cancel
                </Button>
              </div>
            </form>
          ) : (
            <>
              {value ? (
                <span
                  className={
                    isMonospace ? "truncate font-mono text-body-md text-ink" : "text-body-md text-ink"
                  }
                >
                  {value}
                </span>
              ) : (
                <span className="text-body-md text-ash">{emptyText}</span>
              )}
              {hint ? <span className="text-caption text-ash">{hint}</span> : null}
            </>
          )}
        </div>
      </div>

      {/* The button is dropped while editing rather than disabled: Save and Cancel
          are inside the form, and a third greyed control beside them is one more
          thing to read past. */}
      {!isEditing &&
        (isReadOnly ? (
          readOnlyReason ? (
            <span className="max-w-compact shrink-0 text-caption text-ash">{readOnlyReason}</span>
          ) : null
        ) : (
          <div className="flex shrink-0 items-center gap-sm">
            {extraAction}
            <Button
              ref={editButtonRef}
              size="sm"
              variant="ghost"
              onClick={open}
              /* Named for assistive technology, where the visible word is enough
                 for a sighted reader who can see which row it belongs to. Six
                 rows of "Edit" is six identical entries in a list of controls. */
              aria-label={`Edit ${label.toLowerCase()}`}
            >
              {value ? "Edit" : "Add"}
            </Button>
          </div>
        ))}
    </div>
  );
}
