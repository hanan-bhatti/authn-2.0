"use client";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { AlertIcon, Button, Dialog, FormField, Input, Select } from "@authn/ui";
import { AuthnErrorCode, type AuthnError } from "@authn/js";
import { asSentence, presentSaveError } from "@/lib/authError";
import type { StepUpFactor } from "@/components/StepUpDialog";

/**
 * Authn Platform — Security questions
 * File: apps/web-account/src/app/account/recovery/SecurityQuestionsDialog.tsx
 *
 * Three to five prompts and their answers, written in one request with the step-up
 * the engine demands.
 *
 * The whole roster in one dialog, because the engine replaces rather than merges:
 * `PUT .../security-questions` states what the set is. A per-row editor would be
 * lying about what saving one row does, and the replace-only rule is deliberate — a
 * partial update would let whoever is holding an unattended session add a single
 * question they already know the answer to.
 *
 * The suggestions are prompts, not a fixed list. Anything can be typed, and the
 * offered ones are chosen for answers that do not change and are not on a public
 * profile: a first employer rather than a mother's maiden name, which is a matter
 * of record in most countries.
 */

/** Engine constants, from `security_questions_service.go`. */
const MIN_QUESTIONS = 3;
const MAX_QUESTIONS = 5;
const MAX_PROMPT_LENGTH = 200;
const MIN_ANSWER_LENGTH = 3;
const MAX_ANSWER_LENGTH = 100;

/**
 * Prompts offered in the picker.
 *
 * Each one is a fact that does not change and is not published: a favourite that
 * shifts with age or a birthplace listed on a public profile would make the whole
 * set weaker without the reader knowing it had.
 */
const SUGGESTED_PROMPTS = [
  "What was the name of your first school?",
  "What was your first employer called?",
  "What street did you live on as a child?",
  "What was the make of your first car or bike?",
  "What is the name of a childhood friend you no longer see?",
  "What was the first concert or match you went to?",
  "What was your childhood nickname?",
  "What was the name of a pet you had growing up?",
] as const;

const CUSTOM_VALUE = "__custom__";

interface Draft {
  key: number;
  /** The chosen suggestion, or CUSTOM_VALUE while the reader is writing their own. */
  choice: string;
  prompt: string;
  answer: string;
}

function emptyDrafts(): Draft[] {
  return Array.from({ length: MIN_QUESTIONS }, (_, index) => ({
    key: index,
    choice: SUGGESTED_PROMPTS[index] ?? CUSTOM_VALUE,
    prompt: SUGGESTED_PROMPTS[index] ?? "",
    answer: "",
  }));
}

/**
 * Folds an answer the way the engine does before it measures or hashes it:
 * lower-cased, outer whitespace trimmed, internal runs collapsed.
 *
 * Copied rather than approximated, because the length check has to agree with the
 * engine's. An answer of three spaces normalises to nothing, and a local check that
 * counted what was typed would pass it and let the request come back 422.
 */
function normalizeAnswer(answer: string): string {
  return answer.trim().toLowerCase().split(/\s+/).filter(Boolean).join(" ");
}

export interface SecurityQuestionsDialogProps {
  isOpen: boolean;
  onClose: () => void;
  /** True when a roster already exists, which makes this a replacement. */
  isReplacing: boolean;
  /** Which credential the account is checked on, from the profile's `hasPassword`. */
  factor: StepUpFactor;
  /** Sends the roster with its step-up. Resolves to an error to keep the dialog open. */
  onSave: (
    questions: { question: string; answer: string }[],
    credential: string,
  ) => Promise<AuthnError | null>;
}

export function SecurityQuestionsDialog({
  isOpen,
  onClose,
  isReplacing,
  factor,
  onSave,
}: SecurityQuestionsDialogProps): ReactNode {
  const [drafts, setDrafts] = useState<Draft[]>(emptyDrafts);
  const [credential, setCredential] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [isWorking, setIsWorking] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    setDrafts(emptyDrafts());
    setCredential("");
    setMessage(null);
    setIsWorking(false);
  }, [isOpen]);

  /* Suggestions already chosen in another row, so the picker cannot offer the same
     prompt twice — the engine refuses a duplicate on its normalised form, and a
     reader who picked the same one from two dropdowns has no way to see why. */
  const takenPrompts = useMemo(
    () => new Set(drafts.map((row) => row.prompt.trim().toLowerCase()).filter(Boolean)),
    [drafts],
  );

  const edit = useCallback((key: number, patch: Partial<Draft>) => {
    setDrafts((rows) => rows.map((row) => (row.key === key ? { ...row, ...patch } : row)));
    setMessage(null);
  }, []);

  const addRow = useCallback(() => {
    setDrafts((rows) => {
      const unused = SUGGESTED_PROMPTS.find(
        (prompt) => !rows.some((row) => row.prompt === prompt),
      );
      return [
        ...rows,
        {
          key: (rows.at(-1)?.key ?? 0) + 1,
          choice: unused ?? CUSTOM_VALUE,
          prompt: unused ?? "",
          answer: "",
        },
      ];
    });
  }, []);

  const removeRow = useCallback((key: number) => {
    setDrafts((rows) => rows.filter((row) => row.key !== key));
  }, []);

  const submit = useCallback(async () => {
    const rows = drafts.map((row) => ({
      question: row.prompt.trim(),
      answer: row.answer,
    }));

    // Every rule the engine enforces, checked in the same order, so the reader is
    // told which numbered row is wrong instead of being handed a 422 about the set.
    const blank = rows.findIndex((row) => row.question === "");
    if (blank !== -1) {
      setMessage(`Question ${blank + 1} has no prompt. Pick one or write your own.`);
      return;
    }
    const long = rows.findIndex((row) => row.question.length > MAX_PROMPT_LENGTH);
    if (long !== -1) {
      setMessage(`Question ${long + 1} is too long. Keep it under ${MAX_PROMPT_LENGTH} characters.`);
      return;
    }
    const seen = new Set<string>();
    for (const [index, row] of rows.entries()) {
      const key = normalizeAnswer(row.question);
      if (seen.has(key)) {
        setMessage(`Question ${index + 1} repeats an earlier one. Each has to ask something different.`);
        return;
      }
      seen.add(key);
    }
    const shortAnswer = rows.findIndex(
      (row) => normalizeAnswer(row.answer).length < MIN_ANSWER_LENGTH,
    );
    if (shortAnswer !== -1) {
      setMessage(
        `The answer to question ${shortAnswer + 1} is too short. It needs at least ${MIN_ANSWER_LENGTH} characters.`,
      );
      return;
    }
    const longAnswer = rows.findIndex(
      (row) => normalizeAnswer(row.answer).length > MAX_ANSWER_LENGTH,
    );
    if (longAnswer !== -1) {
      setMessage(
        `The answer to question ${longAnswer + 1} is too long. Keep it under ${MAX_ANSWER_LENGTH} characters.`,
      );
      return;
    }
    if (credential.trim() === "") {
      setMessage(
        factor === "password"
          ? "Enter your password to save these."
          : "Enter the current code from your authenticator app to save these.",
      );
      return;
    }

    setIsWorking(true);
    setMessage(null);
    const error = await onSave(rows, credential.trim());
    setIsWorking(false);

    if (!error) return;

    /* A wrong credential and a missing one are answered here rather than by the
       shared presenter, which maps both to "your session ended" — advice that would
       send someone with a working session to sign in again. */
    if (
      error.code === AuthnErrorCode.INVALID_CREDENTIALS ||
      error.code === AuthnErrorCode.STEP_UP_REQUIRED
    ) {
      setMessage(asSentence(error.message) ?? "That did not work. Try again.");
      setCredential("");
      return;
    }
    setMessage(presentSaveError(error, "security questions"));
  }, [credential, drafts, factor, onSave]);

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title={isReplacing ? "Replace your security questions" : "Set up security questions"}
      description={
        isReplacing
          ? "Saving replaces the whole set. The questions you had are removed and only these will be asked."
          : "Between three and five questions. Recovery asks for every answer, so pick facts you will still know years from now."
      }
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
        <div className="flex items-start gap-sm rounded-md border border-hairline bg-surface-elevated p-md">
          <AlertIcon variant="line" size={16} className="mt-px shrink-0 text-ash" />
          <p className="text-caption text-charcoal">
            Capitals and extra spaces are ignored when an answer is checked, so
            &ldquo;Green Lane&rdquo; and &ldquo;green lane&rdquo; both match. Answers are
            stored the way a password is — we cannot read them back to you, and neither
            can anyone else.
          </p>
        </div>

        <ul className="flex flex-col gap-lg">
          {drafts.map((row, index) => (
            <li key={row.key} className="flex flex-col gap-sm rounded-md border border-hairline p-md">
              <div className="flex items-baseline justify-between gap-sm">
                <span className="text-body-sm text-mute">Question {index + 1}</span>
                {/* Only while above the minimum, so the form cannot be walked into a
                    state the engine refuses. */}
                {drafts.length > MIN_QUESTIONS ? (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    disabled={isWorking}
                    onClick={() => removeRow(row.key)}
                  >
                    Remove
                  </Button>
                ) : null}
              </div>

              <Select
                aria-label={`Question ${index + 1} prompt`}
                value={row.choice}
                disabled={isWorking}
                options={[
                  ...SUGGESTED_PROMPTS.filter(
                    (prompt) =>
                      prompt === row.prompt || !takenPrompts.has(prompt.toLowerCase()),
                  ).map((prompt) => ({ value: prompt, label: prompt })),
                  { value: CUSTOM_VALUE, label: "Write my own question…" },
                ]}
                onChange={(event) => {
                  const next = event.target.value;
                  edit(row.key, {
                    choice: next,
                    // Cleared when switching to custom so the reader is not editing a
                    // suggestion they did not choose to keep.
                    prompt: next === CUSTOM_VALUE ? "" : next,
                  });
                }}
              />

              {row.choice === CUSTOM_VALUE ? (
                <FormField label="Your question" isRequired>
                  <Input
                    value={row.prompt}
                    maxLength={MAX_PROMPT_LENGTH}
                    placeholder="Something only you would know the answer to"
                    autoComplete="off"
                    disabled={isWorking}
                    onChange={(event) => edit(row.key, { prompt: event.target.value })}
                  />
                </FormField>
              ) : null}

              <FormField label="Answer" isRequired>
                <Input
                  /* Shown rather than masked. The reader is setting this up in private
                     and needs to see what they typed — an answer they cannot check is
                     an answer they will fail to reproduce, and the whole point of this
                     factor is reproducing it under pressure years later. */
                  type="text"
                  value={row.answer}
                  maxLength={MAX_ANSWER_LENGTH + 20}
                  /* `off` and not a password-manager hint: these are not credentials a
                     manager should file, and an autofilled answer defeats the factor. */
                  autoComplete="off"
                  disabled={isWorking}
                  onChange={(event) => edit(row.key, { answer: event.target.value })}
                />
              </FormField>
            </li>
          ))}
        </ul>

        {drafts.length < MAX_QUESTIONS ? (
          <div>
            <Button type="button" variant="secondary" size="sm" disabled={isWorking} onClick={addRow}>
              Add another question
            </Button>
          </div>
        ) : null}

        <FormField
          label={factor === "password" ? "Your password" : "Code from your authenticator app"}
          isRequired
          hint={
            factor === "password"
              ? "Confirms it is you, because these questions are a permanent way back into the account."
              : "This account has no password, so its authenticator code is what confirms the change."
          }
        >
          <Input
            type={factor === "password" ? "password" : "text"}
            value={credential}
            autoComplete={factor === "password" ? "current-password" : "one-time-code"}
            inputMode={factor === "password" ? undefined : "numeric"}
            maxLength={factor === "password" ? undefined : 6}
            isMonospace={factor !== "password"}
            disabled={isWorking}
            onChange={(event) => {
              setCredential(
                factor === "password"
                  ? event.target.value
                  : event.target.value.replace(/\D/g, ""),
              );
              if (message) setMessage(null);
            }}
          />
        </FormField>

        {message ? <p className="text-body-sm text-accent-red">{message}</p> : null}

        <div className="flex justify-end gap-sm">
          <Button type="button" variant="ghost" disabled={isWorking} onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" isLoading={isWorking}>
            {isReplacing ? "Replace them" : "Save them"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
