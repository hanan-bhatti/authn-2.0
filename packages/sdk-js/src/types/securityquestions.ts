/**
 * @authn/js — Security Question Types
 *
 * The last-resort recovery factor: a set of prompts the account holder answers,
 * stored as Argon2id digests. Routes: /v1/client/account/security-questions.
 *
 * @packageDocumentation
 */

import type { AuthnError } from "./errors";

/**
 * SecurityQuestion is a prompt as the engine returns it.
 *
 * There is no answer field of any kind, at any point, in either direction of a
 * read. {@link id} is what a proof is keyed by, so it has to survive a round trip
 * even though nothing displays it.
 */
export interface SecurityQuestion {
  id: string;
  question: string;
}

/**
 * SecurityQuestionInput is one prompt and its answer, on the way in.
 *
 * The answer is folded before hashing — lower-cased, outer whitespace trimmed,
 * internal runs collapsed to one space — so the person answering months later on
 * another keyboard is not refused over capitalisation. Length is measured in
 * characters after that folding, not bytes, so a non-Latin answer is not charged
 * extra for its encoding.
 */
export interface SecurityQuestionInput {
  question: string;
  answer: string;
}

/**
 * SetSecurityQuestionsParams replaces the whole roster.
 *
 * Replace, not append: the request states what the set is. Sending a shorter list
 * removes the questions not in it.
 *
 * One of `password` or `totpCode` is required — enrolling this factor needs a
 * step-up, because unlike a guardian invitation or a recovery address it needs no
 * second party to confirm, so a session someone walked up to would otherwise be
 * enough to install a permanent way back into the account. Send the password if
 * the account has one; an account with none is checked on its authenticator code.
 * The engine answers 401 `step_up_required` naming which of the two it wants.
 */
export interface SetSecurityQuestionsParams {
  questions: SecurityQuestionInput[];
  password?: string;
  totpCode?: string;
}

/** DeleteSecurityQuestionsParams carries the same step-up as a write. */
export interface DeleteSecurityQuestionsParams {
  password?: string;
  totpCode?: string;
}

/**
 * SecurityQuestionsResult reports the enrolled roster.
 *
 * An account with none reads `ok: false` with a `NOT_FOUND` error rather than an
 * empty array: the caller asked whether this factor is set up, and the engine
 * answers 404 to say it is not.
 */
export type SecurityQuestionsResult =
  | { ok: true; questions: SecurityQuestion[]; total: number; message?: string }
  | { ok: false; error: AuthnError };
