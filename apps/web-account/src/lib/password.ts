/**
 * Authn Platform — Password policy evaluation
 * File: apps/web-account/src/lib/password.ts
 *
 * A local mirror of the engine's own check, so the meter beside the field agrees
 * with the answer the request will get. Divergence here is worse than having no
 * meter at all: a field that accepts what the API refuses reads as a broken
 * site rather than a rule the user broke.
 */

import type { PasswordRules } from "@authn/js";
import { characterLength } from "./text";

/**
 * The engine's criterion names, verbatim.
 *
 * A refusal comes back with `missing_criteria: ["min_length", "require_numeric"]`,
 * and reusing those strings as the ids here is what lets a server answer mark
 * rows in the list the user is already looking at, instead of appearing as a
 * second, differently-worded verdict below it.
 */
export type CriterionId =
  | "min_length"
  | "max_length"
  | "require_uppercase"
  | "require_lowercase"
  | "require_numeric"
  | "require_special";

export interface Criterion {
  id: CriterionId;
  label: string;
  met: boolean;
}

/**
 * Each class is one Unicode general category, matching the `unicode.Is*`
 * predicate the engine uses. A codepoint belongs to exactly one category, so
 * testing them independently here is equivalent to the engine's single pass that
 * classifies each character once.
 */
const CLASS_PATTERNS: Record<string, RegExp> = {
  require_uppercase: /\p{Lu}/u,
  require_lowercase: /\p{Ll}/u,
  require_numeric: /\p{Nd}/u,
  // IsPunct covers the P categories and IsSymbol the S categories. Both count,
  // and a space belongs to neither.
  require_special: /[\p{P}\p{S}]/u,
};

/**
 * Evaluates a password against the effective policy.
 *
 * Only the rules the tenant actually turned on are returned, so the list under
 * the field is the policy rather than a catalogue of everything the engine can
 * enforce. `max_length` is the exception: it appears only once exceeded, because
 * a ceiling of a few thousand characters is noise as a standing requirement and
 * a genuine refusal once crossed.
 *
 * Every test runs against the NFKC form, because that is what the engine
 * classifies. The difference is not theoretical: "①" is category No, which no
 * digit pattern matches, but it composes to "1", which is Nd. Testing the raw
 * input would report a missing number for a password the engine accepts.
 */
export function evaluatePassword(password: string, rules: PasswordRules): Criterion[] {
  const normalized = password.normalize("NFKC");
  const length = characterLength(password);

  const criteria: Criterion[] = [
    {
      id: "min_length",
      label: `At least ${rules.minLength} characters`,
      met: length >= rules.minLength,
    },
  ];

  if (rules.requireUppercase) {
    criteria.push({
      id: "require_uppercase",
      label: "An uppercase letter",
      met: CLASS_PATTERNS["require_uppercase"]!.test(normalized),
    });
  }
  if (rules.requireLowercase) {
    criteria.push({
      id: "require_lowercase",
      label: "A lowercase letter",
      met: CLASS_PATTERNS["require_lowercase"]!.test(normalized),
    });
  }
  if (rules.requireNumeric) {
    criteria.push({
      id: "require_numeric",
      label: "A number",
      met: CLASS_PATTERNS["require_numeric"]!.test(normalized),
    });
  }
  if (rules.requireSpecial) {
    criteria.push({
      id: "require_special",
      label: "A symbol or punctuation mark",
      met: CLASS_PATTERNS["require_special"]!.test(normalized),
    });
  }

  if (length > rules.maxLength) {
    criteria.push({
      id: "max_length",
      label: `No more than ${rules.maxLength} characters`,
      met: false,
    });
  }

  return criteria;
}

/**
 * Marks the criteria a server refusal named as unmet.
 *
 * The engine is the authority, and it can disagree with the local mirror — a
 * policy changed between the bootstrap fetch and the submit, or a rule this
 * build does not know about. Rather than trusting the local verdict over the
 * one that just came back, the named criteria are forced unmet, and any name
 * this build cannot render is reported so the caller can fall back to prose
 * instead of showing a compliant-looking list beside a rejection.
 */
export function applyServerCriteria(
  criteria: Criterion[],
  missing: readonly string[]
): { criteria: Criterion[]; unrecognised: string[] } {
  const known = new Set(criteria.map((c) => c.id));
  const unrecognised = missing.filter((name) => !known.has(name as CriterionId));

  return {
    criteria: criteria.map((c) => (missing.includes(c.id) ? { ...c, met: false } : c)),
    unrecognised,
  };
}
