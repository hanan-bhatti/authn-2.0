"use client";

import React from "react";
import { Label } from "./Label.js";
import { cn } from "../../utils/cn.js";

export interface FormFieldProps {
  label?: React.ReactNode;
  isRequired?: boolean;
  monospaceTag?: string;
  error?: string;
  hint?: string;
  children: React.ReactNode;
  className?: string;
}

/**
 * Wires a label, a control and its message into one accessible field.
 *
 * The three have to be linked by id or the association exists only visually: a
 * screen reader lands on the input and reads "edit text, blank", with the label
 * above it and the reason it was rejected below it both unreachable. So this
 * generates an id, hands it to the control, points the label at it, and names
 * the message in `aria-describedby`.
 *
 * A control that already carries an `id` keeps it — a page wiring its own
 * refs or a native `form.elements` lookup depends on that id being the one it
 * chose.
 *
 * Client-side because `useId` is a hook. The controls this wraps are client
 * components already, so the boundary is where it would have fallen anyway.
 */
export const FormField: React.FC<FormFieldProps> = ({
  label,
  isRequired = false,
  monospaceTag,
  error,
  hint,
  children,
  className,
}) => {
  const generatedId = React.useId();

  // Only a single element can be described; a fragment or a plain string has no
  // props to write to, and cloning it would throw.
  const control = React.isValidElement<{
    id?: string;
    "aria-describedby"?: string;
    "aria-invalid"?: boolean;
  }>(children)
    ? children
    : null;

  const controlId = control?.props.id ?? generatedId;
  const messageId = error ? `${controlId}-error` : hint ? `${controlId}-hint` : undefined;

  // The hint is dropped rather than stacked under the error, so a field showing
  // why it was refused never also shows the rule it broke as if both applied.
  const message = error ?? hint;

  return (
    <div className={cn("flex flex-col w-full gap-1", className)}>
      {label && (
        <Label htmlFor={controlId} isRequired={isRequired} monospaceTag={monospaceTag}>
          {label}
        </Label>
      )}

      {control
        ? React.cloneElement(control, {
            id: controlId,
            "aria-describedby":
              [control.props["aria-describedby"], messageId].filter(Boolean).join(" ") || undefined,
            "aria-invalid": error ? true : control.props["aria-invalid"],
          })
        : children}

      {message && (
        <span
          id={messageId}
          className={cn(
            "text-[11px] font-sans mt-1",
            error ? "text-accent-red" : "text-mute"
          )}
        >
          {message}
        </span>
      )}
    </div>
  );
};
