import React from "react";
import { cn } from "../../utils/cn.js";

/**
 * Authn Platform — Loading placeholder
 * File: packages/ui/src/components/overlays/Skeleton.tsx
 *
 * A bar standing in for content that has not arrived. The variants exist so a
 * placeholder can be the size of the thing it replaces: swapping a `text` bar for
 * a real line of text does not move the page, where a one-size placeholder resizes
 * everything below it the moment the answer lands.
 */

export interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "control" | "card" | "text" | "avatar";
}

export const Skeleton: React.FC<SkeletonProps> = ({
  className,
  variant = "text",
  style,
  ...props
}) => {
  const variantStyles = {
    control: "h-10 w-full rounded-md",
    card: "h-32 w-full rounded-lg",
    text: "h-4 w-3/4 rounded-xs",
    avatar: "h-8 w-8 rounded-full flex-shrink-0",
  };

  return (
    <div
      className={cn(
        /* A band travelling across the bar rather than the whole bar fading in and
           out. Both say "waiting", but a pulse dims the placeholder to nearly the
           background at the bottom of its cycle, so a column of them flickers as a
           block; the sweep keeps every bar continuously visible and reads as one
           surface being filled in.

           The gradient is 200% wide so there is somewhere for the highlight to
           travel from and to — at 100% the keyframes' `-200%` and `200%` positions
           would both be off the element and nothing would appear to move. */
        "animate-shimmer bg-[length:200%_100%]",
        "bg-[linear-gradient(90deg,var(--color-hairline)_0%,var(--color-hairline-strong)_50%,var(--color-hairline)_100%)]",
        /* Held still for anyone who has asked the system for that. The bar stays
           at the strong tone so it is unmistakably a placeholder and not an empty
           space the layout left behind. */
        "motion-reduce:animate-none motion-reduce:bg-hairline-strong motion-reduce:bg-none",
        variantStyles[variant],
        className
      )}
      style={style}
      {...props}
    />
  );
};
