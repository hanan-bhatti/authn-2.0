"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Toast, type ToastProps } from "./Toast.js";
import { cn } from "../../utils/cn.js";

/**
 * Authn Platform — Toast host
 * File: packages/ui/src/components/overlays/ToastProvider.tsx
 *
 * `Toast` renders a notification but cannot summon one: it has no host, no queue
 * and no lifetime. This is the half that lets code far from the render tree —
 * a save handler, a failed request — put a message on screen and forget about it.
 *
 * One host per app, mounted once near the root. Notifications are addressed by id
 * so a caller can replace a pending message with its outcome ("Saving…" becoming
 * "Saved") instead of stacking two.
 */

export type ToastTone = NonNullable<ToastProps["type"]>;

export interface ToastOptions {
  title: string;
  description?: string;
  tone?: ToastTone;
  /**
   * Milliseconds on screen, or 0 to stay until dismissed.
   *
   * Defaulted by tone rather than fixed, because how long a message needs is a
   * property of what it says. "Saved" is confirming something the user just
   * watched happen and can go quickly; a failure is usually the only place the
   * reason appears, and taking it away mid-sentence means the user is left
   * knowing something went wrong and not what.
   */
  duration?: number;
  /**
   * Reuses an existing notification's slot. Passing the id of a live toast
   * rewrites it in place, which is how a pending message becomes its result
   * without the two ever being on screen together.
   */
  id?: string;
}

interface ToastRecord extends ToastOptions {
  id: string;
  tone: ToastTone;
  /** Set while the exit transition plays, so the node survives long enough to animate out. */
  leaving?: boolean;
}

export interface ToastApi {
  /** Shows a notification and returns its id, for replacing or dismissing it later. */
  notify: (options: ToastOptions) => string;
  success: (title: string, description?: string) => string;
  error: (title: string, description?: string) => string;
  warning: (title: string, description?: string) => string;
  info: (title: string, description?: string) => string;
  dismiss: (id: string) => void;
}

const DEFAULT_DURATION: Record<ToastTone, number> = {
  success: 4000,
  info: 5000,
  warning: 7000,
  error: 9000,
};

/** How long the exit transition below runs. The node is dropped after it. */
const EXIT_MS = 150;

/**
 * The most notifications shown at once.
 *
 * Past three the newest arrivals push the earlier ones off the readable area, so
 * a burst of failures becomes a column nobody finishes. The oldest is retired to
 * make room, on the grounds that the message a user has already had time to read
 * is the one they need least.
 */
const MAX_VISIBLE = 3;

const ToastContext = createContext<ToastApi | null>(null);

/**
 * Reach the toast host.
 *
 * Throws when there is no host above the caller, rather than returning a no-op:
 * a silent no-op turns "the save failed" into a screen where nothing happened,
 * which is the exact failure a toast exists to prevent.
 */
export function useToast(): ToastApi {
  const api = useContext(ToastContext);
  if (!api) {
    throw new Error(
      "useToast must be used inside <ToastProvider>. Mount it once near the root of the app.",
    );
  }
  return api;
}

export interface ToastProviderProps {
  children: React.ReactNode;
}

export function ToastProvider({ children }: ToastProviderProps): React.JSX.Element {
  const [items, setItems] = useState<ToastRecord[]>([]);

  // Timers are kept out of state: they are not rendered, and putting them in
  // state would make every tick of bookkeeping a re-render of the whole column.
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());
  const seq = useRef(0);

  const clearTimer = useCallback((id: string) => {
    const handle = timers.current.get(id);
    if (handle !== undefined) {
      clearTimeout(handle);
      timers.current.delete(id);
    }
  }, []);

  const remove = useCallback(
    (id: string) => {
      clearTimer(id);
      setItems((current) => current.filter((item) => item.id !== id));
    },
    [clearTimer],
  );

  const dismiss = useCallback(
    (id: string) => {
      clearTimer(id);
      // Flagged, not removed. Dropping the node immediately would cut the exit
      // transition, so the message would vanish rather than leave.
      setItems((current) =>
        current.map((item) => (item.id === id ? { ...item, leaving: true } : item)),
      );
      setTimeout(() => remove(id), EXIT_MS);
    },
    [clearTimer, remove],
  );

  const schedule = useCallback(
    (id: string, duration: number) => {
      clearTimer(id);
      if (duration <= 0) return;
      timers.current.set(
        id,
        setTimeout(() => dismiss(id), duration),
      );
    },
    [clearTimer, dismiss],
  );

  const notify = useCallback(
    (options: ToastOptions): string => {
      const tone = options.tone ?? "info";
      const duration = options.duration ?? DEFAULT_DURATION[tone];
      // The counter, not a random id: two notifications raised in the same tick
      // must not collide, and this is deterministic under test.
      const id = options.id ?? `toast-${++seq.current}`;

      setItems((current) => {
        const record: ToastRecord = { ...options, id, tone, leaving: false };
        const existing = current.findIndex((item) => item.id === id);
        if (existing >= 0) {
          const next = [...current];
          next[existing] = record;
          return next;
        }
        const next = [...current, record];
        return next.length > MAX_VISIBLE ? next.slice(next.length - MAX_VISIBLE) : next;
      });

      schedule(id, duration);
      return id;
    },
    [schedule],
  );

  const api = useMemo<ToastApi>(
    () => ({
      notify,
      success: (title, description) => notify({ title, description, tone: "success" }),
      error: (title, description) => notify({ title, description, tone: "error" }),
      warning: (title, description) => notify({ title, description, tone: "warning" }),
      info: (title, description) => notify({ title, description, tone: "info" }),
      dismiss,
    }),
    [notify, dismiss],
  );

  // Every pending timer is abandoned on unmount, so a dismissal cannot fire into
  // a tree that is gone.
  useEffect(() => {
    const handles = timers.current;
    return () => {
      handles.forEach((handle) => clearTimeout(handle));
      handles.clear();
    };
  }, []);

  return (
    <ToastContext.Provider value={api}>
      {children}
      {/*
        Bottom of the viewport, centred on a phone and trailing-aligned from `sm`
        up. Bottom rather than top because the account pages carry a sticky header
        on narrow screens, and a notification arriving underneath it is a
        notification nobody sees.

        `pointer-events-none` on the column with `pointer-events-auto` on each
        card: the region spans the width of the screen, and without this it would
        swallow clicks on whatever sits beneath it.
      */}
      <div
        className="pointer-events-none fixed inset-x-0 bottom-0 z-[60] flex flex-col items-center gap-sm p-lg sm:items-end"
        // The region is labelled but not itself a live region: each Toast already
        // announces with its own role, and nesting live regions makes some screen
        // readers read the arrival twice.
        aria-label="Notifications"
      >
        {items.map((item) => (
          <div
            key={item.id}
            className={cn(
              "pointer-events-auto w-full max-w-compact transition-all ease-exit",
              "duration-fast",
              item.leaving ? "translate-y-1 opacity-0" : "translate-y-0 opacity-100",
            )}
            // Reading a message should not race its timer. Hover and keyboard
            // focus both hold it open, and leaving restarts it, so a long
            // description is never taken away mid-sentence.
            onMouseEnter={() => clearTimer(item.id)}
            onMouseLeave={() => schedule(item.id, item.duration ?? DEFAULT_DURATION[item.tone])}
            onFocus={() => clearTimer(item.id)}
            onBlur={() => schedule(item.id, item.duration ?? DEFAULT_DURATION[item.tone])}
          >
            <Toast
              type={item.tone}
              title={item.title}
              description={item.description}
              onClose={() => dismiss(item.id)}
              className="w-full"
            />
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
