"use client";

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type MouseEvent,
  type ReactNode,
} from "react";
import { Chevron } from "../display/Chevron.js";
import type { IconComponent } from "../../icons/createIcon.js";
import { type Accent, ACCENT_SOLID, tint } from "../../utils/accent.js";
import { cn } from "../../utils/cn.js";

/**
 * Authn Platform — Sidebar
 * File: packages/ui/src/components/navigation/Sidebar.tsx
 *
 * A nested navigation tree that is a permanent rail from `md` up and a drawer
 * below it.
 *
 * Built as `nav > ul > li` with real links rather than as `role="tree"`, and that
 * is a deliberate refusal of the closest-matching ARIA pattern. A tree widget is
 * one tab stop for the entire thing: you Tab into it once and then arrow between
 * items. That is right for a file explorer, where you are surveying a hierarchy
 * and most nodes are not destinations. It is wrong here, where every leaf is a
 * page someone wants to reach — under `role="tree"` a keyboard user cannot Tab to
 * "Sessions", they have to enter the widget and press Down the right number of
 * times, and the browser's own find-and-Enter stops working. Nested lists of
 * links cost nothing, are navigable by every assistive technology's link list,
 * and survive JavaScript failing to load.
 */

/**
 * One row. A node with `children` is a branch; a node with an `href` is a
 * destination; a node with both is both, and gets two hit targets.
 */
export interface SidebarNode {
  id: string;
  label: string;
  href?: string;
  /**
   * The icon component, not a rendered element — the sidebar switches to the
   * `filled` cut on the active row, which it can only do if it owns the render.
   */
  icon?: IconComponent;
  /**
   * The row's hue. Inherited by descendants that do not set their own, so a
   * branch is one colour: a child of Security rendered in blue reads as a
   * mis-nested row rather than as a distinction anyone intended.
   *
   * It colours the glyph at all times and the label only on selection. Putting the
   * hue on the label too would leave nothing for `aria-current`'s visual twin to
   * use — five permanently coloured labels are five things claiming emphasis, and a
   * reader scanning them cannot tell which one they are standing on. The glyph can
   * hold colour indefinitely because it is not the thing being read.
   *
   * Left off entirely, a row is monochrome until it is the active one, which is the
   * right default for a run of rows that are variations on one subject rather than
   * separate destinations.
   */
  accent?: Accent;
  badge?: ReactNode;
  children?: readonly SidebarNode[];
  disabled?: boolean;
}

/** A labelled run of top-level nodes, separated from its neighbours by space. */
export interface SidebarSection {
  id: string;
  title?: string;
  nodes: readonly SidebarNode[];
}

/**
 * The props a link receives, so an application can supply its router's link
 * component instead of the bare anchor.
 *
 * Without this the sidebar would either render `<a href>` — correct semantics,
 * but a full document load on every click in a single-page app — or a `<button>`
 * calling `router.push`, which loses middle-click, cmd-click, "copy link
 * address" and the status-bar preview. Taking the component keeps the anchor and
 * gets client-side navigation.
 */
export interface SidebarLinkProps {
  href: string;
  className?: string;
  style?: CSSProperties;
  "aria-current"?: "page";
  onClick?: (event: MouseEvent<HTMLAnchorElement>) => void;
  children: ReactNode;
}

export type SidebarLinkComponent = (props: SidebarLinkProps) => ReactNode;

export interface SidebarProps {
  sections: readonly SidebarSection[];
  /**
   * The id of the node the current page corresponds to. Its ancestors are
   * expanded and marked, so a collapsed branch still shows that the page inside
   * it is the one you are on.
   */
  activeId?: string;
  linkAs?: SidebarLinkComponent;
  /** Fires after a link is followed, which is what closes the drawer. */
  onNavigate?: (node: SidebarNode) => void;
  header?: ReactNode;
  footer?: ReactNode;
  /** Drawer state, below `md` only. The rail above it ignores both. */
  isOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
  className?: string;
}

const Anchor: SidebarLinkComponent = ({ children, ...rest }) => <a {...rest}>{children}</a>;

/**
 * The chain of ids from the outermost node down to `activeId`, inclusive.
 *
 * Depth-first with the path carried down rather than a parent map built up,
 * because the result is wanted as a path: a map would then have to be walked
 * backwards from the leaf, which needs a second lookup structure to answer
 * "is this node an ancestor of the active one" — the only question the caller has.
 */
function findTrail(
  nodes: readonly SidebarNode[],
  activeId: string,
  path: string[] = [],
): string[] {
  for (const node of nodes) {
    const here = [...path, node.id];
    if (node.id === activeId) return here;
    if (node.children) {
      const found = findTrail(node.children, activeId, here);
      if (found.length > 0) return found;
    }
  }
  return [];
}

interface RowProps {
  node: SidebarNode;
  accent: Accent | undefined;
  activeId: string | undefined;
  trail: Set<string>;
  expanded: Set<string>;
  onToggle: (id: string) => void;
  linkAs: SidebarLinkComponent;
  onNavigate: ((node: SidebarNode) => void) | undefined;
}

function Row({
  node,
  accent,
  activeId,
  trail,
  expanded,
  onToggle,
  linkAs: Link,
  onNavigate,
}: RowProps): ReactNode {
  const hue = node.accent ?? accent;
  const isActive = node.id === activeId;
  const isOnTrail = trail.has(node.id) && !isActive;
  const branch = node.children !== undefined && node.children.length > 0;
  const isExpanded = branch && expanded.has(node.id);
  const Glyph = node.icon;

  /**
   * One branch, so exactly one text-colour class is ever emitted. `cn` in this
   * package is plain concatenation rather than `tailwind-merge`, so a row that
   * emitted both `text-mute` and `text-ink` would be decided by the order Tailwind
   * happened to generate those two rules in — which is not something a component
   * should depend on, and not something a reader of this file could check.
   */
  const tone = node.disabled
    ? "pointer-events-none text-mute opacity-40"
    : isActive
      ? hue
        ? ""
        : "bg-ink/[0.06] text-ink"
      : isOnTrail
        ? "text-ink hover:bg-ink/[0.04]"
        : "text-mute hover:bg-ink/[0.04] hover:text-ink";

  /**
   * Every row carries a transparent border and the active one recolours it from
   * here. Swapping in a border class instead would grow the row by two pixels the
   * moment it is selected, and because every row below shifts by the same amount,
   * navigating makes the whole column jog.
   *
   * The recolour is inline rather than a class for the same reason the accent
   * itself is: five hues times four states is twenty classes Tailwind would have
   * to be told about in advance, and it cannot see them in a template literal.
   */
  const rowClass = cn(
    "group flex h-9 min-w-0 flex-1 items-center gap-sm rounded-md border border-transparent",
    "px-sm text-left text-body-sm transition-colors duration-fast ease-standard",
    tone,
  );

  const activeStyle: CSSProperties | undefined = !isActive
    ? undefined
    : hue
      ? {
          color: ACCENT_SOLID[hue],
          backgroundColor: tint(hue, 0.1),
          borderColor: tint(hue, 0.28),
        }
      : { borderColor: "var(--color-hairline-strong)" };

  /**
   * The glyph is always its hue; only the strength moves. Colour therefore belongs
   * to the row permanently and selection is carried by the label, the fill and the
   * border — which is what stops the two from saying the same thing twice and
   * leaves the list scannable by colour before it is read.
   *
   * Full strength covers the active row *and* its ancestors, and that second case
   * is what a collapsed branch needs: fold Organizations away while sitting on a
   * page inside it and the label goes back to looking ordinary, so the lit glyph is
   * the only thing left saying the page you are on is in there.
   */
  const glyphStyle: CSSProperties | undefined = !hue
    ? undefined
    : { color: isActive || isOnTrail ? ACCENT_SOLID[hue] : tint(hue, 0.68) };

  const chevron = (
    <Chevron direction={isExpanded ? "down" : "right"} size="sm" className="text-ash" />
  );

  const body = (
    <>
      {Glyph ? (
        <Glyph variant={isActive ? "filled" : "line"} size={16} style={glyphStyle} />
      ) : (
        <span aria-hidden="true" className="size-4 shrink-0" />
      )}
      <span className="truncate">{node.label}</span>
      {node.badge ? <span className="ml-auto shrink-0 pl-sm">{node.badge}</span> : null}
    </>
  );

  return (
    <li>
      <div className="flex items-center gap-xxs">
        {node.href ? (
          <Link
            href={node.href}
            className={rowClass}
            style={activeStyle}
            aria-current={isActive ? "page" : undefined}
            onClick={() => onNavigate?.(node)}
          >
            {body}
          </Link>
        ) : (
          <button
            type="button"
            className={cn(rowClass, "cursor-pointer")}
            style={activeStyle}
            aria-expanded={branch ? isExpanded : undefined}
            disabled={node.disabled}
            onClick={() => branch && onToggle(node.id)}
          >
            {body}
            {branch ? <span className="ml-auto pl-sm">{chevron}</span> : null}
          </button>
        )}

        {/* A branch that is also a link gets a disclosure button of its own. Folding
            the chevron into the link would make opening a branch impossible without
            leaving the page you are on; making the whole row a button would take the
            parent's own page away. Two targets in one row is the cost of a parent
            that is both. */}
        {branch && node.href ? (
          <button
            type="button"
            className={cn(
              "flex size-7 shrink-0 cursor-pointer items-center justify-center rounded-md",
              "text-ash transition-colors duration-fast ease-standard",
              "hover:bg-ink/[0.04] hover:text-ink",
            )}
            aria-expanded={isExpanded}
            aria-label={`${isExpanded ? "Collapse" : "Expand"} ${node.label}`}
            onClick={() => onToggle(node.id)}
          >
            {chevron}
          </button>
        ) : null}
      </div>

      {/* The rail is a real line, not indentation alone. Same lesson the org-chart
          illustration learned: when the hierarchy is the message, the connector is
          the shape. `ml-4` puts it under the parent's glyph, which is what makes a
          child look hung off its parent rather than merely started further right. */}
      {branch && isExpanded ? (
        <ul className="mt-xxs ml-4 flex flex-col gap-xxs border-l border-hairline-strong pl-sm">
          {node.children?.map((child) => (
            <Row
              key={child.id}
              node={child}
              accent={hue}
              activeId={activeId}
              trail={trail}
              expanded={expanded}
              onToggle={onToggle}
              linkAs={Link}
              onNavigate={onNavigate}
            />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

export function Sidebar({
  sections,
  activeId,
  linkAs = Anchor,
  onNavigate,
  header,
  footer,
  isOpen = false,
  onOpenChange,
  className,
}: SidebarProps): ReactNode {
  const trail = useMemo(() => {
    if (!activeId) return [] as string[];
    for (const section of sections) {
      const found = findTrail(section.nodes, activeId);
      if (found.length > 0) return found;
    }
    return [] as string[];
  }, [sections, activeId]);

  const trailSet = useMemo(() => new Set(trail), [trail]);

  /**
   * Seeded from the active trail, then unioned with it on every change rather
   * than replaced by it. Replacing would close a branch the reader had opened by
   * hand the instant they navigated somewhere else, which makes comparing two
   * branches impossible — and nothing about arriving on a new page is a reason to
   * undo a choice they made about a different one.
   */
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set(trail));

  useEffect(() => {
    if (trail.length === 0) return;
    setExpanded((current) => {
      const next = new Set(current);
      let grew = false;
      for (const id of trail) {
        if (!next.has(id)) {
          next.add(id);
          grew = true;
        }
      }
      return grew ? next : current;
    });
  }, [trail]);

  const toggle = useCallback((id: string) => {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const tree = (
    <>
      {header ? <div className="shrink-0 pb-lg">{header}</div> : null}

      {/* The scroller carries its own horizontal padding. The global focus ring is
          drawn with a two-pixel outline offset by two more, and an `overflow-y-auto`
          box clips on both axes — without the padding a focused row's ring would be
          shaved off flush against the sidebar's edge. */}
      <nav
        aria-label="Account"
        className="flex min-h-0 flex-1 flex-col gap-xl overflow-y-auto px-xs"
      >
        {sections.map((section) => (
          <div key={section.id} className="flex flex-col gap-xs">
            {section.title ? (
              <h2 className="px-sm pb-xxs font-mono text-caption uppercase tracking-wider text-ash">
                {section.title}
              </h2>
            ) : null}
            <ul className="flex flex-col gap-xxs">
              {section.nodes.map((node) => (
                <Row
                  key={node.id}
                  node={node}
                  accent={node.accent}
                  activeId={activeId}
                  trail={trailSet}
                  expanded={expanded}
                  onToggle={toggle}
                  linkAs={linkAs}
                  onNavigate={onNavigate}
                />
              ))}
            </ul>
          </div>
        ))}
      </nav>

      {footer ? (
        <div className="shrink-0 border-t border-hairline-strong pt-lg">{footer}</div>
      ) : null}
    </>
  );

  const shell = cn(
    "flex w-64 shrink-0 select-none flex-col gap-lg bg-canvas p-lg",
    "border-r border-hairline-strong",
    className,
  );

  return (
    <>
      <aside className={cn(shell, "sticky top-0 hidden h-dvh md:flex")}>{tree}</aside>
      <Drawer isOpen={isOpen} onOpenChange={onOpenChange} className={shell}>
        {tree}
      </Drawer>
    </>
  );
}

interface DrawerProps {
  isOpen: boolean;
  onOpenChange: ((open: boolean) => void) | undefined;
  className: string;
  children: ReactNode;
}

/**
 * The `md` breakpoint, as a query rather than a class.
 *
 * The drawer's own `md:hidden` handles the *appearance* at desktop width, but
 * scroll-locking and the Escape handler are JavaScript and would survive the
 * panel going invisible — resize a phone-width window past 768 with the drawer
 * open and the page becomes unscrollable with nothing on screen to close. The
 * query exists so the drawer can close itself instead.
 */
const DESKTOP = "(min-width: 768px)";

/**
 * The same tree, off-canvas, below `md`.
 *
 * Not built on `Sheet`. A sheet is a dialog: it comes with a titled header, a
 * close button in that header and a footer for actions, and none of that is
 * furniture navigation wants — the drawer's whole content is the nav, and a
 * heading above it would only name the thing the reader is already looking at.
 * What is worth borrowing from a dialog is the behaviour, which is the effects
 * below.
 */
function Drawer({ isOpen, onOpenChange, className, children }: DrawerProps): ReactNode {
  const panel = useRef<HTMLElement>(null);
  const opener = useRef<Element | null>(null);

  useEffect(() => {
    if (!isOpen) return;

    /* Recorded on open rather than read back on close, because by then the drawer
       has already taken focus and `document.activeElement` is inside it. */
    opener.current = document.activeElement;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onOpenChange?.(false);
    };
    window.addEventListener("keydown", onKeyDown);

    const desktop = window.matchMedia(DESKTOP);
    const onBreakpoint = (event: MediaQueryListEvent) => {
      if (event.matches) onOpenChange?.(false);
    };
    desktop.addEventListener("change", onBreakpoint);

    const scroll = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    panel.current?.querySelector<HTMLElement>("a, button")?.focus();

    return () => {
      window.removeEventListener("keydown", onKeyDown);
      desktop.removeEventListener("change", onBreakpoint);
      document.body.style.overflow = scroll;
      /* Only when focus is still inside the panel that is going away. Restoring it
         unconditionally would yank the caret out of whatever the reader moved to in
         the meantime — a link they followed, a field they clicked. */
      if (panel.current?.contains(document.activeElement)) {
        (opener.current as HTMLElement | null)?.focus?.();
      }
    };
  }, [isOpen, onOpenChange]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex md:hidden">
      <div
        className="fixed inset-0 bg-canvas/80 backdrop-blur-[25px] animate-enter-fade"
        onClick={() => onOpenChange?.(false)}
      />
      <aside
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-label="Account navigation"
        className={cn(className, "relative z-10 h-dvh max-w-[85vw] animate-enter-slide-left")}
      >
        {children}
      </aside>
    </div>
  );
}
