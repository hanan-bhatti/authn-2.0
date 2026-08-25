import {
  BuildingIcon,
  FingerprintIcon,
  LifeBuoyIcon,
  LinkIcon,
  LockIcon,
  MonitorIcon,
  QrCodeIcon,
  ShieldIcon,
  TrashIcon,
  UserIcon,
  UsersIcon,
  type SidebarSection,
} from "@authn/ui";

/**
 * Authn Platform — Account navigation tree
 * File: apps/web-account/src/lib/accountNav.ts
 *
 * The sidebar's contents, kept out of the shell so a page can ask which row it is
 * without importing a client component.
 *
 * Nesting is only where the hierarchy is real. Security's three children are
 * fragments of the security page rather than routes of their own, and the
 * organisations are fragments of the organisations page — a tree whose second
 * level is invented routes with one card on each is a deeper tree and a worse
 * site. What the nesting buys here is the ability to jump straight to "Passkeys"
 * from anywhere, which is the thing a reader actually wants from it.
 */

/**
 * Every top-level row carries a hue, and the hue is the same one that row's
 * illustration is drawn in. That is the whole reason the two layers share
 * `accent.ts`: arriving on Recovery, the yellow in the sidebar row and the yellow
 * in the buoy are one colour making one statement about where you are, rather
 * than two components that happen to both look warm.
 */
export const ACCOUNT_NAV: readonly SidebarSection[] = [
  {
    id: "account",
    title: "Account",
    nodes: [
      { id: "profile", label: "Profile", href: "/account", icon: UserIcon, accent: "blue" },
      {
        id: "security",
        label: "Security",
        href: "/account/security",
        icon: ShieldIcon,
        accent: "green",
        children: [
          { id: "password", label: "Password", href: "/account/security#password", icon: LockIcon },
          {
            id: "two-factor",
            label: "Two-factor",
            href: "/account/security#two-factor",
            icon: QrCodeIcon,
          },
          {
            id: "passkeys",
            label: "Passkeys",
            href: "/account/security#passkeys",
            icon: FingerprintIcon,
          },
        ],
      },
      {
        id: "sessions",
        label: "Sessions",
        href: "/account/sessions",
        icon: MonitorIcon,
        accent: "orange",
      },
      {
        id: "connections",
        label: "Connected accounts",
        href: "/account/connections",
        icon: LinkIcon,
        accent: "blue",
      },
      {
        id: "recovery",
        label: "Recovery",
        href: "/account/recovery",
        icon: LifeBuoyIcon,
        accent: "yellow",
      },
    ],
  },
  {
    id: "orgs",
    title: "Organizations",
    nodes: [
      {
        id: "organizations",
        label: "Your organizations",
        href: "/account/organizations",
        icon: BuildingIcon,
        accent: "blue",
      },
    ],
  },
  {
    id: "danger",
    nodes: [
      {
        id: "delete",
        label: "Delete account",
        href: "/account/danger",
        icon: TrashIcon,
        accent: "red",
      },
    ],
  },
];

/** The subset of an organization the tree needs to draw a row for it. */
export interface NavOrg {
  id: string;
  name: string;
  slug: string;
}

/**
 * How many workspaces the branch lists before it stops.
 *
 * The branch is a shortcut into a page that shows all of them, so past a handful
 * it stops being a shortcut and starts being a second copy of the page —
 * scrolling the sidebar to find a link to a list is slower than opening the list.
 */
const MAX_ORG_ROWS = 8;

/**
 * The tree with the organization branch filled in from the account's real
 * memberships.
 *
 * A function rather than a mutation of `ACCOUNT_NAV`, so the base tree stays a
 * constant the route matcher below can read without needing to know whether the
 * organizations have loaded yet. Given an empty list — before the request settles,
 * or for an account in no workspaces — it returns the tree unchanged, so the
 * branch simply has no children rather than an expander that opens onto nothing.
 */
export function accountNav(orgs: readonly NavOrg[]): readonly SidebarSection[] {
  if (orgs.length === 0) return ACCOUNT_NAV;

  const children = orgs.slice(0, MAX_ORG_ROWS).map((org) => ({
    // Prefixed, because an organization id is only unique among organizations and
    // the sidebar's ids address every row in the tree.
    id: `org-${org.id}`,
    label: org.name,
    // The card's own anchor on the organizations page. The slug and not the id:
    // it is in the address bar after the jump, and a slug says which workspace
    // where an opaque id says nothing.
    href: `/account/organizations#${org.slug}`,
    icon: UsersIcon,
  }));

  return ACCOUNT_NAV.map((section) =>
    section.id === "orgs"
      ? {
          ...section,
          nodes: section.nodes.map((node) =>
            node.id === "organizations" ? { ...node, children } : node,
          ),
        }
      : section,
  );
}

/**
 * Which row a pathname corresponds to.
 *
 * Longest match wins, which is what makes `/account/security` resolve to Security
 * rather than to Profile — every account path starts with `/account`, so a
 * first-match scan would light up Profile on all seven pages. The fragment-only
 * children are skipped: two rows cannot both be `aria-current="page"`, and the
 * page is the parent.
 */
export function activeNavId(pathname: string): string | undefined {
  let bestId: string | undefined;
  let bestLength = 0;

  for (const section of ACCOUNT_NAV) {
    for (const node of section.nodes) {
      const href = node.href;
      if (href === undefined || href.includes("#")) continue;
      if (pathname === href || pathname.startsWith(`${href}/`)) {
        if (href.length > bestLength) {
          bestId = node.id;
          bestLength = href.length;
        }
      }
    }
  }

  return bestId;
}
