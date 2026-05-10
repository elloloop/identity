// Single source of truth for the documentation nav. Used by:
//   - the sidebar (rendered in DocsLayout)
//   - breadcrumbs
//   - prev/next links at the bottom of every page
//
// Keep `href` paths in sync with the file paths under src/pages/.

export interface NavItem {
  label: string;
  href: string;
}

export interface NavSection {
  title: string;
  items: NavItem[];
}

export const BASE = "/identity";

export const sidebarSections: NavSection[] = [
  {
    title: "Getting Started",
    items: [
      { label: "Introduction", href: `${BASE}/` },
      { label: "What is Identity", href: `${BASE}/docs/introduction` },
      { label: "Quick Start", href: `${BASE}/docs/quickstart` },
    ],
  },
  {
    title: "Concepts",
    items: [
      { label: "Architecture", href: `${BASE}/docs/concepts/architecture` },
      { label: "Auth Model", href: `${BASE}/docs/concepts/auth-model` },
      { label: "Sessions", href: `${BASE}/docs/concepts/sessions` },
      { label: "Multi-Tenancy", href: `${BASE}/docs/concepts/multi-tenancy` },
    ],
  },
  {
    title: "Installation",
    items: [
      { label: "Docker", href: `${BASE}/docs/installation/docker` },
      { label: "Configuration", href: `${BASE}/docs/installation/configuration` },
      { label: "JWT Keys", href: `${BASE}/docs/installation/jwt-keys` },
    ],
  },
  {
    title: "Authentication",
    items: [
      { label: "Password", href: `${BASE}/docs/auth/password` },
      { label: "Invitations", href: `${BASE}/docs/auth/invitations` },
      { label: "OAuth", href: `${BASE}/docs/auth/oauth` },
      { label: "Passkey", href: `${BASE}/docs/auth/passkey` },
      { label: "TOTP (2FA)", href: `${BASE}/docs/auth/totp` },
      { label: "Identity Verification (KYC)", href: `${BASE}/docs/auth/identity-verification` },
    ],
  },
  {
    title: "Users & Groups",
    items: [
      { label: "User Management", href: `${BASE}/docs/users/management` },
    ],
  },
  {
    title: "API Reference",
    items: [
      { label: "gRPC Services", href: `${BASE}/docs/api-reference/grpc` },
    ],
  },
  {
    title: "Operations",
    items: [
      { label: "Audit Logging", href: `${BASE}/docs/operations/audit-logging` },
      { label: "Observability", href: `${BASE}/docs/operations/observability` },
      { label: "Password Toggle Rollout", href: `${BASE}/docs/operations/password-toggle-rollout` },
    ],
  },
  {
    title: "Deployment",
    items: [
      { label: "GitHub Actions", href: `${BASE}/docs/deployment/github-actions` },
      { label: "Kubernetes", href: `${BASE}/docs/deployment/kubernetes` },
    ],
  },
  {
    title: "Examples",
    items: [
      { label: "Multi-App SSO", href: `${BASE}/docs/examples/multi-app-sso` },
      { label: "Passwordless Onboarding", href: `${BASE}/docs/examples/passwordless-onboarding` },
      { label: "Key Rotation", href: `${BASE}/docs/examples/key-rotation` },
    ],
  },
];

// Flat ordered list with section labels — drives breadcrumbs and prev/next.
export interface FlatNavItem extends NavItem {
  section: string;
}

export const flatNav: FlatNavItem[] = sidebarSections.flatMap((section) =>
  section.items.map((item) => ({ ...item, section: section.title })),
);

// Normalize a path to match how `href` is defined above (strip trailing slash,
// keep root as just the BASE).
function normalize(p: string): string {
  if (!p) return p;
  if (p === BASE || p === `${BASE}/`) return `${BASE}/`;
  return p.replace(/\/+$/, "");
}

export function findCurrent(currentPath: string): FlatNavItem | undefined {
  const target = normalize(currentPath);
  return flatNav.find(
    (item) => normalize(item.href) === target || item.href === target,
  );
}

export function findPrevNext(currentPath: string): {
  prev?: FlatNavItem;
  next?: FlatNavItem;
} {
  const target = normalize(currentPath);
  const idx = flatNav.findIndex(
    (item) => normalize(item.href) === target || item.href === target,
  );
  if (idx === -1) return {};
  return {
    prev: idx > 0 ? flatNav[idx - 1] : undefined,
    next: idx < flatNav.length - 1 ? flatNav[idx + 1] : undefined,
  };
}

export function buildBreadcrumbs(
  currentPath: string,
): { label: string; href?: string }[] {
  const current = findCurrent(currentPath);
  const docsRoot = { label: "Docs", href: `${BASE}/` };
  if (!current) return [docsRoot];
  // Root introduction page — just "Docs".
  if (current.href === `${BASE}/`) return [docsRoot];
  return [
    docsRoot,
    { label: current.section },
    { label: current.label },
  ];
}
