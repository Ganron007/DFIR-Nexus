/**
 * Case-scoped paths (WO-U3, UD8).
 *
 * The URL names the case. A bookmarked `/case/CASE-9F2A1B/explore` reopens the
 * same case even after the examiner switches away in another tab, and a stale
 * link cannot quietly show the wrong case's findings.
 *
 * Legacy `/explore` paths stay resolvable and redirect; `pageFor(pathname)`
 * is what those redirects use, so a legacy URL and the nav can never disagree
 * about what "explore" is.
 */

export const CASE_ROOT = "/case";

/** Every cockpit page, in navigation order. The nav and the redirects share it. */
export const CASE_PAGES = [
  "evidence",
  "briefing",
  "explore",
  "analysis",
  "steer",
  "agent-run",
  "workbench",
  "findings",
  "approve",
  "timeline",
  "report",
  "entities",
  "ingest",
  "iocs",
  "todos",
  "transparency",
] as const;

export type CasePage = (typeof CASE_PAGES)[number];

const PAGE_SET = new Set<string>(CASE_PAGES);

/** The scoped path for a page. An empty case id degrades to the legacy path. */
export function casePath(caseId: string | null | undefined, page: CasePage | string): string {
  if (!caseId) return `/${page}`;
  return `${CASE_ROOT}/${encodeURIComponent(caseId)}/${page}`;
}

/** The case id in a scoped path, or null for a legacy/root path. */
export function caseIdFromPath(pathname: string): string | null {
  const match = /^\/case\/([^/]+)(?:\/|$)/.exec(pathname);
  return match ? decodeURIComponent(match[1]) : null;
}

/** The page in a scoped path, or null. */
export function pageFromPath(pathname: string): string | null {
  const match = /^\/case\/[^/]+\/([^/?#]+)/.exec(pathname);
  const page = match ? match[1] : null;
  return page && PAGE_SET.has(page) ? page : null;
}

/** The page a legacy `/foo` path means, or null when it is not a cockpit page. */
export function pageFor(pathname: string): string | null {
  const bare = pathname.replace(/^\/+/, "").replace(/\/+$/, "");
  if (!bare || bare.includes("/")) return null;
  return PAGE_SET.has(bare) ? bare : null;
}

/** True when the path is one of ours (scoped or legacy) - used by the boundary. */
export function isCockpitPath(pathname: string): boolean {
  return pageFromPath(pathname) !== null || pageFor(pathname) !== null;
}