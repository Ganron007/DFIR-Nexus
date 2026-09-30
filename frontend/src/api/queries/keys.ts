/**
 * Query keys (WO-U4, UI-FOUNDATION-DESIGN §6): case-scoped by construction.
 * Switching the active case is a key change — no cross-case cache bleed —
 * and invalidation is exact.
 */
import type { QueryClient } from "@tanstack/react-query";

export function caseKey(caseId: string | null | undefined, domain: string, ...parts: unknown[]) {
  return ["case", caseId ?? "", domain, ...parts] as const;
}

export function systemKey(name: string, ...parts: unknown[]) {
  return ["system", name, ...parts] as const;
}

export const invalidateKeys = {
  case: (client: QueryClient, caseId: string | null | undefined, domain: string) =>
    client.invalidateQueries({ queryKey: caseKey(caseId, domain) }),
  system: (client: QueryClient, name: string) =>
    client.invalidateQueries({ queryKey: systemKey(name) }),
};
