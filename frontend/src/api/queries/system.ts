/**
 * System-state queries (WO-U4): backend / ES / SIFT health polled on an
 * interval — replacing the probe-once-at-mount that let a service come up
 * (or die) after mount and never be noticed.
 */
import { useQuery } from "@tanstack/react-query";
import { api } from "../client";
import { systemKey } from "./keys";

export interface SystemHealthState {
  backend: "ok" | "down";
  es: { configured: boolean; reachable: boolean };
  sift: { selected: boolean; reachable: boolean | null; message?: string };
}

const DOWN: SystemHealthState = {
  backend: "down",
  es: { configured: false, reachable: false },
  sift: { selected: false, reachable: false },
};

function toState(r: {
  backend?: string;
  es?: { configured?: boolean; reachable?: boolean };
  sift?: { selected?: boolean; reachable?: boolean | null; message?: string };
}): SystemHealthState {
  return {
    backend: r.backend === "ok" ? "ok" : "down",
    es: {
      configured: r.es?.configured !== false,
      reachable: r.es?.reachable === true,
    },
    sift: {
      selected: r.sift?.selected === true,
      reachable: typeof r.sift?.reachable === "boolean" ? r.sift.reachable : null,
      message: r.sift?.message,
    },
  };
}

/** UI-FOUNDATION-DESIGN §6: health every 30 s, background, never blocking. */
export function useSystemHealth(intervalMs = 30_000) {
  return useQuery<SystemHealthState>({
    queryKey: systemKey("health"),
    queryFn: async () => {
      try {
        return toState(await api.systemHealth());
      } catch {
        return DOWN;
      }
    },
    refetchInterval: intervalMs,
    staleTime: 10_000,
  });
}
