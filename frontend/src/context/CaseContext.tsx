/**
 * CaseContext — shared case state across the cockpit.
 *
 * Phase 4e: the UI never invents an active case. It mirrors the server's
 * active-case pointer, and every request carries the case id explicitly
 * (client.ts X-Nexus-Case) so dashboard previews and cockpit operations can
 * never drift onto the wrong case.
 *
 * WO-U4: the data-shaped state (cases list, backend/ES/SIFT health) lives in
 * TanStack Query hooks and is POLLED — the probe-once-at-mount version let a
 * service come up (or die) after mount and never be noticed. The context
 * slims toward identity: it keeps only the active-case identity, the
 * compatibility projections of the polled queries, and the case-scoped
 * mode/stage refreshes pages still consume (page adoption is U8a/U8b).
 */
import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, setRequestCaseId, type CaseSummary } from "../api/client";
import { useCases } from "../api/queries/cases";
import { useSystemHealth } from "../api/queries/system";
import { invalidateKeys } from "../api/queries/keys";

export type StageStatus = Record<string, boolean>;

export interface EsStatus {
  /** NEXUS_ES_URL configured at all */
  configured: boolean;
  /** cluster answered a version probe */
  reachable: boolean;
}

export interface SiftStatus {
  /** the case selects the SIFT lane (sift_required) */
  selected: boolean;
  /** host reachable; null = not probed yet. A MACHINE-level fact, shown even
   *  when the case does not select the lane. */
  reachable: boolean | null;
  message?: string;
}

interface CaseContextValue {
  cases: string[];
  caseSummaries: Record<string, CaseSummary>;
  activeCase: string;
  previewCase: string;
  booting: boolean;
  mode: string;
  health: "ok" | "down" | "checking";
  /** Real Elasticsearch state — NOT implied by backend liveness. */
  es: EsStatus;
  /** SIFT lane: only a SELECTED case can refuse while the host is down. */
  sift: SiftStatus;
  stages: Record<string, boolean>;
  setActiveCase: (caseId: string) => Promise<void>;
  setPreviewCase: (caseId: string) => void;
  exitToDashboard: () => Promise<void>;
  refreshCases: () => Promise<void>;
  refreshMode: (caseId?: string) => Promise<void>;
  refreshStages: (caseId: string) => Promise<void>;
  setMode: (mode: string) => Promise<void>;
}

const CaseContext = createContext<CaseContextValue | null>(null);

export function CaseProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [activeCase, setActiveCaseState] = useState<string>("");
  const [previewCase, setPreviewCaseState] = useState<string>("");
  const [mode, setModeState] = useState<string>("");
  const [stages, setStages] = useState<Record<string, boolean>>({});

  // Polled server state (WO-U4): health every 30 s, cases every 30 s.
  const casesQuery = useCases();
  const healthQuery = useSystemHealth();

  const cases = casesQuery.data?.cases ?? [];
  const caseSummaries = casesQuery.data?.details ?? {};
  const booting = casesQuery.isPending;
  const health = healthQuery.data
    ? healthQuery.data.backend
    : healthQuery.isError
      ? "down"
      : "checking";
  const es: EsStatus = healthQuery.data?.es ?? { configured: false, reachable: false };
  const sift = healthQuery.data?.sift ?? { selected: false, reachable: null };

  const refreshCases = useCallback(async () => {
    await queryClient.refetchQueries({ queryKey: ["system", "cases"] });
    // Mirror the server pointer — never fabricate an active case.
    const r = casesQuery.data;
    if (r) {
      setActiveCaseState(r.active || "");
      setRequestCaseId(r.active || "");
    }
  }, [queryClient, casesQuery.data]);

  const refreshMode = useCallback(async (caseId?: string) => {
    if (!caseId) {
      setModeState("");
      return;
    }
    try {
      const r = await api.getCaseMode(caseId);
      setModeState(r.mode || "");
    } catch {
      // ignore
    }
  }, []);

  const refreshStages = useCallback(async (caseId: string) => {
    try {
      const d = await api.caseDetails(caseId);
      setStages({
        N1: true, // case exists = intake done
        N2: d.pipeline_complete || false,
        N3: d.pipeline_complete || false, // index built during N2
        N4: (d.findings_count || 0) > 0 || (d.evidence_count || 0) > 0,
        N5: (d.findings_count || 0) > 0,
        N6: (d.approved_count || 0) > 0,
        N7: (d.evidence_count || 0) > 0 && (d.pipeline_complete || false),
        N8: d.report_exists || false,
      });
    } catch {
      setStages({});
    }
  }, []);

  const setActiveCase = useCallback(
    async (caseId: string) => {
      await api.activateCase(caseId);
      // Synchronous header sync — no window where pages fetch the old case.
      setRequestCaseId(caseId);
      setActiveCaseState(caseId);
      await invalidateKeys.case(queryClient, caseId, "status");
      await queryClient.invalidateQueries({ queryKey: ["system", "cases"] });
      await refreshMode(caseId);
      await refreshStages(caseId);
    },
    [queryClient, refreshMode, refreshStages],
  );

  const setPreviewCase = useCallback((caseId: string) => {
    setPreviewCaseState(caseId);
  }, []);

  const exitToDashboard = useCallback(async () => {
    try {
      await api.deactivateCase();
    } catch {
      // best-effort; still detach locally
    }
    setRequestCaseId("");
    setActiveCaseState("");
    setModeState("");
    setStages({});
    setPreviewCaseState("");
    await queryClient.invalidateQueries({ queryKey: ["system", "cases"] });
  }, [queryClient]);

  const setMode = useCallback(
    async (newMode: string) => {
      if (!activeCase) return;
      await api.setCaseMode(newMode, activeCase);
      setModeState(newMode);
    },
    [activeCase],
  );

  // Mirror the server pointer on first load and on any polled change while
  // the examiner has not chosen a case explicitly.
  useEffect(() => {
    if (casesQuery.data && !activeCase) {
      setActiveCaseState(casesQuery.data.active || "");
      setRequestCaseId(casesQuery.data.active || "");
    }
  }, [casesQuery.data, activeCase]);

  // Every API request from now on carries the explicit case identity.
  useEffect(() => {
    setRequestCaseId(activeCase);
  }, [activeCase]);

  useEffect(() => {
    if (activeCase) {
      refreshMode(activeCase);
      refreshStages(activeCase);
    } else {
      setStages({});
      setModeState("");
    }
  }, [activeCase, refreshMode, refreshStages]);

  return (
    <CaseContext.Provider
      value={{
        cases,
        caseSummaries,
        activeCase,
        previewCase,
        booting,
        mode,
        health,
        es,
        sift,
        stages,
        setActiveCase,
        setPreviewCase,
        exitToDashboard,
        refreshCases,
        refreshMode,
        refreshStages,
        setMode,
      }}
    >
      {children}
    </CaseContext.Provider>
  );
}

export function useCase() {
  const ctx = useContext(CaseContext);
  if (!ctx) throw new Error("useCase must be used within CaseProvider");
  return ctx;
}
