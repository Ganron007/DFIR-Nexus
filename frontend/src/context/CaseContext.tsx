/**
 * CaseContext — shared case state across the cockpit.
 *
 * Phase 4e: the UI never invents an active case. It mirrors the server's
 * active-case pointer, and every request carries the case id explicitly
 * (client.ts X-Nexus-Case) so dashboard previews and cockpit operations can
 * never drift onto the wrong case.
 */
import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import { api, setRequestCaseId, type CaseSummary } from "../api/client";

export type StageStatus = Record<string, boolean>;

export interface EsStatus {
  /** NEXUS_ES_URL configured at all */
  configured: boolean;
  /** cluster answered a version probe */
  reachable: boolean;
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
  stages: Record<string, boolean>;
  setActiveCase: (caseId: string) => Promise<void>;
  setPreviewCase: (caseId: string) => void;
  exitToDashboard: () => Promise<void>;
  refreshCases: () => Promise<void>;
  refreshMode: (caseId?: string) => Promise<void>;
  setMode: (mode: string) => Promise<void>;
}

const CaseContext = createContext<CaseContextValue | null>(null);

export function CaseProvider({ children }: { children: ReactNode }) {
  const [cases, setCases] = useState<string[]>([]);
  const [caseSummaries, setCaseSummaries] = useState<Record<string, CaseSummary>>({});
  const [activeCase, setActiveCaseState] = useState<string>("");
  const [previewCase, setPreviewCaseState] = useState<string>("");
  const [booting, setBooting] = useState<boolean>(true);
  const [mode, setModeState] = useState<string>("");
  const [health, setHealth] = useState<"ok" | "down" | "checking">("checking");
  const [es, setEs] = useState<EsStatus>({ configured: false, reachable: false });
  const [stages, setStages] = useState<Record<string, boolean>>({});

  const refreshCases = useCallback(async () => {
    try {
      const r = await api.cases();
      setCases(r.cases || []);
      setCaseSummaries(r.details || {});
      // Mirror the server pointer — never fabricate an active case.
      setActiveCaseState(r.active || "");
      // Sync the request header synchronously with the state change so child
      // load effects (which run before parent effects) see the right case.
      setRequestCaseId(r.active || "");
    } catch {
      // keep prior state on transient failure
    } finally {
      setBooting(false);
    }
  }, []);

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
      await refreshMode(caseId);
      await refreshStages(caseId);
    },
    [refreshMode, refreshStages],
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
    await refreshCases();
  }, [refreshCases]);

  const setMode = useCallback(
    async (newMode: string) => {
      if (!activeCase) return;
      await api.setCaseMode(newMode, activeCase);
      setModeState(newMode);
    },
    [activeCase],
  );

  useEffect(() => {
    refreshCases();
    // Backend liveness AND Elasticsearch state are separate signals —
    // a green backend dot must never imply ES is up.
    api.systemHealth()
      .then((r) => {
        setHealth(r.backend === "ok" ? "ok" : "down");
        setEs({
          configured: r.es?.configured !== false,
          reachable: r.es?.reachable === true,
        });
      })
      .catch(() => {
        setHealth("down");
        setEs({ configured: false, reachable: false });
      });
  }, [refreshCases]);

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
        stages,
        setActiveCase,
        setPreviewCase,
        exitToDashboard,
        refreshCases,
        refreshMode,
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
