/**
 * CaseContext — shared case state across the cockpit.
 *
 * WP 4b.11: Lifts activeCase from Layout's local state to React Context
 * so all route pages re-fetch when the case switches.
 * WP 4b.6: Also stores the investigation mode (1/2/3) per-case.
 * WP 4d.5: Exposes live N1-N8 stage completion for the sidebar + stepper.
 */
import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import { api } from "../api/client";

export type StageStatus = Record<string, boolean>;

interface CaseContextValue {
  cases: string[];
  activeCase: string;
  mode: string;
  health: "ok" | "down" | "checking";
  stages: Record<string, boolean>;
  setActiveCase: (caseId: string) => Promise<void>;
  refreshCases: () => Promise<void>;
  refreshMode: () => Promise<void>;
  setMode: (mode: string) => Promise<void>;
}

const CaseContext = createContext<CaseContextValue | null>(null);

export function CaseProvider({ children }: { children: ReactNode }) {
  const [cases, setCases] = useState<string[]>([]);
  const [activeCase, setActiveCaseState] = useState<string>("");
  const [mode, setModeState] = useState<string>("");
  const [health, setHealth] = useState<"ok" | "down" | "checking">("checking");
  const [stages, setStages] = useState<Record<string, boolean>>({});

  const refreshCases = useCallback(async () => {
    try {
      const r = await api.cases();
      setCases(r.cases || []);
      setActiveCaseState(r.active || (r.cases[0] || ""));
    } catch {
      // ignore
    }
  }, []);

  const refreshMode = useCallback(async () => {
    try {
      const r = await api.getCaseMode();
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

  const setActiveCase = useCallback(async (caseId: string) => {
    try {
      await api.activateCase(caseId);
      setActiveCaseState(caseId);
      const r = await api.getCaseMode();
      setModeState(r.mode || "");
      await refreshStages(caseId);
    } catch (e) {
      console.error("Failed to activate case:", e);
    }
  }, []);

  const setMode = useCallback(async (newMode: string) => {
    try {
      await api.setCaseMode(newMode);
      setModeState(newMode);
    } catch (e) {
      console.error("Failed to set mode:", e);
    }
  }, []);

  useEffect(() => {
    refreshCases();
    fetch("/health")
      .then((r) => setHealth(r.ok ? "ok" : "down"))
      .catch(() => setHealth("down"));
  }, [refreshCases]);

  useEffect(() => {
    if (activeCase) {
      refreshMode();
      refreshStages(activeCase);
    }
  }, [activeCase, refreshMode, refreshStages]);

  return (
    <CaseContext.Provider
      value={{ cases, activeCase, mode, health, stages, setActiveCase, refreshCases, refreshMode, setMode }}
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
