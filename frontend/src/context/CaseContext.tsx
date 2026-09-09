/**
 * CaseContext — shared case state across the cockpit.
 *
 * WP 4b.11: Lifts activeCase from Layout's local state to React Context
 * so all route pages re-fetch when the case switches.
 * WP 4b.6: Also stores the investigation mode (1/2/3) per-case.
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

interface CaseContextValue {
  cases: string[];
  activeCase: string;
  mode: string;
  health: "ok" | "down" | "checking";
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

  const setActiveCase = useCallback(async (caseId: string) => {
    try {
      await api.activateCase(caseId);
      setActiveCaseState(caseId);
      // Refresh mode after switching case
      const r = await api.getCaseMode();
      setModeState(r.mode || "");
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
    }
  }, [activeCase, refreshMode]);

  return (
    <CaseContext.Provider
      value={{ cases, activeCase, mode, health, setActiveCase, refreshCases, refreshMode, setMode }}
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
