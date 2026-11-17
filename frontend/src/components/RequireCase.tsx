/**
 * RequireCase — cockpit route guard (Phase 4e.4).
 *
 * The dashboard (/) and the New Investigation wizard (/case-setup) are open;
 * every investigation surface requires a server-confirmed active case. While
 * the initial case list is loading we render a placeholder instead of
 * redirecting, so a reload on a cockpit URL does not bounce to the dashboard.
 */
import { useEffect } from "react";
import { Navigate, useParams } from "react-router-dom";
import { useCase } from "../context/CaseContext";

export default function RequireCase({ children }: { children: React.ReactNode }) {
  const { booting, activeCase, cases, setActiveCase } = useCase();
  const { caseId } = useParams();

  // If the route explicitly names a valid case, synchronize it if not already active
  useEffect(() => {
    if (caseId && cases.includes(caseId) && activeCase !== caseId) {
      setActiveCase(caseId).catch(() => {});
    }
  }, [caseId, cases, activeCase, setActiveCase]);

  if (booting) {
    return <div className="loading">Loading case…</div>;
  }

  const effectiveCase = (caseId && cases.includes(caseId)) ? caseId : activeCase;

  if (!effectiveCase) {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}
