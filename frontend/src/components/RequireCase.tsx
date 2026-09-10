/**
 * RequireCase — cockpit route guard (Phase 4e.4).
 *
 * The dashboard (/) and the New Investigation wizard (/case-setup) are open;
 * every investigation surface requires a server-confirmed active case. While
 * the initial case list is loading we render a placeholder instead of
 * redirecting, so a reload on a cockpit URL does not bounce to the dashboard.
 */
import { Navigate } from "react-router-dom";
import { useCase } from "../context/CaseContext";

export default function RequireCase({ children }: { children: React.ReactNode }) {
  const { booting, activeCase } = useCase();

  if (booting) {
    return <div className="loading">Loading case…</div>;
  }
  if (!activeCase) {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}
