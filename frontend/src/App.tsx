import { lazy, Suspense, type ComponentType } from "react";
import { Routes, Route, Navigate, useLocation, useParams } from "react-router-dom";
import { CaseProvider, useCase } from "./context/CaseContext";
import Layout from "./components/Layout";
import RequireCase from "./components/RequireCase";
import Overview from "./pages/Overview";
import CaseSetup from "./pages/CaseSetup";
import { RouteErrorBoundary } from "./shell/RouteErrorBoundary";
import { CASE_PAGES, casePath, pageFor, type CasePage } from "./shell/caseScope";

// Dev-only kit gallery: import.meta.env.DEV is statically replaced at build,
// so the dynamic import (and the chunk) never reaches a production bundle.
const KitGallery = import.meta.env.DEV
  ? lazy(() => import("./pages/KitGallery"))
  : null;

// Route-level code splitting (WO-U3): one chunk per page, loaded when asked.
const Briefing = lazy(() => import("./pages/Briefing"));
const Explore = lazy(() => import("./pages/Explore"));
const Timeline = lazy(() => import("./pages/Timeline"));
const SteerChat = lazy(() => import("./pages/SteerChat"));
const Analysis = lazy(() => import("./pages/Analysis"));
const AgentRun = lazy(() => import("./pages/AgentRun"));
const Workbench = lazy(() => import("./pages/Workbench"));
const Findings = lazy(() => import("./pages/Findings"));
const Approve = lazy(() => import("./pages/Approve"));
const Report = lazy(() => import("./pages/Report"));
const Evidence = lazy(() => import("./pages/Evidence"));
const Entities = lazy(() => import("./pages/Entities"));
const Transparency = lazy(() => import("./pages/Transparency"));
const Ingest = lazy(() => import("./pages/Ingest"));
const Iocs = lazy(() => import("./pages/Iocs"));
const Todos = lazy(() => import("./pages/Todos"));

const PAGE_COMPONENTS: Record<CasePage, ComponentType> = {
  evidence: Evidence as ComponentType,
  briefing: Briefing as ComponentType,
  explore: Explore as ComponentType,
  steer: SteerChat as ComponentType,
  analysis: Analysis as ComponentType,
  "agent-run": AgentRun as ComponentType,
  workbench: Workbench as ComponentType,
  findings: Findings as ComponentType,
  approve: Approve as ComponentType,
  timeline: Timeline as ComponentType,
  report: Report as ComponentType,
  entities: Entities as ComponentType,
  ingest: Ingest as ComponentType,
  iocs: Iocs as ComponentType,
  todos: Todos as ComponentType,
  transparency: Transparency as ComponentType,
};

/** Every cockpit page under one route: the URL names the case (UD8). */
function CasePageRoute({ page }: { page: CasePage }) {
  const { caseId } = useParams();
  const Component = PAGE_COMPONENTS[page];
  return (
    <RequireCase>
      <RouteErrorBoundary routeName={page}>
        <Suspense fallback={<RouteFallback />}>
          <Component key={`${caseId}:${page}`} />
        </Suspense>
      </RouteErrorBoundary>
    </RequireCase>
  );
}

function RouteFallback() {
  return (
    <div
      data-testid="route-fallback"
      style={{ padding: "var(--space-5)", color: "var(--color-fg-muted)" }}
    >
      Loading…
    </div>
  );
}

/**
 * A legacy `/explore` URL redirects to the scoped path for the active case
 * rather than rendering the page unscoped - the URL and the data agree.
 */
function LegacyRedirect() {
  const location = useLocation();
  const { activeCase } = useCase();
  const page = pageFor(location.pathname);
  if (!page) return <Navigate to="/" replace />;
  if (!activeCase) {
    // No case yet: let RequireCase explain, which is better than a dead end.
    const Component = PAGE_COMPONENTS[page as CasePage];
    return (
      <RequireCase>
        <Suspense fallback={<RouteFallback />}>
          <Component />
        </Suspense>
      </RequireCase>
    );
  }
  return <Navigate to={casePath(activeCase, page)} replace />;
}

export default function App() {
  return (
    <CaseProvider>
      <Layout>
        <Routes>
          {/* Dashboard - case management, no active case required */}
          <Route path="/" element={<Overview />} />
          <Route path="/case-setup" element={<CaseSetup />} />
          {KitGallery ? (
            <Route
              path="/_kit"
              element={
                <Suspense fallback={null}>
                  <KitGallery />
                </Suspense>
              }
            />
          ) : null}

          {/* Cockpit - the URL names the case */}
          {CASE_PAGES.map((page) => (
            <Route
              key={page}
              path={`/case/:caseId/${page}`}
              element={<CasePageRoute page={page} />}
            />
          ))}

          {/* Legacy cockpit URLs -> the scoped path for the active case */}
          {CASE_PAGES.map((page) => (
            <Route key={`legacy-${page}`} path={`/${page}`} element={<LegacyRedirect />} />
          ))}

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </CaseProvider>
  );
}