import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Findings from "./Findings";
import { api } from "../api/client";
import * as caseContext from "../context/CaseContext";

function withCase(caseId: string) {
  vi.spyOn(caseContext, "useCase").mockReturnValue({
    activeCase: caseId, cases: [caseId], caseSummaries: {}, previewCase: caseId,
    booting: false, mode: "1", health: "ok",
    es: { configured: true, reachable: true },
    sift: { selected: false, reachable: false },
    setActiveCase: vi.fn(), setPreviewCase: vi.fn(), exitToDashboard: vi.fn(),
    refreshCases: vi.fn(), refreshMode: vi.fn(), refreshStages: vi.fn(), setMode: vi.fn(),
    stages: {},
  } as unknown as ReturnType<typeof caseContext.useCase>);
}

function renderPage(node: React.ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
});

const FINDING = {
  id: "F-abc123",
  title: "Encoded PowerShell in a scheduled task",
  observation: "Task action runs powershell -enc ...",
  interpretation: "Likely a stager.",
  confidence_justification: "One artifact family only.",
  status: "DRAFT",
  severity: "high",
  confidence: "medium",
  audit_ids: ["nx-audit-1", "nx-audit-2"],
  examiner_selected: false,
};

describe("Findings (migrated)", () => {
  it("lists findings in a grid, not a card per finding", async () => {
    withCase("CASE-FND0001");
    vi.spyOn(api, "findings").mockResolvedValue({ findings: [FINDING] } as never);
    renderPage(<Findings />);
    await waitFor(() => expect(screen.getByText("F-abc123")).toBeInTheDocument());
    expect(screen.getByText("Encoded PowerShell in a scheduled task")).toBeInTheDocument();
    // the origin column is present: an LLM draft is not an examiner selection
    expect(screen.getByText("LLM-drafted")).toBeInTheDocument();
  });

  // WO-1C item 4/5 — one DRAFT per claim per case. The mode lineage is what
  // says a claim was corroborated across modes, not merely restated once.
  it("shows the mode lineage and the run that produced a claim", async () => {
    withCase("CASE-FND0002");
    vi.spyOn(api, "findings").mockResolvedValue({
      findings: [{
        ...FINDING,
        provenance: { mode: 1, run_id: "M1-20261009T060000-a1b2c3", modes: [1, 2, 3] },
      }],
    } as never);
    renderPage(<Findings />);
    await waitFor(() => expect(screen.getByText("F-abc123")).toBeInTheDocument());
    // The Modes column renders the merged lineage, so a claim corroborated by
    // three modes is visible without opening the row.
    expect(screen.getByText("1,2,3")).toBeInTheDocument();
  });

  it("surfaces a failed findings read instead of an empty grid", async () => {
    withCase("CASE-FND0004");
    vi.spyOn(api, "findings").mockRejectedValue(new Error("case db locked"));
    renderPage(<Findings />);
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/case db locked/),
    );
  });

  it("says nothing is a finding until one is staged", async () => {
    withCase("CASE-FND0005");
    vi.spyOn(api, "findings").mockResolvedValue({ findings: [] } as never);
    renderPage(<Findings />);
    await waitFor(() => expect(screen.getByText("No findings yet")).toBeInTheDocument());
  });
});
