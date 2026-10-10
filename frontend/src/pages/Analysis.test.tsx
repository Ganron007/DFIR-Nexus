import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Analysis from "./Analysis";
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

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Analysis />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, "crossMode").mockResolvedValue({ modes_present: ["2"], shared: [], contradictions: [] });
});

describe("Analysis (mode picker)", () => {
  it("offers the three modes and both contexts, and keeps Run off until a mode is chosen", async () => {
    withCase("CASE-PICK0001");
    renderPage();

    expect(screen.getByRole("checkbox", { name: /Mode 1/ })).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: /Mode 2/ })).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: /Mode 3/ })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /Independent/ })).toBeChecked();
    expect(screen.getByRole("button", { name: /^Run/ })).toBeDisabled();

    fireEvent.click(screen.getByRole("checkbox", { name: /Mode 2/ }));
    expect(screen.getByRole("button", { name: /^Run$/ })).toBeEnabled();
  });

  it("names all three in the run button when all are chosen", () => {
    withCase("CASE-PICK0002");
    renderPage();
    for (const mode of ["Mode 1", "Mode 2", "Mode 3"]) {
      fireEvent.click(screen.getByRole("checkbox", { name: new RegExp(mode) }));
    }
    expect(screen.getByRole("button", { name: "Run all three (1 → 2 → 3)" })).toBeEnabled();
  });

  it("reads the cross-mode view for the case it shows", async () => {
    withCase("CASE-PICK0003");
    renderPage();
    await waitFor(() => expect(screen.getByText(/Mode 2/, { selector: "p" })).toBeInTheDocument());
    expect(api.crossMode).toHaveBeenCalled();
  });
});
