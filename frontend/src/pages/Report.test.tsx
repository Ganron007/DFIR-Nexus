/**
 * Report page migration (WO-U8a) — chiefly the print gain.
 *
 * The print rules are the reason this page existed in the WO: the cockpit is
 * dark, so printing produced a dark, toner-wasting, unreadable page. These
 * tests pin the three things that must be true of the output:
 *   1. print rules exist and invert to ink-on-paper,
 *   2. the chrome that has no business on paper is hidden,
 *   3. provenance (case + how many approved findings) is forced onto the page.
 */
import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Report from "./Report";
import { api } from "../api/client";
import * as caseContext from "../context/CaseContext";

const APPROVED = {
  id: "F-abc123",
  title: "Encoded PowerShell in a scheduled task",
  observation: "Task action runs powershell -enc …",
  interpretation: "Likely a stager.",
  confidence_justification: "Corroborated across two families.",
  confidence: "high",
  status: "APPROVED",
  approved_by: "examiner",
  approved_at: "2026-09-30T11:00:00Z",
  audit_ids: ["nx-audit-1"],
  examiner_selected: true,
};

function withCase(caseId: string, status = "active") {
  vi.spyOn(caseContext, "useCase").mockReturnValue({
    activeCase: caseId,
    cases: [caseId],
    caseSummaries: { [caseId]: { status } as never },
    previewCase: caseId,
    booting: false,
    mode: "1",
    health: "ok",
    es: { configured: true, reachable: true },
    sift: { selected: false, reachable: false },
    setActiveCase: vi.fn(),
    setPreviewCase: vi.fn(),
    exitToDashboard: vi.fn(),
    refreshCases: vi.fn(),
    refreshMode: vi.fn(),
    refreshStages: vi.fn(),
    setMode: vi.fn(),
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

function stubReads(over: Record<string, unknown> = {}) {
  vi.spyOn(api, "findings").mockResolvedValue({
    findings: [APPROVED],
    total: 1,
  } as never);
  vi.spyOn(api, "summary").mockResolvedValue({
    findings: { total: 3, approved: 1, draft: 1, rejected: 1 },
  } as never);
  vi.spyOn(api, "reportView").mockResolvedValue({
    ok: true,
    markdown: "# Case Report\n\nExecutive summary.\n",
  } as never);
  vi.spyOn(api, "reportRounds").mockResolvedValue({
    rounds: [
      {
        round: 1,
        ts: "2026-09-30T10:00:00Z",
        instruction: "focus on persistence",
        report_sha256: "b".repeat(64),
        snapshot_path: "reports/rounds/r1.md",
      },
    ],
  } as never);
  for (const [name, value] of Object.entries(over)) {
    vi.spyOn(api, name as never).mockResolvedValue(value as never);
  }
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("Report (migrated)", () => {
  it("renders the official document with provenance on it", async () => {
    withCase("CASE-RPT0001");
    stubReads();
    renderPage(<Report />);
    const doc = await screen.findByTestId("report-document");
    expect(doc).toHaveTextContent("Executive summary.");
    const provenance = screen.getByTestId("report-provenance");
    // a printed report with no provenance is not evidence
    expect(provenance).toHaveTextContent("CASE-RPT0001");
    expect(provenance).toHaveTextContent("1 of 3");
    expect(provenance).toHaveTextContent(/compiled/);
  });

  it("offers Print and calls window.print", async () => {
    withCase("CASE-RPT0002");
    stubReads();
    const printed = vi.fn();
    vi.stubGlobal("print", printed);
    renderPage(<Report />);
    await screen.findByTestId("report-document");
    fireEvent.click(screen.getByText("Print / Save PDF"));
    expect(printed).toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("does not offer Print when there is no document", async () => {
    withCase("CASE-RPT0003");
    stubReads({ reportView: { ok: false } });
    renderPage(<Report />);
    await waitFor(() =>
      expect(screen.getByText("No official report for this case yet")).toBeInTheDocument(),
    );
    expect(screen.getByText("Print / Save PDF")).toBeDisabled();
  });

  it("reports how many approved findings are in the document", async () => {
    withCase("CASE-RPT0004");
    stubReads();
    renderPage(<Report />);
    expect(await screen.findByTestId("report-coverage")).toHaveTextContent(
      "1 / 3",
    );
  });

  it("lists the steer rounds with their snapshot hash", async () => {
    withCase("CASE-RPT0005");
    stubReads();
    renderPage(<Report />);
    const rounds = await screen.findByTestId("report-rounds");
    expect(rounds).toHaveTextContent("focus on persistence");
    expect(rounds).toHaveTextContent("r1");
    expect(rounds).toHaveTextContent("sha bbbbbbbbbbbb");
  });

  // WO-1C item 5 — the cross-mode view replaces the sibling comparison. It is
  // read-only and honest: before any report exists it says so, with the reason.
  it("shows the intra-case cross-mode comparison when one exists", async () => {
    withCase("CASE-RPT0007");
    stubReads({
      reportGrade: {
        case_id: "CASE-RPT0007",
        grade: { score: 82 },
        intra_case: {
          modes_present: ["Mode 1 (LLM)", "Mode 2 (multi-role)", "Mode 3 (multi-agent)"],
          modes_missing: [],
          verdict: "consistent",
          scope: "intra-case",
          claim_rows: 12,
          entity_overlap: { "1-2": 1.0, "1-3": 0.5, "2-3": 0.5 },
          shared_entities: ["ws01"],
          counts: { shared: 4, contradictions: 0, row_contradictions: 0 },
        },
        reason: null,
      },
    });
    renderPage(<Report />);
    const summary = await screen.findByTestId("crossmode-summary");
    expect(summary).toHaveTextContent("consistent");
    expect(summary).toHaveTextContent("intra-case");
    expect(summary).toHaveTextContent("12");
    expect(screen.getByTestId("report-grade")).toHaveTextContent("82");
    expect(document.body.textContent).toContain("1-2: 1");
  });

  it("says why there is no cross-mode comparison yet", async () => {
    withCase("CASE-RPT0008");
    stubReads({
      reportGrade: {
        case_id: "CASE-RPT0008",
        grade: null,
        intra_case: null,
        reason: "not yet graded - generate the report first",
      },
    });
    renderPage(<Report />);
    expect(
      await screen.findByText(/No cross-mode comparison yet/),
    ).toBeInTheDocument();
    // The reason comes from the endpoint, not from the page's own wording, so
    // the examiner sees what the product actually reported.
    expect(
      await screen.findByText(/not yet graded - generate the report first/),
    ).toBeInTheDocument();
  });

  it("steers the report and reports the round it applied", async () => {
    withCase("CASE-RPT0006");
    stubReads();
    vi.spyOn(api, "reportSteer").mockResolvedValue({
      ok: true,
      round: 2,
      instructions_applied: 1,
    } as never);
    renderPage(<Report />);
    await screen.findByTestId("report-document");
    fireEvent.change(screen.getByLabelText("Steer the analysis"), {
      target: { value: "dig into the mshta chain" },
    });
    fireEvent.click(screen.getByTestId("report-steer"));
    await waitFor(() =>
      expect(screen.getByTestId("report-notice")).toHaveTextContent(
        /Round 2 applied .*\(1 instruction in effect\)/,
      ),
    );
    expect(api.reportSteer).toHaveBeenCalledWith({
      instruction: "dig into the mshta chain",
      finding_id: undefined,
    });
  });

  it("switches to the approved findings view", async () => {
    withCase("CASE-RPT0007");
    stubReads();
    renderPage(<Report />);
    await screen.findByTestId("report-document");
    // Radix activates a tab on mousedown, so this is a real user click, not
    // a synthetic click event.
    const user = userEvent.setup({ pointerEventsCheck: 0 });
    await user.click(screen.getByRole("tab", { name: /Approved findings/ }));
    await waitFor(() =>
      expect(screen.getByTestId("report-summary")).toHaveTextContent(
        "Total 3 · approved 1 · draft 1 · rejected 1",
      ),
    );
    expect(screen.getByText(APPROVED.title)).toBeInTheDocument();
  });

  it("explains a sealed case instead of offering a seal that would 409", async () => {
    withCase("CASE-RPT0008", "sealed");
    stubReads();
    renderPage(<Report />);
    await screen.findByTestId("report-document");
    expect(screen.getByText(/sealed \(completed\)/)).toBeInTheDocument();
    expect(screen.queryByText("Seal & close case…")).not.toBeInTheDocument();
  });

  it("refuses to seal without the examiner password", async () => {
    withCase("CASE-RPT0009");
    stubReads();
    renderPage(<Report />);
    await screen.findByTestId("report-document");
    fireEvent.click(screen.getByText("Seal & close case…"));
    // the seal button is disabled with an empty password; typing unlocks it
    const seal = await screen.findByTestId("report-seal");
    expect(seal).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Examiner approval password"), {
      target: { value: "hunter2" },
    });
    expect(seal).toBeEnabled();
  });

  it("surfaces a failed findings read", async () => {
    withCase("CASE-RPT0010");
    stubReads();
    vi.spyOn(api, "findings").mockRejectedValue(new Error("case db locked"));
    renderPage(<Report />);
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("case db locked"),
    );
  });
});
