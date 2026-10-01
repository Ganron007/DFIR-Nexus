/**
 * Evidence page migration (WO-U8a) — the review items and the guards.
 *
 * The properties pinned here are the ones that are easy to lose in a rewrite:
 * the Mode 2/3 question guard, verify-on-demand (never on mount), per-path
 * registration failures, and the integrity verdict reading unambiguously.
 */
import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Evidence from "./Evidence";
import { api } from "../api/client";
import * as caseContext from "../context/CaseContext";

const EVIDENCE = [
  {
    path: "D:\\evidence\\conn.log",
    name: "conn.log",
    sha256: "a".repeat(64),
    description: "Zeek conn log",
    status: "registered",
    registered_at: "2026-09-29T10:00:00Z",
  },
];

function withCase(caseId: string, mode = "1") {
  vi.spyOn(caseContext, "useCase").mockReturnValue({
    activeCase: caseId,
    cases: [caseId],
    caseSummaries: {},
    previewCase: caseId,
    booting: false,
    mode,
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

/** Everything the page reads on mount, answered quietly. */
function stubReads(over: Record<string, unknown> = {}) {
  vi.spyOn(api, "evidence").mockResolvedValue({ evidence: EVIDENCE } as never);
  vi.spyOn(api, "caseDetails").mockResolvedValue({
    intake: { question: "What did the intruder do?" },
  } as never);
  vi.spyOn(api, "pipelineLedger").mockResolvedValue({
    ledger: [
      {
        tool: "chainsaw",
        status: "OK",
        argv: ["chainsaw", "evtx", "Security.evtx"],
        output_saved_to: "extractions/security.csv",
      },
    ],
    run_id: "run-1",
    run_status: "complete",
    evidence_paths: ["D:\\evidence\\Security.evtx"],
  } as never);
  vi.spyOn(api, "caseDigest").mockResolvedValue({
    digest: { ts_coverage: { evtx: { present: 12, missing: 1, synthesized: 2 } } },
  } as never);
  for (const [name, value] of Object.entries(over)) {
    if (value instanceof Error) {
      vi.spyOn(api, name as never).mockRejectedValue(value);
    } else {
      vi.spyOn(api, name as never).mockResolvedValue(value as never);
    }
  }
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("Evidence (migrated)", () => {
  it("shows the registry with a copyable path and a copyable full hash", async () => {
    withCase("CASE-EVD0001");
    stubReads();
    renderPage(<Evidence />);
    await waitFor(() =>
      expect(screen.getByText("D:\\evidence\\conn.log")).toBeInTheDocument(),
    );
    // The review asked for CopyableHash. The old page truncated to 16 chars and
    // offered no way to get the rest, which is not enough to paste into
    // sigcheck or a report. The kit primitive shows a short form and copies the
    // FULL digest, so that is the contract to pin.
    const copyHash = screen.getByRole("button", { name: /Copy hash a{12}/ });
    expect(copyHash).toBeInTheDocument();
    // and the path is copyable too
    expect(
      screen.getByRole("button", { name: /Copy path/i }),
    ).toBeInTheDocument();
  });

  it("renders the parser lane ledger and the processed evidence", async () => {
    withCase("CASE-EVD0002");
    stubReads();
    renderPage(<Evidence />);
    await waitFor(() => expect(screen.getByText("chainsaw")).toBeInTheDocument());
    expect(screen.getByText("D:\\evidence\\Security.evtx")).toBeInTheDocument();
    expect(screen.getByText(/1\/1 OK/)).toBeInTheDocument();
  });

  it("does NOT verify hashes on mount", async () => {
    withCase("CASE-EVD0003");
    stubReads();
    const verify = vi.spyOn(api, "evidenceVerify");
    renderPage(<Evidence />);
    await waitFor(() => expect(screen.getByText("chainsaw")).toBeInTheDocument());
    // It reads every registered file off disk; mounting must not trigger it.
    expect(verify).not.toHaveBeenCalled();
  });

  it("says all-verified and says mismatch - never a bare colour", async () => {
    withCase("CASE-EVD0004");
    stubReads();
    vi.spyOn(api, "evidenceVerify").mockResolvedValue({
      ok: true,
      results: [{ file_path: "D:\\evidence\\conn.log", name: "conn.log", valid: true }],
    } as never);
    const { fireEvent } = await import("@testing-library/react");
    renderPage(<Evidence />);
    await waitFor(() => expect(screen.getByText("chainsaw")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Verify hashes"));
    const verdict = await screen.findByTestId("evidence-verify-verdict");
    expect(verdict).toHaveTextContent(/Integrity verified: all 1 registered file/);
    expect(verdict).not.toHaveTextContent(/mismatch/i);
  });

  it("says mismatch in words when a hash fails", async () => {
    withCase("CASE-EVD0005");
    stubReads();
    vi.spyOn(api, "evidenceVerify").mockResolvedValue({
      ok: true,
      results: [{ file_path: "x", name: "x", valid: false, error: "content changed" }],
    } as never);
    const { fireEvent } = await import("@testing-library/react");
    renderPage(<Evidence />);
    await waitFor(() => expect(screen.getByText("chainsaw")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Verify hashes"));
    const verdict = await screen.findByTestId("evidence-verify-verdict");
    expect(verdict).toHaveTextContent(/Integrity mismatch: 1 of 1/);
  });

  it("refuses the N2 lane for Mode 2/3 with no examiner question", async () => {
    withCase("CASE-EVD0006", "2");
    stubReads({ caseDetails: { intake: { question: "" } } });
    const run = vi.spyOn(api, "pipelineRun");
    const { fireEvent } = await import("@testing-library/react");
    renderPage(<Evidence />);
    await waitFor(() => expect(screen.getByText("chainsaw")).toBeInTheDocument());
    fireEvent.click(screen.getByText("▶ Run N2 lane"));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/needs an examiner question/),
    );
    // The guard is behaviour, not a tooltip: nothing was started.
    expect(run).not.toHaveBeenCalled();
  });

  it("allows the N2 lane for Mode 1 with no question", async () => {
    withCase("CASE-EVD0007", "1");
    stubReads({ caseDetails: { intake: { question: "" } } });
    const run = vi
      .spyOn(api, "pipelineRun")
      .mockResolvedValue({ run_id: "run-2" } as never);
    vi.spyOn(api, "pipelineStatus").mockResolvedValue({
      status: "complete",
      stages: [],
    } as never);
    const { fireEvent } = await import("@testing-library/react");
    renderPage(<Evidence />);
    await waitFor(() => expect(screen.getByText("chainsaw")).toBeInTheDocument());
    fireEvent.click(screen.getByText("▶ Run N2 lane"));
    await waitFor(() => expect(run).toHaveBeenCalled());
  });

  it("surfaces a failed registry read instead of an empty table", async () => {
    withCase("CASE-EVD0008");
    stubReads({ evidence: new Error("registry unreadable") });
    renderPage(<Evidence />);
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/registry unreadable/),
    );
  });

  it("warns that a family with no parsed times is not an absence of activity", async () => {
    withCase("CASE-EVD0009");
    stubReads({
      caseDigest: { digest: { ts_coverage: { tasks: { present: 0, missing: 9 } } } },
    });
    renderPage(<Evidence />);
    await waitFor(() =>
      expect(screen.getByText(/no parsed event timestamps/)).toBeInTheDocument(),
    );
    expect(screen.getByText(/do not read absence as timeline evidence/)).toBeInTheDocument();
  });
});
